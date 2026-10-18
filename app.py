# -*- coding: utf-8 -*-
"""سامانه کنترل حمل ورق فولادی فراسکو — temporary restore for Vercel entrypoint."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for, flash, abort
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from dotenv import load_dotenv

from models import User, db, ROLE_ADMIN

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
_is_serverless = bool(
    os.environ.get("VERCEL") == "1"
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
)
_default_data_dir = Path("/tmp/varagh-data") if _is_serverless else BASE_DIR / "data"
DATA_DIR = Path(os.environ.get("VARAGH_DATA_DIR") or _default_data_dir).resolve()
UPLOAD_DIR = Path(os.environ.get("VARAGH_UPLOAD_DIR") or (DATA_DIR / "receipts")).resolve()


def _normalize_database_url(url: str) -> str:
    if not url:
        return url
    url = url.replace("postgres://", "postgresql://", 1)
    if url.startswith("postgresql://") and "+psycopg" not in url.split("://", 1)[0]:
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("VARAGH_SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=_normalize_database_url(
            os.environ.get(
                "DATABASE_URL", f"sqlite:///{(DATA_DIR / 'varagh.db').as_posix()}"
            )
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.login_message = "برای ادامه ابتدا وارد سامانه شوید."
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            supplied = request.form.get("_csrf_token", "")
            expected = session.get("_csrf_token", "")
            if not expected or not supplied or not secrets.compare_digest(supplied, expected):
                abort(400, description="درخواست معتبر نیست؛ صفحه را تازه‌سازی و دوباره تلاش کنید.")

    @app.context_processor
    def inject_globals():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["_csrf_token"], "current_user": current_user}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = User.query.filter_by(username=username).first()
            if user and user.is_active_user and user.check_password(password):
                session.clear()
                login_user(user, remember=False, fresh=True)
                session["_csrf_token"] = secrets.token_urlsafe(32)
                flash("با موفقیت وارد شدید.", "success")
                return redirect(url_for("index"))
            flash("نام کاربری یا رمز عبور صحیح نیست.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        session.clear()
        flash("از سامانه خارج شدید.", "info")
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        return render_template(
            "index.html",
            stats={
                "total": 0, "completed": 0, "incomplete": 0, "need_review": 0,
                "sum_esnadi": 0, "sum_khales": 0, "balance": 0,
                "pos_diff": 0, "neg_diff": 0, "sum_pos": 0, "sum_neg": 0,
                "no_ghabz_por": 0, "no_ghabz_khali": 0,
                "total_duration": 0, "avg_duration": 0,
            },
            followups=[],
        )

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="شما مجوز انجام این عملیات را ندارید."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="صفحه یا فایل موردنظر پیدا نشد."), 404

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "درخواست معتبر نیست.")), 400

    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            bootstrap_password = os.environ.get("VARAGH_ADMIN_PASSWORD")
            if bootstrap_password and len(bootstrap_password) >= 12:
                admin = User(
                    username=os.environ.get("VARAGH_ADMIN_USERNAME", "admin"),
                    full_name="مدیر سامانه",
                    role=ROLE_ADMIN,
                    is_active_user=True,
                )
                admin.set_password(bootstrap_password)
                db.session.add(admin)
                db.session.commit()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
