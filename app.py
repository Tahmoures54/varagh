# -*- coding: utf-8 -*-
"""سامانه کنترل حمل ورق فولادی فراسکو."""
from __future__ import annotations

import csv
import io
import os
import secrets
import uuid
from datetime import date, datetime, time
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, make_response, redirect, render_template, request,
    send_from_directory, session, url_for,
)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from models import (
    AuditLog, Havaleh, Inventory, SerialCounter, User, db,
    ROLE_ADMIN, ROLE_ANBAR, ROLE_HERASAT, ROLE_PROJECT, ROLE_VIEWER,
)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
# Vercel function bundles are read-only; /tmp is writable but not persistent.
# Set VARAGH_DATA_DIR explicitly when using a mounted/persistent volume elsewhere.
_default_data_dir = Path("/tmp/varagh-data") if os.environ.get("VERCEL") == "1" else BASE_DIR / "data"
DATA_DIR = Path(os.environ.get("VARAGH_DATA_DIR") or _default_data_dir).resolve()
UPLOAD_DIR = Path(os.environ.get("VARAGH_UPLOAD_DIR") or (DATA_DIR / "receipts")).resolve()
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "webp"}
STATUSES = ["ثبت‌شده", "در حال بررسی", "خارج‌شده", "ناقص", "نیازمند بررسی", "تکمیل‌شده"]
MOGHAYERAT = ["بدون مغایرت", "مغایرت مثبت", "مغایرت منفی", "نیازمند بررسی"]
BALE_KHEYR = ["خیر", "بله"]


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("VARAGH_SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", f"sqlite:///{(DATA_DIR / 'varagh.db').as_posix()}"
        ).replace("postgres://", "postgresql://", 1),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
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

    def log_action(action, entity=None, entity_id=None, detail=None):
        db.session.add(AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action, entity=entity, entity_id=entity_id, detail=(detail or "")[:2000],
        ))

    def require_roles(*roles):
        def decorator(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if current_user.role not in roles:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

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

    @app.template_filter("fa_date")
    def fa_date(value):
        if not value:
            return "—"
        if isinstance(value, datetime):
            value = value.date()
        if not isinstance(value, date):
            return str(value)
        jy, jm, jd = gregorian_to_jalali(value.year, value.month, value.day)
        return f"{jy:04d}/{jm:02d}/{jd:02d}"

    def parse_date(field):
        raw = (request.form.get(field) or "").strip()
        if not raw:
            return None
        try:
            return date.fromisoformat(raw)
        except ValueError:
            raise ValueError(f"مقدار تاریخ «{field}» معتبر نیست.")

    def parse_time(field):
        raw = (request.form.get(field) or "").strip()
        if not raw:
            return None
        try:
            return time.fromisoformat(raw)
        except ValueError:
            raise ValueError(f"مقدار ساعت «{field}» معتبر نیست.")

    def parse_float(field, label, required=False):
        raw = (request.form.get(field) or "").strip()
        if not raw:
            if required:
                raise ValueError(f"فیلد «{label}» الزامی است.")
            return None
        try:
            value = float(raw.replace(",", ""))
        except ValueError:
            raise ValueError(f"مقدار «{label}» باید عددی باشد.")
        if value < 0:
            raise ValueError(f"مقدار «{label}» نمی‌تواند منفی باشد.")
        return value

    def parse_int(field, label):
        raw = (request.form.get(field) or "").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"مقدار «{label}» باید عدد صحیح باشد.")
        if value < 0:
            raise ValueError(f"مقدار «{label}» نمی‌تواند منفی باشد.")
        return value

    def next_voucher_number():
        jy, _, _ = gregorian_to_jalali(date.today().year, date.today().month, date.today().day)
        prefix = f"HV-{jy}-"
        counter = SerialCounter.query.filter_by(prefix=prefix).with_for_update().first()
        if counter is None:
            counter = SerialCounter(prefix=prefix, last_number=0)
            db.session.add(counter)
            db.session.flush()
        counter.last_number += 1
        return f"{prefix}{counter.last_number:04d}"

    def save_receipt(field, current_path=None):
        upload = request.files.get(field)
        if not upload or not upload.filename:
            return current_path
        original = secure_filename(upload.filename)
        extension = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        if extension not in ALLOWED_EXTENSIONS:
            raise ValueError("نوع فایل قبض مجاز نیست؛ فقط PDF، PNG، JPG یا WEBP پذیرفته می‌شود.")
        # Random names prevent path traversal and filename collisions.
        stored_name = f"{uuid.uuid4().hex}.{extension}"
        upload.save(UPLOAD_DIR / stored_name)
        return stored_name
