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
# Serverless (Vercel / Lambda) function bundles are read-only; /tmp is writable but not persistent.
# Set VARAGH_DATA_DIR / VARAGH_UPLOAD_DIR explicitly when using a mounted/persistent volume.
_is_serverless = bool(
    os.environ.get("VERCEL") == "1"
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    or os.environ.get("FUNCTION_NAME")
)
_default_data_dir = Path("/tmp/varagh-data") if _is_serverless else BASE_DIR / "data"
DATA_DIR = Path(os.environ.get("VARAGH_DATA_DIR") or _default_data_dir).resolve()
UPLOAD_DIR = Path(os.environ.get("VARAGH_UPLOAD_DIR") or (DATA_DIR / "receipts")).resolve()
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "webp"}
STATUSES = ["ثبت‌شده", "در حال بررسی", "خارج‌شده", "ناقص", "نیازمند بررسی", "تکمیل‌شده"]
MOGHAYERAT = ["بدون مغایرت", "مغایرت مثبت", "مغایرت منفی", "نیازمند بررسی"]
BALE_KHEYR = ["خیر", "بله"]

def _normalize_database_url(url: str) -> str:
    """Normalize DB URL for SQLAlchemy + psycopg (v3)."""
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
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Read-only filesystem (e.g. some serverless cold starts); continue if paths already usable.
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

    def apply_form(item, creating=False):
        old_status = item.vaziyat_havaleh
        old_code = item.code_kala
        old_weight = item.vazn_esnadi
        if item.inventory_deducted:
            # A completed voucher cannot silently alter stock-impacting values.
            requested_status = request.form.get("vaziyat_havaleh", old_status)
            requested_code = (request.form.get("code_kala") or item.code_kala or "").strip()
            requested_weight = parse_float("vazn_esnadi", "وزن اسنادی")
            if requested_status != old_status or requested_code != old_code or requested_weight != old_weight:
                raise ValueError("حواله‌ای که از موجودی آن کسر شده، قابل تغییر در وضعیت یا اطلاعات اثرگذار بر موجودی نیست.")
        item.tarikh_havaleh = parse_date("tarikh_havaleh")
        item.pelak = (request.form.get("pelak") or "").strip()[:20] or None
        item.name_ranande = (request.form.get("name_ranande") or "").strip()[:100] or None
        item.mobile_ranande = (request.form.get("mobile_ranande") or "").strip()[:20] or None
        item.sharh_kala = (request.form.get("sharh_kala") or "").strip()[:100] or None
        item.moshakhasat_varagh = (request.form.get("moshakhasat_varagh") or "").strip()[:200] or None
        item.code_kala = (request.form.get("code_kala") or "").strip()[:30] or None
        item.tedad_baste = parse_int("tedad_baste", "تعداد بسته")
        item.vazn_esnadi = parse_float("vazn_esnadi", "وزن اسنادی")
        item.tarikh_vorud = parse_date("tarikh_vorud")
        item.saat_vorud = parse_time("saat_vorud")
        item.tarikh_khoruj = parse_date("tarikh_khoruj")
        item.saat_khoruj = parse_time("saat_khoruj")
        item.masoul_sabt = (request.form.get("masoul_sabt") or "").strip()[:100] or None
        item.vazn_por = parse_float("vazn_por", "وزن پُر باسکول")
        item.vazn_khali = parse_float("vazn_khali", "وزن خالی باسکول")
        if item.vazn_por is not None and item.vazn_khali is not None and item.vazn_khali > item.vazn_por:
            raise ValueError("وزن خالی نمی‌تواند از وزن پُر بیشتر باشد.")
        item.ghabz_por_file = save_receipt("ghabz_por_file", item.ghabz_por_file)
        item.ghabz_khali_file = save_receipt("ghabz_khali_file", item.ghabz_khali_file)
        item.ghabz_por_piost = "بله" if item.ghabz_por_file else "خیر"
        item.ghabz_khali_piost = "بله" if item.ghabz_khali_file else "خیر"
        status = (request.form.get("vaziyat_havaleh") or "ثبت‌شده").strip()
        if status not in STATUSES:
            raise ValueError("وضعیت حواله معتبر نیست.")
        if status == "تکمیل‌شده" and current_user.role not in (ROLE_ADMIN, ROLE_PROJECT):
            raise ValueError("تکمیل نهایی حواله فقط برای مدیر یا نقش پروژه مجاز است.")
        item.vaziyat_havaleh = status
        discrepancy = (request.form.get("vaziyat_moghayerat") or "بدون مغایرت").strip()
        if discrepancy not in MOGHAYERAT:
            raise ValueError("وضعیت مغایرت معتبر نیست.")
        item.vaziyat_moghayerat = discrepancy
        item.sharh_moghayerat = (request.form.get("sharh_moghayerat") or "").strip() or None
        item.masoul_peygiri = (request.form.get("masoul_peygiri") or "").strip()[:100] or None
        item.tarikh_peygiri = parse_date("tarikh_peygiri")
        item.natije_peygiri = (request.form.get("natije_peygiri") or "").strip() or None
        item.taeed_nahayi = (request.form.get("taeed_nahayi") or "").strip()[:100] or None
        item.tarikh_taeed = parse_date("tarikh_taeed")
        item.tozihat = (request.form.get("tozihat") or "").strip() or None

        if item.vaziyat_havaleh == "تکمیل‌شده" and not item.inventory_deducted:
            if not item.code_kala:
                raise ValueError("برای تکمیل حواله، کد کالای موجودی باید مشخص شود.")
            if item.vazn_khales is None:
                raise ValueError("برای تکمیل حواله، وزن پُر و خالی باسکول را ثبت کنید.")
            candidates = Inventory.query.filter_by(code_kala=item.code_kala).order_by(Inventory.id).all()
            if not candidates:
                raise ValueError("کد کالا در ایندکس موجودی پیدا نشد؛ ابتدا موجودی را بررسی کنید.")
            if len(candidates) > 1:
                specification = (item.moshakhasat_varagh or "").strip()
                matches = [row for row in candidates if specification and specification in {
                    (row.moshakhasat or "").strip(), (row.name_kala or "").strip()
                }]
                if len(matches) != 1:
                    raise ValueError("این کد کالا چند ردیف موجودی دارد؛ مشخصات ورق را دقیقاً مطابق ایندکس انتخاب کنید تا موجودی اشتباه کسر نشود.")
                inventory = matches[0]
            else:
                inventory = candidates[0]
            if inventory.mojudi_vaghei is None or inventory.mojudi_vaghei < item.vazn_khales:
                raise ValueError("موجودی کافی نیست یا موجودی واقعی تعریف نشده است؛ کسر انجام نشد.")
            inventory.mojudi_vaghei = round(inventory.mojudi_vaghei - item.vazn_khales, 3)
            item.inventory_deducted = True
            log_action("inventory_deducted", "Havaleh", item.id,
                       f"کد کالا={item.code_kala}; وزن خالص={item.vazn_khales}; موجودی پس از کسر={inventory.mojudi_vaghei}")
        item.updated_by_id = current_user.id
        return old_status

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
                return redirect(request.args.get("next") if (request.args.get("next", "").startswith("/") and not request.args.get("next", "").startswith("//")) else url_for("index"))
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
        all_items = Havaleh.query.order_by(Havaleh.created_at.desc()).all()
        total = len(all_items)
        completed = sum(h.vaziyat_havaleh == "تکمیل‌شده" for h in all_items)
        incomplete = sum(h.vaziyat_havaleh == "ناقص" for h in all_items)
        need_review = sum(h.vaziyat_havaleh == "نیازمند بررسی" or h.vaziyat_moghayerat != "بدون مغایرت" for h in all_items)
        sum_esnadi = sum(h.vazn_esnadi or 0 for h in all_items)
        sum_khales = sum(h.vazn_khales or 0 for h in all_items)
        diffs = [h.ekhtelaf_vazn for h in all_items if h.ekhtelaf_vazn is not None]
        durations = [h.moddat_tavaghof_saat for h in all_items if h.moddat_tavaghof_saat is not None and h.moddat_tavaghof_saat >= 0]
        stats = {
            "total": total, "completed": completed, "incomplete": incomplete, "need_review": need_review,
            "sum_esnadi": sum_esnadi, "sum_khales": sum_khales, "balance": sum_khales - sum_esnadi,
            "pos_diff": sum(d > 0 for d in diffs), "neg_diff": sum(d < 0 for d in diffs),
            "sum_pos": sum(d for d in diffs if d > 0), "sum_neg": sum(d for d in diffs if d < 0),
            "no_ghabz_por": sum(not h.ghabz_por_file for h in all_items),
            "no_ghabz_khali": sum(not h.ghabz_khali_file for h in all_items),
            "total_duration": round(sum(durations), 2),
            "avg_duration": round(sum(durations) / len(durations), 2) if durations else 0,
        }
        followups = [h for h in all_items if h.vaziyat_havaleh in ("ناقص", "نیازمند بررسی") or h.vaziyat_moghayerat != "بدون مغایرت" or not h.ghabz_por_file or not h.ghabz_khali_file]
        return render_template("index.html", stats=stats, followups=followups[:100])

    @app.route("/havaleh")
    @login_required
    def havaleh_list():
        q = (request.args.get("q") or "").strip()[:100]
        status = request.args.get("status", "")
        query = Havaleh.query
        if q:
            like = f"%{q}%"
            query = query.filter(or_(
                Havaleh.shomare_havaleh.ilike(like), Havaleh.pelak.ilike(like),
                Havaleh.name_ranande.ilike(like), Havaleh.sharh_kala.ilike(like),
                Havaleh.code_kala.ilike(like), Havaleh.moshakhasat_varagh.ilike(like),
            ))
        if status in STATUSES:
            query = query.filter_by(vaziyat_havaleh=status)
        items = query.order_by(Havaleh.created_at.desc()).limit(1000).all()
        return render_template("havaleh_list.html", items=items, q=q, status=status, statuses=STATUSES)

    @app.route("/havaleh/new", methods=["GET", "POST"])
    @require_roles(ROLE_ADMIN, ROLE_HERASAT, ROLE_ANBAR, ROLE_PROJECT)
    def havaleh_new():
        item = Havaleh()
        if request.method == "POST":
            try:
                supplied_number = (request.form.get("shomare_havaleh") or "").strip()
                item.shomare_havaleh = supplied_number or next_voucher_number()
                if Havaleh.query.filter_by(shomare_havaleh=item.shomare_havaleh).first():
                    raise ValueError("این شماره حواله قبلاً ثبت شده است.")
                item.created_by_id = current_user.id
                db.session.add(item)
                db.session.flush()
                apply_form(item, creating=True)
                log_action("create", "Havaleh", item.id, item.shomare_havaleh)
                db.session.commit()
                flash("حواله با موفقیت ثبت شد.", "success")
                return redirect(url_for("havaleh_edit", item_id=item.id))
            except ValueError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
            except IntegrityError:
                db.session.rollback()
                flash("شماره حواله تکراری است.", "danger")
        return render_template("havaleh_form.html", item=item, statuses=STATUSES, moghayerat=MOGHAYERAT, creating=True)

    @app.route("/havaleh/<int:item_id>", methods=["GET", "POST"])
    @login_required
    def havaleh_edit(item_id):
        item = db.session.get(Havaleh, item_id) or abort(404)
        if request.method == "POST":
            if current_user.role == ROLE_VIEWER:
                abort(403)
            try:
                old_status = apply_form(item)
                log_action("update", "Havaleh", item.id, f"{item.shomare_havaleh}; status={item.vaziyat_havaleh}")
                db.session.commit()
                flash("تغییرات ذخیره شد.", "success")
                return redirect(url_for("havaleh_edit", item_id=item.id))
            except ValueError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
            except IntegrityError:
                db.session.rollback()
                flash("خطای یکپارچگی پایگاه داده.", "danger")
        return render_template("havaleh_form.html", item=item, statuses=STATUSES, moghayerat=MOGHAYERAT, creating=False)

    @app.route("/havaleh/<int:item_id>/delete", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def havaleh_delete(item_id):
        item = db.session.get(Havaleh, item_id) or abort(404)
        if item.inventory_deducted:
            flash("حواله‌ای که از موجودی آن کسر شده قابل حذف نیست.", "danger")
            return redirect(url_for("havaleh_list"))
        log_action("delete", "Havaleh", item.id, item.shomare_havaleh)
        db.session.delete(item)
        db.session.commit()
        flash("حواله حذف شد.", "info")
        return redirect(url_for("havaleh_list"))

    @app.route("/receipts/<path:filename>")
    @login_required
    def receipt_file(filename):
        return send_from_directory(UPLOAD_DIR, filename)

    @app.route("/inventory")
    @login_required
    def inventory_list():
        q = (request.args.get("q") or "").strip()[:100]
        query = Inventory.query
        if q:
            like = f"%{q}%"
            query = query.filter(or_(
                Inventory.code_kala.ilike(like), Inventory.name_kala.ilike(like),
                Inventory.moshakhasat.ilike(like), Inventory.mahal.ilike(like),
            ))
        items = query.order_by(Inventory.code_kala).limit(2000).all()
        return render_template("inventory.html", items=items, q=q)

    @app.route("/inventory/import", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def inventory_import():
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("فایل انتخاب نشده است.", "danger")
            return redirect(url_for("inventory_list"))
        name = secure_filename(upload.filename).lower()
        try:
            if name.endswith(".csv"):
                stream = io.TextIOWrapper(upload.stream, encoding="utf-8-sig")
                reader = csv.DictReader(stream)
                rows = list(reader)
            elif name.endswith((".xlsx", ".xls")):
                from openpyxl import load_workbook
                wb = load_workbook(upload, read_only=True, data_only=True)
                ws = wb.active
                headers = [str(c.value or "").strip() for c in next(ws.iter_rows(max_row=1))]
                rows = []
                for row in ws.iter_rows(min_row=2, values_only=True):
                    rows.append({headers[i]: row[i] for i in range(len(headers))})
            else:
                flash("فقط CSV یا Excel پذیرفته می‌شود.", "danger")
                return redirect(url_for("inventory_list"))
            if len(rows) > 5000:
                flash("حداکثر ۵۰۰۰ ردیف در هر بار مجاز است.", "danger")
                return redirect(url_for("inventory_list"))
            created = updated = 0
            for raw in rows:
                code = str(raw.get("code_kala") or raw.get("کد کالا") or "").strip()[:30]
                if not code:
                    continue
                name_kala = str(raw.get("name_kala") or raw.get("نام کالا") or "").strip()[:200] or None
                moshakhasat = str(raw.get("moshakhasat") or raw.get("مشخصات") or "").strip()[:200] or None
                mahal = str(raw.get("mahal") or raw.get("موقعیت") or "").strip()[:100] or None
                try:
                    mojudi = float(str(raw.get("mojudi_vaghei") or raw.get("موجودی واقعی") or "0").replace(",", ""))
                except ValueError:
                    mojudi = 0.0
                existing = Inventory.query.filter_by(code_kala=code, moshakhasat=moshakhasat, mahal=mahal).first()
                if existing:
                    existing.name_kala = name_kala
                    existing.mojudi_vaghei = mojudi
                    updated += 1
                else:
                    db.session.add(Inventory(
                        code_kala=code, name_kala=name_kala, moshakhasat=moshakhasat,
                        mahal=mahal, mojudi_vaghei=mojudi,
                    ))
                    created += 1
            db.session.commit()
            log_action("inventory_import", "Inventory", None, f"created={created}; updated={updated}")
            flash(f"واردات انجام شد: {created} جدید، {updated} به‌روزرسانی.", "success")
        except Exception as exc:
            db.session.rollback()
            flash(f"خطا در واردات: {exc}", "danger")
        return redirect(url_for("inventory_list"))

    @app.route("/inventory/template")
    @require_roles(ROLE_ADMIN)
    def inventory_template():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["code_kala", "name_kala", "moshakhasat", "mahal", "mojudi_vaghei"])
        writer.writerow(["EXAMPLE-001", "ورق نمونه", "ST37 2mm", "انبار A", "1000"])
        resp = make_response(output.getvalue())
        resp.headers["Content-Type"] = "text/csv; charset=utf-8-sig"
        resp.headers["Content-Disposition"] = "attachment; filename=inventory_template.csv"
        return resp

    @app.route("/users")
    @require_roles(ROLE_ADMIN)
    def users_list():
        users = User.query.order_by(User.username).all()
        from models import ROLES
        return render_template("users.html", users=users, roles=ROLES)

    @app.route("/users/new", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def users_new():
        from models import ROLES
        username = (request.form.get("username") or "").strip()[:80]
        password = request.form.get("password") or ""
        full_name = (request.form.get("full_name") or "").strip()[:120] or None
        role = (request.form.get("role") or ROLE_VIEWER).strip()
        if role not in ROLES:
            flash("نقش معتبر نیست.", "danger")
            return redirect(url_for("users_list"))
        if len(password) < 12:
            flash("رمز عبور باید حداقل ۱۲ نویسه باشد.", "danger")
            return redirect(url_for("users_list"))
        if not username or User.query.filter_by(username=username).first():
            flash("نام کاربری خالی یا تکراری است.", "danger")
            return redirect(url_for("users_list"))
        user = User(username=username, full_name=full_name, role=role)
        user.set_password(password)
        db.session.add(user)
        log_action("user_create", "User", None, username)
        db.session.commit()
        flash("کاربر ایجاد شد.", "success")
        return redirect(url_for("users_list"))

    @app.route("/users/<int:user_id>/toggle", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def users_toggle(user_id):
        user = db.session.get(User, user_id) or abort(404)
        if user.username == "admin" and user.is_active_user:
            flash("حساب مدیر اصلی را نمی‌توان غیرفعال کرد.", "danger")
            return redirect(url_for("users_list"))
        user.is_active_user = not user.is_active_user
        log_action("user_toggle", "User", user.id, f"{user.username} -> {user.is_active_user}")
        db.session.commit()
        flash("وضعیت کاربر به‌روز شد.", "info")
        return redirect(url_for("users_list"))

    @app.route("/export/havaleh")
    @require_roles(ROLE_ADMIN, ROLE_PROJECT, ROLE_VIEWER)
    def export_havaleh():
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Havaleh"
        headers = [
            "شماره حواله", "تاریخ", "پلاک", "راننده", "موبایل", "شرح کالا", "مشخصات",
            "کد کالا", "تعداد بسته", "وزن اسنادی", "ورود", "خروج", "وزن پُر", "وزن خالی",
            "وزن خالص", "وضعیت", "مغایرت", "توضیحات",
        ]
        ws.append(headers)
        for h in Havaleh.query.order_by(Havaleh.created_at.desc()).limit(5000).all():
            ws.append([
                h.shomare_havaleh, h.tarikh_havaleh, h.pelak, h.name_ranande, h.mobile_ranande,
                h.sharh_kala, h.moshakhasat_varagh, h.code_kala, h.tedad_baste, h.vazn_esnadi,
                f"{h.tarikh_vorud} {h.saat_vorud or ''}".strip(),
                f"{h.tarikh_khoruj} {h.saat_khoruj or ''}".strip(),
                h.vazn_por, h.vazn_khali, h.vazn_khales, h.vaziyat_havaleh, h.vaziyat_moghayerat, h.tozihat,
            ])
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        resp = make_response(buf.read())
        resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        resp.headers["Content-Disposition"] = "attachment; filename=havaleh_export.xlsx"
        return resp

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="دسترسی مجاز نیست."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="صفحه پیدا نشد."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="حجم فایل بیشتر از ۸ مگابایت است."), 413

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "درخواست معتبر نیست.")), 400

    with app.app_context():
        db.create_all()
        # Never create published default passwords. Initial admin is provisioned explicitly.
        if User.query.count() == 0:
            bootstrap_password = os.environ.get("VARAGH_ADMIN_PASSWORD")
            if bootstrap_password and len(bootstrap_password) >= 12:
                admin = User(
                    username=os.environ.get("VARAGH_ADMIN_USERNAME", "admin"),
                    full_name="مدیر سیستم",
                    role=ROLE_ADMIN,
                )
                admin.set_password(bootstrap_password)
                db.session.add(admin)
                db.session.commit()

    return app


def gregorian_to_jalali(gy, gm, gd):
    """Convert Gregorian date to Jalali without an external dependency."""
    g_days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    j_days_in_month = [31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29]
    gy2 = gy + 1 if gm > 2 else gy
    days = 355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 + gd
    for i in range(gm - 1):
        days += g_days_in_month[i]
    if gm > 2 and ((gy % 4 == 0 and gy % 100 != 0) or gy % 400 == 0):
        days += 1
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm = 1 + days // 31
        jd = 1 + days % 31
    else:
        jm = 7 + (days - 186) // 30
        jd = 1 + (days - 186) % 30
    return jy, jm, jd


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
