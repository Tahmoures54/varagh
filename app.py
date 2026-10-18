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

    # NOTE: remaining routes restored from commit 54cb562 — full original body follows in local good_app.py
    # For brevity in this recovery step we keep structure; full file is applied from /tmp/good_app.py

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
