# -*- coding: utf-8 -*-
"""
مدل‌های پایگاه داده سیستم کنترل حمل ورق فولادی فراسکو
فاز ۲: کاربر، نقش، آپلود قبض، کسر موجودی
"""
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utcnow():
    """Naive UTC now — جایگزین deprecation-free برای datetime.utcnow().

    Naïve نگه می‌دارد تا با داده‌های موجود سازگار بماند؛ در آینده اگر
    timezone-aware ذخیره شد، این تابع را با datetime.now(timezone.utc) جایگزین کنید.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------- نقش‌ها ----------
ROLE_ADMIN = 'admin'
ROLE_HERASAT = 'herasat'
ROLE_ANBAR = 'anbar'
ROLE_PROJECT = 'project'
ROLE_VIEWER = 'viewer'

ROLES = {
    ROLE_ADMIN: 'مدیر سیستم',
    ROLE_HERASAT: 'حراست',
    ROLE_ANBAR: 'انبار',
    ROLE_PROJECT: 'پروژه',
    ROLE_VIEWER: 'مشاهده‌گر',
}

# ---------- ثابت‌های دامنه (منبع واحد حقیقت) ----------
STATUSES = (
    'ثبت‌شده', 'در حال بررسی', 'خارج‌شده',
    'ناقص', 'نیازمند بررسی', 'تکمیل‌شده',
)
MOGHAYERAT = (
    'بدون مغایرت', 'مغایرت مثبت', 'مغایرت منفی', 'نیازمند بررسی',
)
BALE_KHEYR = ('خیر', 'بله')


def _in_list_clause(column, values):
    """ساخت عبارت SQL برای CheckConstraint از فهرست مقادیر مجاز."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(30), default=ROLE_VIEWER, nullable=False)
    is_active_user = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        # اگر مقدار None باشد (مثلاً قبل از flush)، فعال در نظر گرفته می‌شود
        # تا با default=True هم‌راستا باشد و کاربر به‌اشتباه قفل نشود.
        if self.is_active_user is None:
            return True
        return bool(self.is_active_user)

    @property
    def role_label(self):
        return ROLES.get(self.role, self.role)

    # ---- سازگاری با نسخه‌های قبلی؛ در app.py از role_editable_fields استفاده می‌شود ----
    def can_edit_entry_exit(self):
        return self.role in (ROLE_ADMIN, ROLE_HERASAT)

    def can_edit_scale(self):
        return self.role in (ROLE_ADMIN, ROLE_ANBAR)

    def can_approve(self):
        return self.role in (ROLE_ADMIN, ROLE_PROJECT)

    def can_edit_all(self):
        return self.role == ROLE_ADMIN

    def __repr__(self):
        return f"<User {self.username!r} role={self.role}>"


class Havaleh(db.Model):
    __tablename__ = 'havaleh'

    __table_args__ = (
        db.CheckConstraint(
            _in_list_clause("vaziyat_havaleh", STATUSES),
            name="ck_havaleh_vaziyat",
        ),
        db.CheckConstraint(
            _in_list_clause("vaziyat_moghayerat", MOGHAYERAT),
            name="ck_havaleh_moghayerat",
        ),
        # ایندکس ترکیبی برای فیلتر رایج در داشبورد/گزارش‌ها
        db.Index(
            "ix_havaleh_status_created",
            "vaziyat_havaleh", "created_at",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    shomare_havaleh = db.Column(db.String(50), unique=True, nullable=False, index=True)
    tarikh_havaleh = db.Column(db.Date, nullable=True, index=True)
    pelak = db.Column(db.String(20), nullable=True)
    noe_vasileh = db.Column(db.String(30), nullable=True)
    pelak_trailer = db.Column(db.String(20), nullable=True)
    name_ranande = db.Column(db.String(100), nullable=True)
    mobile_ranande = db.Column(db.String(20), nullable=True)
    sharh_kala = db.Column(db.String(100), nullable=True)
    moshakhasat_varagh = db.Column(db.String(200), nullable=True)
    code_kala = db.Column(db.String(30), nullable=True, index=True)
    mogheiyat_varagh = db.Column(db.String(200), nullable=True)
    tedad_baste = db.Column(db.Integer, nullable=True)
    vazn_esnadi = db.Column(db.Float, nullable=True)
    tarikh_vorud = db.Column(db.Date, nullable=True)
    saat_vorud = db.Column(db.Time, nullable=True)
    tarikh_khoruj = db.Column(db.Date, nullable=True)
    saat_khoruj = db.Column(db.Time, nullable=True)
    masoul_sabt = db.Column(db.String(100), nullable=True)
    vazn_por = db.Column(db.Float, nullable=True)
    vazn_khali = db.Column(db.Float, nullable=True)
    ghabz_por_piost = db.Column(db.String(10), default='خیر', nullable=False)
    ghabz_khali_piost = db.Column(db.String(10), default='خیر', nullable=False)
    ghabz_por_file = db.Column(db.String(255), nullable=True)
    ghabz_khali_file = db.Column(db.String(255), nullable=True)
    vaziyat_havaleh = db.Column(db.String(30), default='ثبت‌شده', nullable=False, index=True)
    vaziyat_moghayerat = db.Column(db.String(30), default='بدون مغایرت', nullable=False)
    sharh_moghayerat = db.Column(db.Text, nullable=True)
    masoul_peygiri = db.Column(db.String(100), nullable=True)
    tarikh_peygiri = db.Column(db.Date, nullable=True)
    natije_peygiri = db.Column(db.Text, nullable=True)
    taeed_nahayi = db.Column(db.String(100), nullable=True)
    tarikh_taeed = db.Column(db.Date, nullable=True)
    tozihat = db.Column(db.Text, nullable=True)
    inventory_deducted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])

    @property
    def vazn_khales(self):
        if self.vazn_por is not None and self.vazn_khali is not None:
            return round(self.vazn_por - self.vazn_khali, 3)
        return None

    @property
    def ekhtelaf_vazn(self):
        khales = self.vazn_khales
        if khales is not None and self.vazn_esnadi is not None:
            return round(khales - self.vazn_esnadi, 3)
        return None

    @property
    def darsad_ekhtelaf(self):
        ekht = self.ekhtelaf_vazn
        if ekht is not None and self.vazn_esnadi and self.vazn_esnadi != 0:
            return round((ekht / self.vazn_esnadi) * 100, 2)
        return None

    @property
    def moddat_tavaghof_saat(self):
        if not all([
            self.tarikh_vorud, self.saat_vorud,
            self.tarikh_khoruj, self.saat_khoruj,
        ]):
            return None
        dt_vorud = datetime.combine(self.tarikh_vorud, self.saat_vorud)
        dt_khoruj = datetime.combine(self.tarikh_khoruj, self.saat_khoruj)
        delta = dt_khoruj - dt_vorud
        return round(delta.total_seconds() / 3600, 2)

    @property
    def vaziyat_ghabzha(self):
        """وضعیت پیوست قبض‌ها.

        'کامل' → هر دو قبض، 'ناقص' → یکی از دو قبض،
        None → هیچ‌کدام. مصرف‌کننده در قالب از `or '—'` استفاده می‌کند.
        """
        full = self.ghabz_por_piost == 'بله'
        empty = self.ghabz_khali_piost == 'بله'
        if full and empty:
            return 'کامل'
        if full or empty:
            return 'ناقص'
        return None

    def __repr__(self):
        return f"<Havaleh {self.shomare_havaleh} status={self.vaziyat_havaleh}>"


class Inventory(db.Model):
    __tablename__ = 'inventory'

    # توصیه: برای داده‌های موجود که ممکن است تکراری باشند، ابتدا با یک
    # migration داده‌ها را پاک‌سازی کنید، سپس این قید را فعال کنید:
    # __table_args__ = (
    #     db.UniqueConstraint(
    #         "code_kala", "moshakhasat", "mogheiyat",
    #         name="uq_inventory_identity",
    #     ),
    # )

    id = db.Column(db.Integer, primary_key=True)
    radif = db.Column(db.Integer, nullable=True)
    code_kala = db.Column(db.String(30), index=True, nullable=False)
    name_kala = db.Column(db.String(100), nullable=True)
    zekhamat = db.Column(db.Float, nullable=True)
    moshakhasat = db.Column(db.String(200), nullable=True, index=True)
    vahed = db.Column(db.String(20), default='کیلو گرم', nullable=False)
    mojudi_vaghei = db.Column(db.Float, nullable=True)
    tedad_sheet = db.Column(db.Float, nullable=True)
    vazn_har_sheet = db.Column(db.Float, nullable=True)
    vazn_goruh = db.Column(db.Float, nullable=True)
    mogheiyat = db.Column(db.String(200), nullable=True, index=True)

    def __repr__(self):
        return f"<Inventory {self.code_kala} loc={self.mogheiyat}>"


class SerialCounter(db.Model):
    __tablename__ = 'serial_counter'
    id = db.Column(db.Integer, primary_key=True)
    prefix = db.Column(db.String(30), unique=True, nullable=False, index=True)
    last_number = db.Column(db.Integer, default=0, nullable=False)


class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=True, index=True,
    )
    action = db.Column(db.String(50), nullable=False, index=True)
    entity = db.Column(db.String(50), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    user = db.relationship('User')

    def __repr__(self):
        return f"<AuditLog {self.action} entity={self.entity}:{self.entity_id}>"


class TransferControl(db.Model):
    """Single-row tracking for expert valuation and final transfer reconciliation."""
    __tablename__ = "transfer_control"

    __table_args__ = (
        # تضمین تک‌رکوردی بودن؛ از ایجاد id=2 جلوگیری می‌کند
        db.CheckConstraint("id = 1", name="ck_transfer_control_singleton"),
    )

    id = db.Column(db.Integer, primary_key=True, default=1)
    agreement_signed_on = db.Column(db.Date, nullable=True)
    valuation_announced_on = db.Column(db.Date, nullable=True)
    valuation_price_per_kg = db.Column(db.Float, nullable=True)
    valuation_reference = db.Column(db.String(300), nullable=True)
    final_summary_signed_on = db.Column(db.Date, nullable=True)
    final_summary_signed_by = db.Column(db.String(200), nullable=True)
    final_summary_notes = db.Column(db.Text, nullable=True)
    final_summary_snapshot = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)
