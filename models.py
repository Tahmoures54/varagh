# -*- coding: utf-8 -*-
"""
مدل‌های پایگاه داده سیستم کنترل حمل ورق فولادی فراسکو
فاز ۲: کاربر، نقش، آپلود قبض، کسر موجودی
"""
from datetime import datetime, date, time
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

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


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(30), default=ROLE_VIEWER, nullable=False)
    is_active_user = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return bool(self.is_active_user)

    @property
    def role_label(self):
        return ROLES.get(self.role, self.role)

    def can_edit_entry_exit(self):
        return self.role in (ROLE_ADMIN, ROLE_HERASAT)

    def can_edit_scale(self):
        return self.role in (ROLE_ADMIN, ROLE_ANBAR)

    def can_approve(self):
        return self.role in (ROLE_ADMIN, ROLE_PROJECT)

    def can_edit_all(self):
        return self.role == ROLE_ADMIN


class Havaleh(db.Model):
    __tablename__ = 'havaleh'
    id = db.Column(db.Integer, primary_key=True)
    shomare_havaleh = db.Column(db.String(50), unique=True, nullable=False, index=True)
    tarikh_havaleh = db.Column(db.Date, nullable=True)
    pelak = db.Column(db.String(20), nullable=True)
    name_ranande = db.Column(db.String(100), nullable=True)
    mobile_ranande = db.Column(db.String(20), nullable=True)
    sharh_kala = db.Column(db.String(100), nullable=True)
    moshakhasat_varagh = db.Column(db.String(200), nullable=True)
    code_kala = db.Column(db.String(30), nullable=True, index=True)
    tedad_baste = db.Column(db.Integer, nullable=True)
    vazn_esnadi = db.Column(db.Float, nullable=True)
    tarikh_vorud = db.Column(db.Date, nullable=True)
    saat_vorud = db.Column(db.Time, nullable=True)
    tarikh_khoruj = db.Column(db.Date, nullable=True)
    saat_khoruj = db.Column(db.Time, nullable=True)
    masoul_sabt = db.Column(db.String(100), nullable=True)
    vazn_por = db.Column(db.Float, nullable=True)
    vazn_khali = db.Column(db.Float, nullable=True)
    ghabz_por_piost = db.Column(db.String(10), default='خیر')
    ghabz_khali_piost = db.Column(db.String(10), default='خیر')
    ghabz_por_file = db.Column(db.String(255), nullable=True)
    ghabz_khali_file = db.Column(db.String(255), nullable=True)
    vaziyat_havaleh = db.Column(db.String(30), default='ثبت‌شده')
    vaziyat_moghayerat = db.Column(db.String(30), default='بدون مغایرت')
    sharh_moghayerat = db.Column(db.Text, nullable=True)
    masoul_peygiri = db.Column(db.String(100), nullable=True)
    tarikh_peygiri = db.Column(db.Date, nullable=True)
    natije_peygiri = db.Column(db.Text, nullable=True)
    taeed_nahayi = db.Column(db.String(100), nullable=True)
    tarikh_taeed = db.Column(db.Date, nullable=True)
    tozihat = db.Column(db.Text, nullable=True)
    inventory_deducted = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])

    @property
    def vazn_khales(self):
        if self.vazn_por is not None and self.vazn_khali is not None:
            return round(self.vazn_por - self.vazn_khali, 2)
        return None

    @property
    def ekhtelaf_vazn(self):
        khales = self.vazn_khales
        if khales is not None and self.vazn_esnadi is not None:
            return round(khales - self.vazn_esnadi, 2)
        return None

    @property
    def darsad_ekhtelaf(self):
        ekht = self.ekhtelaf_vazn
        if ekht is not None and self.vazn_esnadi and self.vazn_esnadi != 0:
            return round((ekht / self.vazn_esnadi) * 100, 2)
        return None

    @property
    def moddat_tavaghof_saat(self):
        if not all([self.tarikh_vorud, self.saat_vorud, self.tarikh_khoruj, self.saat_khoruj]):
            return None
        dt_vorud = datetime.combine(self.tarikh_vorud, self.saat_vorud)
        dt_khoruj = datetime.combine(self.tarikh_khoruj, self.saat_khoruj)
        delta = dt_khoruj - dt_vorud
        return round(delta.total_seconds() / 3600, 2)

    @property
    def vaziyat_ghabzha(self):
        full_receipt = self.ghabz_por_piost == 'بله'
        empty_receipt = self.ghabz_khali_piost == 'بله'
        if full_receipt and empty_receipt:
            return 'کامل'
        if full_receipt or empty_receipt:
            return 'ناقص'
        return None


class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    radif = db.Column(db.Integer, nullable=True)
    code_kala = db.Column(db.String(30), index=True, nullable=False)
    name_kala = db.Column(db.String(100), nullable=True)
    zekhamat = db.Column(db.Float, nullable=True)
    moshakhasat = db.Column(db.String(200), nullable=True)
    vahed = db.Column(db.String(20), default='کیلو گرم')
    mojudi_vaghei = db.Column(db.Float, nullable=True)
    tedad_sheet = db.Column(db.Float, nullable=True)
    vazn_har_sheet = db.Column(db.Float, nullable=True)
    vazn_goruh = db.Column(db.Float, nullable=True)
    mogheiyat = db.Column(db.String(200), nullable=True)


class SerialCounter(db.Model):
    __tablename__ = 'serial_counter'
    id = db.Column(db.Integer, primary_key=True)
    prefix = db.Column(db.String(30), unique=True, nullable=False)
    last_number = db.Column(db.Integer, default=0)


class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    entity = db.Column(db.String(50), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')
