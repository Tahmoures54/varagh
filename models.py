# -*- coding: utf-8 -*-
"""
مدل‌های پایگاه داده سیستم کنترل حمل ورق فولادی فراسکو
"""
from datetime import datetime, date, time
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Havaleh(db.Model):
    """حواله / کامیون"""
    __tablename__ = 'havaleh'

    id = db.Column(db.Integer, primary_key=True)

    # الف) اطلاعات حواله و وسیله نقلیه
    shomare_havaleh = db.Column(db.String(50), unique=True, nullable=False, index=True)
    tarikh_havaleh = db.Column(db.Date, nullable=True)
    pelak = db.Column(db.String(20), nullable=True)
    name_ranande = db.Column(db.String(100), nullable=True)
    mobile_ranande = db.Column(db.String(20), nullable=True)
    sharh_kala = db.Column(db.String(100), nullable=True)
    moshakhasat_varagh = db.Column(db.String(200), nullable=True)
    tedad_baste = db.Column(db.Integer, nullable=True)
    vazn_esnadi = db.Column(db.Float, nullable=True)  # کیلوگرم

    # ب) ورود و خروج
    tarikh_vorud = db.Column(db.Date, nullable=True)
    saat_vorud = db.Column(db.Time, nullable=True)
    tarikh_khoruj = db.Column(db.Date, nullable=True)
    saat_khoruj = db.Column(db.Time, nullable=True)
    masoul_sabt = db.Column(db.String(100), nullable=True)

    # ج) باسکول
    vazn_por = db.Column(db.Float, nullable=True)
    vazn_khali = db.Column(db.Float, nullable=True)
    ghabz_por_piost = db.Column(db.String(10), default='خیر')  # بله / خیر
    ghabz_khali_piost = db.Column(db.String(10), default='خیر')

    # د) وضعیت کنترل
    vaziyat_havaleh = db.Column(db.String(30), default='ثبت‌شده')
    # ثبت‌شده / خارج‌شده / ناقص / نیازمند بررسی / تکمیل‌شده
    vaziyat_moghayerat = db.Column(db.String(30), default='بدون مغایرت')
    # بدون مغایرت / نیازمند بررسی / تعیین تکلیف‌شده
    sharh_moghayerat = db.Column(db.Text, nullable=True)
    masoul_peygiri = db.Column(db.String(100), nullable=True)
    tarikh_peygiri = db.Column(db.Date, nullable=True)
    natije_peygiri = db.Column(db.Text, nullable=True)
    taeed_nahayi = db.Column(db.String(100), nullable=True)
    tarikh_taeed = db.Column(db.Date, nullable=True)
    tozihat = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ---------- محاسبات ----------
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
        """مدت توقف به ساعت (اعشاری)"""
        if not all([self.tarikh_vorud, self.saat_vorud, self.tarikh_khoruj, self.saat_khoruj]):
            return None
        dt_vorud = datetime.combine(self.tarikh_vorud, self.saat_vorud)
        dt_khoruj = datetime.combine(self.tarikh_khoruj, self.saat_khoruj)
        delta = dt_khoruj - dt_vorud
        return round(delta.total_seconds() / 3600, 2)

    @property
    def vaziyat_ghabzha(self):
        if self.ghabz_por_piost == 'بله' and self.ghabz_khali_piost == 'بله':
            return 'کامل'
        if self.ghabz_por_piost or self.ghabz_khali_piost:
            return 'ناقص'
        return None

    def to_dict(self):
        return {
            'id': self.id,
            'shomare_havaleh': self.shomare_havaleh,
            'tarikh_havaleh': self.tarikh_havaleh.isoformat() if self.tarikh_havaleh else None,
            'pelak': self.pelak,
            'name_ranande': self.name_ranande,
            'mobile_ranande': self.mobile_ranande,
            'sharh_kala': self.sharh_kala,
            'moshakhasat_varagh': self.moshakhasat_varagh,
            'tedad_baste': self.tedad_baste,
            'vazn_esnadi': self.vazn_esnadi,
            'tarikh_vorud': self.tarikh_vorud.isoformat() if self.tarikh_vorud else None,
            'saat_vorud': self.saat_vorud.strftime('%H:%M') if self.saat_vorud else None,
            'tarikh_khoruj': self.tarikh_khoruj.isoformat() if self.tarikh_khoruj else None,
            'saat_khoruj': self.saat_khoruj.strftime('%H:%M') if self.saat_khoruj else None,
            'moddat_tavaghof': self.moddat_tavaghof_saat,
            'masoul_sabt': self.masoul_sabt,
            'vazn_por': self.vazn_por,
            'vazn_khali': self.vazn_khali,
            'vazn_khales': self.vazn_khales,
            'ekhtelaf_vazn': self.ekhtelaf_vazn,
            'darsad_ekhtelaf': self.darsad_ekhtelaf,
            'ghabz_por_piost': self.ghabz_por_piost,
            'ghabz_khali_piost': self.ghabz_khali_piost,
            'vaziyat_ghabzha': self.vaziyat_ghabzha,
            'vaziyat_havaleh': self.vaziyat_havaleh,
            'vaziyat_moghayerat': self.vaziyat_moghayerat,
            'sharh_moghayerat': self.sharh_moghayerat,
            'masoul_peygiri': self.masoul_peygiri,
            'tarikh_peygiri': self.tarikh_peygiri.isoformat() if self.tarikh_peygiri else None,
            'natije_peygiri': self.natije_peygiri,
            'taeed_nahayi': self.taeed_nahayi,
            'tarikh_taeed': self.tarikh_taeed.isoformat() if self.tarikh_taeed else None,
            'tozihat': self.tozihat,
        }


class Inventory(db.Model):
    """ایندکس موجودی ورق‌ها"""
    __tablename__ = 'inventory'

    id = db.Column(db.Integer, primary_key=True)
    radif = db.Column(db.Integer, nullable=True)
    code_kala = db.Column(db.String(30), index=True, nullable=False)
    name_kala = db.Column(db.String(100), nullable=True)
    zekhamat = db.Column(db.Float, nullable=True)  # میل
    moshakhasat = db.Column(db.String(200), nullable=True)
    vahed = db.Column(db.String(20), default='کیلو گرم')
    mojudi_vaghei = db.Column(db.Float, nullable=True)  # کیلوگرم کل
    tedad_sheet = db.Column(db.Float, nullable=True)
    vazn_har_sheet = db.Column(db.Float, nullable=True)
    vazn_goruh = db.Column(db.Float, nullable=True)  # برای گروه‌های فرعی
    mogheiyat = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'radif': self.radif,
            'code_kala': self.code_kala,
            'name_kala': self.name_kala,
            'zekhamat': self.zekhamat,
            'moshakhasat': self.moshakhasat,
            'vahed': self.vahed,
            'mojudi_vaghei': self.mojudi_vaghei,
            'tedad_sheet': self.tedad_sheet,
            'vazn_har_sheet': self.vazn_har_sheet,
            'vazn_goruh': self.vazn_goruh,
            'mogheiyat': self.mogheiyat,
        }
