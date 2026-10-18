# -*- coding: utf-8 -*-
"""
سیستم کنترل حمل ورق فولادی از فراسکو
Flask Web Application
"""
import os
from datetime import datetime, date, time
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_file
)
from models import db, Havaleh, Inventory
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'varagh-frasco-secret-key-2026')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'data', 'varagh.db')
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

VAZIYAT_HAVALEH = ['ثبت‌شده', 'خارج‌شده', 'ناقص', 'نیازمند بررسی', 'تکمیل‌شده']
VAZIYAT_MOGHAYERAT = ['بدون مغایرت', 'نیازمند بررسی', 'تعیین تکلیف‌شده']
BALE_KHEYR = ['بله', 'خیر']

def parse_date(val):
    if not val: return None
    try: return datetime.strptime(val, '%Y-%m-%d').date()
    except: return None

def parse_time(val):
    if not val: return None
    try: return datetime.strptime(val, '%H:%M').time()
    except: return None

def parse_float(val):
    if val is None or val == '': return None
    try: return float(str(val).replace(',', ''))
    except: return None

@app.route('/')
def index():
    total = Havaleh.query.count()
    completed = Havaleh.query.filter_by(vaziyat_havaleh='تکمیل‌شده').count()
    incomplete = Havaleh.query.filter_by(vaziyat_havaleh='ناقص').count()
    need_review = Havaleh.query.filter_by(vaziyat_havaleh='نیازمند بررسی').count()
    exited = Havaleh.query.filter_by(vaziyat_havaleh='خارج‌شده').count()
    no_ghabz_por = Havaleh.query.filter_by(ghabz_por_piost='خیر').count()
    no_ghabz_khali = Havaleh.query.filter_by(ghabz_khali_piost='خیر').count()
    all_h = Havaleh.query.all()
    sum_esnadi = sum(h.vazn_esnadi or 0 for h in all_h)
    sum_khales = sum(h.vazn_khales or 0 for h in all_h)
    balance = sum_khales - sum_esnadi
    pos_diff = sum(1 for h in all_h if h.ekhtelaf_vazn and h.ekhtelaf_vazn > 0)
    neg_diff = sum(1 for h in all_h if h.ekhtelaf_vazn and h.ekhtelaf_vazn < 0)
    sum_pos = sum(h.ekhtelaf_vazn for h in all_h if h.ekhtelaf_vazn and h.ekhtelaf_vazn > 0)
    sum_neg = sum(h.ekhtelaf_vazn for h in all_h if h.ekhtelaf_vazn and h.ekhtelaf_vazn < 0)
    durations = [h.moddat_tavaghof_saat for h in all_h if h.moddat_tavaghof_saat is not None]
    avg_duration = round(sum(durations) / len(durations), 2) if durations else 0
    total_duration = round(sum(durations), 2) if durations else 0
    followups = Havaleh.query.filter(
        db.or_(
            Havaleh.vaziyat_havaleh.in_(['ناقص', 'نیازمند بررسی']),
            Havaleh.vaziyat_moghayerat == 'نیازمند بررسی'
        )
    ).order_by(Havaleh.id.desc()).limit(20).all()
    stats = dict(total=total, completed=completed, incomplete=incomplete, need_review=need_review,
                 exited=exited, no_ghabz_por=no_ghabz_por, no_ghabz_khali=no_ghabz_khali,
                 sum_esnadi=sum_esnadi, sum_khales=sum_khales, balance=balance,
                 pos_diff=pos_diff, neg_diff=neg_diff, sum_pos=sum_pos, sum_neg=sum_neg,
                 avg_duration=avg_duration, total_duration=total_duration)
    return render_template('index.html', stats=stats, followups=followups)

@app.route('/havaleh')
def havaleh_list():
    q = request.args.get('q', '').strip()
    status = request.args.get('status', '')
    query = Havaleh.query
    if q:
        query = query.filter(db.or_(Havaleh.shomare_havaleh.contains(q), Havaleh.pelak.contains(q),
                                    Havaleh.name_ranande.contains(q), Havaleh.sharh_kala.contains(q)))
    if status:
        query = query.filter_by(vaziyat_havaleh=status)
    items = query.order_by(Havaleh.id.desc()).all()
    return render_template('havaleh_list.html', items=items, q=q, status=status, statuses=VAZIYAT_HAVALEH)

@app.route('/havaleh/new', methods=['GET', 'POST'])
def havaleh_new():
    if request.method == 'POST':
        shomare = request.form.get('shomare_havaleh', '').strip()
        if not shomare:
            flash('شماره حواله الزامی است.', 'danger')
            return redirect(url_for('havaleh_new'))
        if Havaleh.query.filter_by(shomare_havaleh=shomare).first():
            flash('این شماره حواله قبلاً ثبت شده است.', 'danger')
            return redirect(url_for('havaleh_new'))
        h = Havaleh(
            shomare_havaleh=shomare,
            tarikh_havaleh=parse_date(request.form.get('tarikh_havaleh')),
            pelak=request.form.get('pelak', '').strip() or None,
            name_ranande=request.form.get('name_ranande', '').strip() or None,
            mobile_ranande=request.form.get('mobile_ranande', '').strip() or None,
            sharh_kala=request.form.get('sharh_kala', '').strip() or None,
            moshakhasat_varagh=request.form.get('moshakhasat_varagh', '').strip() or None,
            tedad_baste=int(request.form['tedad_baste']) if request.form.get('tedad_baste') else None,
            vazn_esnadi=parse_float(request.form.get('vazn_esnadi')),
            tarikh_vorud=parse_date(request.form.get('tarikh_vorud')),
            saat_vorud=parse_time(request.form.get('saat_vorud')),
            tarikh_khoruj=parse_date(request.form.get('tarikh_khoruj')),
            saat_khoruj=parse_time(request.form.get('saat_khoruj')),
            masoul_sabt=request.form.get('masoul_sabt', '').strip() or None,
            vazn_por=parse_float(request.form.get('vazn_por')),
            vazn_khali=parse_float(request.form.get('vazn_khali')),
            ghabz_por_piost=request.form.get('ghabz_por_piost') or 'خیر',
            ghabz_khali_piost=request.form.get('ghabz_khali_piost') or 'خیر',
            vaziyat_havaleh=request.form.get('vaziyat_havaleh') or 'ثبت‌شده',
            vaziyat_moghayerat=request.form.get('vaziyat_moghayerat') or 'بدون مغایرت',
            sharh_moghayerat=request.form.get('sharh_moghayerat', '').strip() or None,
            masoul_peygiri=request.form.get('masoul_peygiri', '').strip() or None,
            tarikh_peygiri=parse_date(request.form.get('tarikh_peygiri')),
            natije_peygiri=request.form.get('natije_peygiri', '').strip() or None,
            taeed_nahayi=request.form.get('taeed_nahayi', '').strip() or None,
            tarikh_taeed=parse_date(request.form.get('tarikh_taeed')),
            tozihat=request.form.get('tozihat', '').strip() or None,
        )
        db.session.add(h)
        db.session.commit()
        flash(f'حواله {shomare} با موفقیت ثبت شد.', 'success')
        return redirect(url_for('havaleh_list'))
    return render_template('havaleh_form.html', item=None, statuses=VAZIYAT_HAVALEH,
                           moghayerat_list=VAZIYAT_MOGHAYERAT, bale_kheyr=BALE_KHEYR,
                           inventory=Inventory.query.order_by(Inventory.zekhamat, Inventory.code_kala).all())

@app.route('/havaleh/<int:id>/edit', methods=['GET', 'POST'])
def havaleh_edit(id):
    h = Havaleh.query.get_or_404(id)
    if request.method == 'POST':
        h.tarikh_havaleh = parse_date(request.form.get('tarikh_havaleh'))
        h.pelak = request.form.get('pelak', '').strip() or None
        h.name_ranande = request.form.get('name_ranande', '').strip() or None
        h.mobile_ranande = request.form.get('mobile_ranande', '').strip() or None
        h.sharh_kala = request.form.get('sharh_kala', '').strip() or None
        h.moshakhasat_varagh = request.form.get('moshakhasat_varagh', '').strip() or None
        h.tedad_baste = int(request.form['tedad_baste']) if request.form.get('tedad_baste') else None
        h.vazn_esnadi = parse_float(request.form.get('vazn_esnadi'))
        h.tarikh_vorud = parse_date(request.form.get('tarikh_vorud'))
        h.saat_vorud = parse_time(request.form.get('saat_vorud'))
        h.tarikh_khoruj = parse_date(request.form.get('tarikh_khoruj'))
        h.saat_khoruj = parse_time(request.form.get('saat_khoruj'))
        h.masoul_sabt = request.form.get('masoul_sabt', '').strip() or None
        h.vazn_por = parse_float(request.form.get('vazn_por'))
        h.vazn_khali = parse_float(request.form.get('vazn_khali'))
        h.ghabz_por_piost = request.form.get('ghabz_por_piost') or 'خیر'
        h.ghabz_khali_piost = request.form.get('ghabz_khali_piost') or 'خیر'
        h.vaziyat_havaleh = request.form.get('vaziyat_havaleh') or 'ثبت‌شده'
        h.vaziyat_moghayerat = request.form.get('vaziyat_moghayerat') or 'بدون مغایرت'
        h.sharh_moghayerat = request.form.get('sharh_moghayerat', '').strip() or None
        h.masoul_peygiri = request.form.get('masoul_peygiri', '').strip() or None
        h.tarikh_peygiri = parse_date(request.form.get('tarikh_peygiri'))
        h.natije_peygiri = request.form.get('natije_peygiri', '').strip() or None
        h.taeed_nahayi = request.form.get('taeed_nahayi', '').strip() or None
        h.tarikh_taeed = parse_date(request.form.get('tarikh_taeed'))
        h.tozihat = request.form.get('tozihat', '').strip() or None
        db.session.commit()
        flash('حواله به‌روزرسانی شد.', 'success')
        return redirect(url_for('havaleh_list'))
    return render_template('havaleh_form.html', item=h, statuses=VAZIYAT_HAVALEH,
                           moghayerat_list=VAZIYAT_MOGHAYERAT, bale_kheyr=BALE_KHEYR,
                           inventory=Inventory.query.order_by(Inventory.zekhamat, Inventory.code_kala).all())

@app.route('/havaleh/<int:id>/delete', methods=['POST'])
def havaleh_delete(id):
    h = Havaleh.query.get_or_404(id)
    sh = h.shomare_havaleh
    db.session.delete(h)
    db.session.commit()
    flash(f'حواله {sh} حذف شد.', 'warning')
    return redirect(url_for('havaleh_list'))

@app.route('/inventory')
def inventory_list():
    items = Inventory.query.order_by(Inventory.zekhamat, Inventory.code_kala, Inventory.id).all()
    unique = {}
    for it in items:
        if it.code_kala not in unique:
            unique[it.code_kala] = it.mojudi_vaghei or 0
    total_kg = sum(unique.values())
    return render_template('inventory.html', items=items, total_kg=total_kg, unique_count=len(unique))

@app.route('/export/excel')
def export_excel():
    wb = Workbook()
    ws = wb.active
    ws.title = 'حواله‌ها'
    headers = ['شماره حواله', 'تاریخ حواله', 'پلاک', 'نام راننده', 'موبایل', 'شرح کالا', 'مشخصات ورق',
               'تعداد بسته', 'وزن اسنادی', 'تاریخ ورود', 'ساعت ورود', 'تاریخ خروج', 'ساعت خروج',
               'مدت توقف', 'مسئول ثبت', 'وزن پر', 'وزن خالی', 'وزن خالص', 'اختلاف وزن', 'درصد اختلاف',
               'قبض پر', 'قبض خالی', 'وضعیت قبض‌ها', 'وضعیت حواله', 'وضعیت مغایرت', 'شرح مغایرت',
               'مسئول پیگیری', 'تاریخ پیگیری', 'نتیجه پیگیری', 'تأیید نهایی', 'تاریخ تأیید', 'توضیحات']
    for col, h in enumerate(headers, 1):
        cell = ws.cell(1, col, h)
        cell.font = Font(bold=True, color='FFFFFF')
        cell.fill = PatternFill('solid', fgColor='1F4E79')
    for row_idx, h in enumerate(Havaleh.query.order_by(Havaleh.id).all(), 2):
        values = [h.shomare_havaleh, h.tarikh_havaleh.isoformat() if h.tarikh_havaleh else '',
                  h.pelak or '', h.name_ranande or '', h.mobile_ranande or '', h.sharh_kala or '',
                  h.moshakhasat_varagh or '', h.tedad_baste, h.vazn_esnadi,
                  h.tarikh_vorud.isoformat() if h.tarikh_vorud else '',
                  h.saat_vorud.strftime('%H:%M') if h.saat_vorud else '',
                  h.tarikh_khoruj.isoformat() if h.tarikh_khoruj else '',
                  h.saat_khoruj.strftime('%H:%M') if h.saat_khoruj else '', h.moddat_tavaghof_saat,
                  h.masoul_sabt or '', h.vazn_por, h.vazn_khali, h.vazn_khales, h.ekhtelaf_vazn,
                  h.darsad_ekhtelaf, h.ghabz_por_piost or '', h.ghabz_khali_piost or '',
                  h.vaziyat_ghabzha or '', h.vaziyat_havaleh or '', h.vaziyat_moghayerat or '',
                  h.sharh_moghayerat or '', h.masoul_peygiri or '',
                  h.tarikh_peygiri.isoformat() if h.tarikh_peygiri else '', h.natije_peygiri or '',
                  h.taeed_nahayi or '', h.tarikh_taeed.isoformat() if h.tarikh_taeed else '', h.tozihat or '']
        for col, v in enumerate(values, 1):
            ws.cell(row_idx, col, v)
    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f'havaleh_export_{datetime.now().strftime("%Y%m%d_%H%M")}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

INVENTORY_DATA = [
    (1, '120200195', 'ورق گرم 10 میل', 10, 'گرید فولادی P355NL2', 1458, 1, 1458.0, None, '1 شیت لیدان'),
    (2, '120200256', 'ورق گرم 10 میل', 10, 'گرید فولادی A283', 2918, 2, 1459.0, None, 'ساب استیشن'),
    (3, '120200197', 'ورق گرم 12 میل', 12, 'گرید فولادی P355 cl.1', 31870, 18, 1765.0, None, '18 شیت لیدان'),
    (4, '120200209', 'ورق گرم 13 میل', 13, 'گرید فولادی A537 * CI.1', 316800, 128, 2475.5, None, '128 شیت لیدان'),
    (5, '120200149', 'ورق گرم 14 میل', 14, 'A537cl.1', 251767, 91, 2766.0, None, '91 شیت 12 متری لیدان'),
    (6, '120200255', 'ورق گرم 14 میل', 14, 'گرید فولادی A283', 50232, 26, 1932.0, None, '5 شیت لیدان - 21 شیت ساب استیشن'),
    (7, '120200194', 'ورق گرم 18 میل', 18, 'گرید فولادی A537 cI.1', 13840, 4, 3460.0, None, 'لیدان'),
    (8, '120200261', 'ورق گرم 19 میل', 19, 'گرید فولادی A537 * CI.1', 110980, 6, 3372.0, 20230, '6 شیت 11.054 متری لیدان'),
    (8, '120200261', 'ورق گرم 19 میل', 19, 'گرید فولادی A537 * CI.1', 110980, 25, 3630.0, 90750, '25 شیت لیدان'),
    (9, '120200259', 'ورق گرم 20 میل', 20, 'گرید فولادی A283', 270908, 94, 2882.0, None, 'لیدان'),
    (10, '20080291', 'ورق گرم 20 میل', 20, 'گرید فولادی A537 * CI.1', 57776, 11, 2544.0, 27984, '11 شیت 8 متری ساب استیشن'),
    (10, '20080291', 'ورق گرم 20 میل', 20, 'گرید فولادی A537 * CI.1', 57776, 8, 3725.0, 29792, '8 شیت 12 متری لیدان'),
    (11, '120200258', 'ورق گرم 22 میل', 22, 'گرید فولادی A537 cI.1', 200350, 9, 2128.0, 19150, '9 شیت 6 متری لیدان'),
    (11, '120200258', 'ورق گرم 22 میل', 22, 'گرید فولادی A537 cI.1', 200350, 43, 4214.0, 181200, '43 شیت 12 متری لیدان'),
    (12, '120200260', 'ورق گرم 22 میل', 22, 'گرید فولادی A283', 25250, 8, 3156.0, None, 'لیدان'),
    (13, '120200217', 'ورق گرم 25 میل', 25, 'گرید فولادی A537 * CI.1', 333830, 70, 4769.0, None, '70 شیت لیدان'),
    (14, '120200206', 'ورق گرم 28 میل', 28, 'گرید فولادی A537 * CI.1', 422571, 79, 5349.0, None, 'لیدان'),
    (15, '120200201', 'ورق گرم 31 میل', 31, 'گرید فولادی A537 * CI.1', 317523, 53, 5991.0, None, '53 شیت لیدان'),
    (16, '120200198', 'ورق گرم 34 میل', 34, 'گرید فولادی A537 * CI.1', 544026, 84, 6476.5, None, '76 شیت لیدان - 8 شیت ساب استیشن'),
    (17, '120200205', 'ورق گرم 37 میل', 37, 'گرید فولادی A537 * CI.1', 451520, 64, 7055.0, None, 'لیدان'),
    (18, '120200203', 'ورق گرم 5 میل', 5, 'گرید فولادی A283*93', 897, 1.5, 725.0, None, '1.5 شیت ساب استیشن'),
    (19, '120200148', 'ورق گرم 8 میل', 8, '', 280586, 402, 587.0, 235974, '402 شیت 6 متری ساب استیشن'),
    (19, '120200148', 'ورق گرم 8 میل', 8, '', 280586, 38, 1174.0, 44612, '23 شیت 12 متری لیدان - 15 شیت 12 متری ساب استیشن'),
    (20, '120200881', 'ورق گرم 9 میل', 9, 'گرید فولادی p355 * CI.1', 21408, 16, 1338.0, None, 'لیدان'),
]

def seed_inventory():
    if Inventory.query.count() > 0: return
    for row in INVENTORY_DATA:
        db.session.add(Inventory(radif=row[0], code_kala=row[1], name_kala=row[2], zekhamat=row[3],
                                 moshakhasat=row[4] or None, mojudi_vaghei=row[5], tedad_sheet=row[6],
                                 vazn_har_sheet=row[7], vazn_goruh=row[8], mogheiyat=row[9]))
    db.session.commit()

def seed_sample_havaleh():
    if Havaleh.query.count() > 0: return
    samples = [
        dict(shomare_havaleh='HV-1405-1001', tarikh_havaleh=date(2026, 10, 15), pelak='۱۲ب۳۴۵۶۷',
             name_ranande='علی محمدی', mobile_ranande='09121234567', sharh_kala='ورق فولادی',
             moshakhasat_varagh='ST37 ضخامت ۸mm', tedad_baste=6, vazn_esnadi=20081,
             tarikh_vorud=date(2026, 10, 15), saat_vorud=time(8, 30), tarikh_khoruj=date(2026, 10, 15),
             saat_khoruj=time(13, 0), masoul_sabt='کریمی', vazn_por=34667, vazn_khali=14647,
             ghabz_por_piost='بله', ghabz_khali_piost='بله', vaziyat_havaleh='تکمیل‌شده',
             vaziyat_moghayerat='بدون مغایرت'),
        dict(shomare_havaleh='HV-1405-1002', tarikh_havaleh=date(2026, 10, 15), pelak='۲۳ج۴۵۶۷۸',
             name_ranande='حسین رضایی', sharh_kala='ورق گالوانیزه', tedad_baste=12, vazn_esnadi=22500,
             tarikh_vorud=date(2026, 10, 15), saat_vorud=time(9, 0), tarikh_khoruj=date(2026, 10, 15),
             saat_khoruj=time(14, 30), masoul_sabt='احمدی', vazn_por=38000, vazn_khali=15500,
             ghabz_por_piost='بله', ghabz_khali_piost='بله', vaziyat_havaleh='تکمیل‌شده',
             vaziyat_moghayerat='بدون مغایرت'),
        dict(shomare_havaleh='HV-1405-1003', tarikh_havaleh=date(2026, 10, 16), pelak='۳۴د۵۶۷۸۹',
             name_ranande='محمد کریمی', sharh_kala='ورق فولادی', tedad_baste=8, vazn_esnadi=22128,
             tarikh_vorud=date(2026, 10, 16), saat_vorud=time(10, 15), masoul_sabt='نوری',
             ghabz_por_piost='خیر', ghabz_khali_piost='خیر', vaziyat_havaleh='ناقص',
             vaziyat_moghayerat='بدون مغایرت'),
    ]
    for s in samples:
        db.session.add(Havaleh(**s))
    db.session.commit()

@app.cli.command('init-db')
def init_db():
    os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)
    db.create_all()
    seed_inventory()
    seed_sample_havaleh()
    print('Database initialized.')

with app.app_context():
    os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)
    db.create_all()
    seed_inventory()
    seed_sample_havaleh()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
