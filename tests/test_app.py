import re
import io

import pytest

from app import create_app
from models import User, db, Havaleh, Inventory


@pytest.fixture()
def app():
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })
    with application.app_context():
        db.drop_all()
        db.create_all()
        admin = User(username="admin", full_name="Admin", role="admin", is_active_user=True)
        admin.set_password("strong-test-password")
        viewer = User(username="viewer", full_name="Viewer", role="viewer", is_active_user=True)
        viewer.set_password("strong-test-password")
        db.session.add_all([admin, viewer])
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client, path="/login"):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(rb'name="_csrf_token" value="([^"]+)"', response.data)
    assert match, "CSRF token should be present in rendered forms"
    return match.group(1).decode()


def login(client, username="admin"):
    token = csrf(client)
    response = client.post("/login", data={
        "_csrf_token": token,
        "username": username,
        "password": "strong-test-password",
    }, follow_redirects=False)
    assert response.status_code == 302


def test_login_and_dashboard(client):
    login(client)
    response = client.get("/")
    assert response.status_code == 200
    assert "داشبورد".encode() in response.data


def test_post_without_csrf_is_rejected(client):
    response = client.post("/login", data={"username": "admin", "password": "strong-test-password"})
    assert response.status_code == 400


def test_viewer_cannot_open_create_form(client):
    login(client, "viewer")
    response = client.get("/havaleh/new")
    assert response.status_code == 403


def test_voucher_number_is_generated(client, app):
    login(client)
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token,
        "shomare_havaleh": "",
        "vaziyat_havaleh": "ثبت‌شده",
        "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر",
        "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 302
    with app.app_context():
        item = Havaleh.query.one()
        assert re.fullmatch(r"HV-\d{4}-\d{4}", item.shomare_havaleh)



def test_blank_print_form_matches_online_registration_fields(client):
    login(client)
    response = client.get("/havaleh/blank-print")
    assert response.status_code == 200
    for label in ["ایندکس / کد کالا", "نوع وسیله", "محل موجودی", "وزن اسنادی", "وزن پُر باسکول", "وزن خالی باسکول", "وضعیت مغایرت", "مسئول پیگیری", "تأییدکننده نهایی"]:
        assert label.encode("utf-8") in response.data


def test_vehicle_type_is_saved(client, app):
    login(client)
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token,
        "shomare_havaleh": "VEHICLE-TEST",
        "noe_vasileh": "تریلی",
        "pelak": "12الف345ایران67",
        "mogheiyat_varagh": "انبار A",
        "vaziyat_havaleh": "ثبت‌شده",
        "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر",
        "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 302
    with app.app_context():
        item = Havaleh.query.filter_by(shomare_havaleh="VEHICLE-TEST").one()
        assert item.noe_vasileh == "تریلی"
        assert item.mogheiyat_varagh == "انبار A"

def test_completion_refuses_unknown_inventory_code(client, app):
    login(client)
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token,
        "shomare_havaleh": "TEST-1",
        "code_kala": "UNKNOWN",
        "vazn_esnadi": "100",
        "vazn_por": "150",
        "vazn_khali": "50",
        "vaziyat_havaleh": "تکمیل‌شده",
        "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر",
        "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 200
    with app.app_context():
        assert Havaleh.query.count() == 0


def test_completion_deducts_stock_once(client, app):
    login(client)
    with app.app_context():
        db.session.add(Inventory(code_kala="ST-1", name_kala="ورق", mojudi_vaghei=1000))
        db.session.commit()
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token,
        "shomare_havaleh": "TEST-2",
        "code_kala": "ST-1",
        "vazn_esnadi": "200",
        "vazn_por": "250",
        "vazn_khali": "50",
        "vaziyat_havaleh": "تکمیل‌شده",
        "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر",
        "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 302
    with app.app_context():
        inventory = Inventory.query.one()
        item = Havaleh.query.one()
        assert inventory.mojudi_vaghei == 800
        assert item.inventory_deducted is True


def test_admin_can_create_user(client, app):
    login(client)
    token = csrf(client, "/users")
    response = client.post("/users", data={
        "_csrf_token": token,
        "username": "warehouse_1",
        "full_name": "کاربر انبار",
        "password": "a-very-strong-password",
        "role": "anbar",
    })
    assert response.status_code == 302
    with app.app_context():
        user = User.query.filter_by(username="warehouse_1").one()
        assert user.role == "anbar"
        assert user.check_password("a-very-strong-password")


def test_warehouse_cannot_complete_voucher(client, app):
    with app.app_context():
        warehouse = User(username="warehouse", full_name="Warehouse", role="anbar", is_active_user=True)
        warehouse.set_password("strong-test-password")
        db.session.add(warehouse)
        db.session.add(Inventory(code_kala="ST-2", name_kala="ورق", mojudi_vaghei=1000))
        db.session.commit()
    login(client, "warehouse")
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token,
        "shomare_havaleh": "TEST-3",
        "code_kala": "ST-2",
        "vazn_esnadi": "200",
        "vazn_por": "250",
        "vazn_khali": "50",
        "vaziyat_havaleh": "تکمیل‌شده",
        "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر",
        "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 200
    with app.app_context():
        assert Havaleh.query.count() == 0
        assert Inventory.query.one().mojudi_vaghei == 1000


def test_inventory_csv_import_is_repeatable(client, app):
    login(client)
    token = csrf(client, "/inventory")
    payload = (
        "code_kala,name_kala,moshakhasat,mojudi_vaghei,mogheiyat\n"
        "ST-CSV,ورق,ST37-10mm,500,انبار A\n"
    ).encode("utf-8")
    response = client.post("/inventory/import", data={
        "_csrf_token": token,
        "inventory_file": (io.BytesIO(payload), "inventory.csv"),
    }, content_type="multipart/form-data")
    assert response.status_code == 302
    token = csrf(client, "/inventory")
    payload2 = (
        "code_kala,name_kala,moshakhasat,mojudi_vaghei,mogheiyat\n"
        "ST-CSV,ورق,ST37-10mm,450,انبار A\n"
    ).encode("utf-8")
    response = client.post("/inventory/import", data={
        "_csrf_token": token,
        "inventory_file": (io.BytesIO(payload2), "inventory.csv"),
    }, content_type="multipart/form-data")
    assert response.status_code == 302
    with app.app_context():
        assert Inventory.query.filter_by(code_kala="ST-CSV").count() == 1
        assert Inventory.query.filter_by(code_kala="ST-CSV").one().mojudi_vaghei == 450


def test_duplicate_stock_code_requires_matching_specification(client, app):
    with app.app_context():
        db.session.add_all([
            Inventory(code_kala="DUP", name_kala="ورق", moshakhasat="A", mogheiyat="قفسه 1", mojudi_vaghei=500),
            Inventory(code_kala="DUP", name_kala="ورق", moshakhasat="B", mogheiyat="قفسه 2", mojudi_vaghei=700),
        ])
        db.session.commit()
    login(client)
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token,
        "shomare_havaleh": "TEST-DUP",
        "code_kala": "DUP",
        "moshakhasat_varagh": "",
        "vazn_esnadi": "100",
        "vazn_por": "150",
        "vazn_khali": "50",
        "vaziyat_havaleh": "تکمیل‌شده",
        "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر",
        "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 200
    with app.app_context():
        stocks = sorted(row.mojudi_vaghei for row in Inventory.query.filter_by(code_kala="DUP").all())
        assert stocks == [500, 700]
        assert Havaleh.query.count() == 0



def test_upload_size_limit_is_configured(app):
    assert app.config["MAX_CONTENT_LENGTH"] == 8 * 1024 * 1024


def test_receipt_status_only_counts_yes_as_uploaded():
    assert Havaleh(ghabz_por_piost="خیر", ghabz_khali_piost="خیر").vaziyat_ghabzha is None
    assert Havaleh(ghabz_por_piost="بله", ghabz_khali_piost="خیر").vaziyat_ghabzha == "ناقص"
    assert Havaleh(ghabz_por_piost="بله", ghabz_khali_piost="بله").vaziyat_ghabzha == "کامل"


def test_multi_item_voucher_deducts_each_stock_atomically(client, app):
    login(client)
    with app.app_context():
        db.session.add_all([
            Inventory(code_kala="MULTI-A", name_kala="ورق A", moshakhasat="A", mogheiyat="انبار A", mojudi_vaghei=1000),
            Inventory(code_kala="MULTI-B", name_kala="ورق B", moshakhasat="B", mogheiyat="انبار B", mojudi_vaghei=800),
        ])
        db.session.commit()
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token, "shomare_havaleh": "MULTI-OK",
        "item_code_kala": ["MULTI-A", "MULTI-B"], "item_sharh_kala": ["ورق A", "ورق B"],
        "item_moshakhasat_varagh": ["A", "B"], "item_mogheiyat_varagh": ["انبار A", "انبار B"],
        "item_tedad_baste": ["2", "3"], "item_vazn_esnadi": ["200", "100"],
        "code_kala": "MULTI-A", "sharh_kala": "ورق A", "moshakhasat_varagh": "A",
        "mogheiyat_varagh": "انبار A", "tedad_baste": "2", "vazn_esnadi": "300",
        "vazn_por": "400", "vazn_khali": "100", "vaziyat_havaleh": "تکمیل‌شده",
        "vaziyat_moghayerat": "بدون مغایرت", "ghabz_por_piost": "خیر", "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 302
    with app.app_context():
        voucher = Havaleh.query.filter_by(shomare_havaleh="MULTI-OK").one()
        assert len(voucher.kala_items) == 2 and voucher.vazn_esnadi == 300
        stocks = {x.code_kala: x.mojudi_vaghei for x in Inventory.query.all()}
        assert stocks == {"MULTI-A": 800, "MULTI-B": 700}
        assert voucher.inventory_deducted is True


def test_multi_item_voucher_insufficient_stock_deducts_nothing(client, app):
    login(client)
    with app.app_context():
        db.session.add_all([
            Inventory(code_kala="MULTI-C", name_kala="ورق C", moshakhasat="C", mogheiyat="انبار C", mojudi_vaghei=1000),
            Inventory(code_kala="MULTI-D", name_kala="ورق D", moshakhasat="D", mogheiyat="انبار D", mojudi_vaghei=50),
        ])
        db.session.commit()
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token, "shomare_havaleh": "MULTI-FAIL",
        "item_code_kala": ["MULTI-C", "MULTI-D"], "item_sharh_kala": ["ورق C", "ورق D"],
        "item_moshakhasat_varagh": ["C", "D"], "item_mogheiyat_varagh": ["انبار C", "انبار D"],
        "item_tedad_baste": ["1", "1"], "item_vazn_esnadi": ["100", "100"],
        "code_kala": "MULTI-C", "sharh_kala": "ورق C", "moshakhasat_varagh": "C",
        "mogheiyat_varagh": "انبار C", "tedad_baste": "1", "vazn_esnadi": "200",
        "vazn_por": "300", "vazn_khali": "100", "vaziyat_havaleh": "تکمیل‌شده",
        "vaziyat_moghayerat": "بدون مغایرت", "ghabz_por_piost": "خیر", "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 200
    with app.app_context():
        assert Havaleh.query.filter_by(shomare_havaleh="MULTI-FAIL").count() == 0
        stocks = {x.code_kala: x.mojudi_vaghei for x in Inventory.query.all()}
        assert stocks == {"MULTI-C": 1000, "MULTI-D": 50}


def test_delivery_item_stores_raw_form_specifications(client, app):
    login(client)
    with app.app_context():
        db.session.add(Inventory(
            code_kala="RAW-1", name_kala="ورق سیاه", moshakhasat="ST37",
            zekhamat=10, tool="6", arz="1.5", tedad_sheet=20,
            vazn_har_sheet=120, mojudi_vaghei=5000, mogheiyat="لیدان",
        ))
        db.session.commit()
    token = csrf(client, "/havaleh/new")
    response = client.post("/havaleh/new", data={
        "_csrf_token": token, "shomare_havaleh": "RAW-FIELDS-1",
        "item_code_kala": ["RAW-1"], "item_sharh_kala": ["ورق سیاه"],
        "item_moshakhasat_varagh": ["ST37"], "item_mogheiyat_varagh": ["لیدان"],
        "item_tedad_baste": ["2"], "item_vazn_esnadi": ["2400"],
        "item_noe_varagh": ["ورق سیاه"], "item_grade_varagh": ["ST37"],
        "item_zekhamat": ["10"], "item_tool": ["6"], "item_arz": ["1.5"],
        "item_tedad_sheet": ["20"], "item_vazn_har_sheet": ["120"],
        "item_tozihat": ["بارگیری از محل لیدان"],
        "vaziyat_havaleh": "ثبت‌شده", "vaziyat_moghayerat": "بدون مغایرت",
        "ghabz_por_piost": "خیر", "ghabz_khali_piost": "خیر",
    })
    assert response.status_code == 302
    from models import HavalehItem
    with app.app_context():
        row = HavalehItem.query.one()
        assert (row.noe_varagh, row.grade_varagh, row.zekhamat, row.tool, row.arz) == ("ورق سیاه", "ST37", 10, 6, 1.5)
        assert (row.tedad_sheet, row.vazn_har_sheet, row.tozihat) == (20, 120, "بارگیری از محل لیدان")
