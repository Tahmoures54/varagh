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
