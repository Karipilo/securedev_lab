"""Pruebas funcionales de SecureDev Tickets (etapa 'Pruebas' del pipeline)."""

import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(database_path=tmp_path / "test.db")
    app.config["TESTING"] = True
    return app.test_client()


def login(client, username="ana", password="ana123"):
    return client.post("/login", data={"username": username, "password": password})


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_redirige_a_login_sin_sesion(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_correcto(client):
    response = login(client)
    assert response.status_code == 302
    assert b"Revisi" in client.get("/").data


def test_login_incorrecto(client):
    response = login(client, password="mala")
    assert "Credenciales inválidas".encode() in response.data


def test_metrics_expuestas(client):
    client.get("/health")
    body = client.get("/metrics").data
    assert b"securedev_http_requests_total" in body
    assert b"securedev_login_failures_total" in body
