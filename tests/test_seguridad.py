"""Pruebas de regresión de seguridad: cada prueba verifica que una
vulnerabilidad corregida no vuelva a aparecer (V1-V7 del informe)."""

import re

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path):
    app = create_app(database_path=tmp_path / "test.db")
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client, url="/login"):
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, username="ana", password="ana123"):
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf(client)},
    )


def test_v1_inyeccion_sql_en_busqueda(client):
    login(client)
    response = client.get("/search", query_string={"q": "' OR '1'='1"})
    assert response.status_code == 200
    # Con la consulta parametrizada el payload es texto literal: no hay resultados.
    assert b"Sin resultados" in response.data
    # La búsqueda nunca muestra tickets de otros usuarios (bruno = ticket #2).
    assert b"Acceso al panel" not in client.get("/search", query_string={"q": ""}).data


def test_v2_xss_almacenado_en_comentarios(client):
    login(client)
    payload = "<script>alert('xss')</script>"
    client.post("/tickets/1/comments", data={"body": payload, "csrf_token": csrf(client, "/tickets/1")})
    html = client.get("/tickets/1").get_data(as_text=True)
    assert payload not in html
    assert "&lt;script&gt;" in html


def test_v3_idor_ticket_ajeno(client):
    login(client)  # ana es dueña del ticket 1; el ticket 2 es de bruno
    assert client.get("/tickets/2").status_code == 404
    token = csrf(client, "/tickets/1")
    respuesta = client.post("/tickets/2/comments", data={"body": "intruso", "csrf_token": token})
    assert respuesta.status_code == 404


def test_v4_csrf_sin_token_es_rechazado(client):
    login(client)
    assert client.post("/tickets/1/comments", data={"body": "sin token"}).status_code == 400
    assert client.post("/login", data={"username": "ana", "password": "ana123"}).status_code == 400
    assert client.post("/logout").status_code == 400


def test_v5_secret_key_no_es_la_clave_fija(app):
    assert app.config["SECRET_KEY"] != "clave-insegura-solo-laboratorio"
    assert len(app.config["SECRET_KEY"]) >= 32


def test_v6_cabeceras_de_seguridad(client):
    headers = client.get("/login").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_v7_cookie_de_sesion_segura(client):
    cookie = login(client).headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
