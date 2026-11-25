"""SecureDev Tickets - versión corregida (OCY1102 EV3).

Correcciones de seguridad aplicadas (detalle en docs/INFORME.md):
  V1  Inyección SQL en /search            -> consulta parametrizada
  V2  XSS almacenado en comentarios        -> se elimina el filtro |safe (autoescape)
  V3  IDOR en /tickets/<id> y comentarios  -> control de acceso por propietario
  V4  Ausencia de tokens CSRF              -> token CSRF por sesión en todo POST
  V5  SECRET_KEY fija en el código         -> se toma del entorno o se genera aleatoria
  V6  Cabeceras de seguridad ausentes      -> CSP, X-Frame-Options, nosniff, etc.
  V7  Cookie de sesión sin SameSite        -> SameSite=Lax + HttpOnly
  V8  Servidor de desarrollo / bind 0.0.0.0 -> Gunicorn en el contenedor
"""

import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash


HTTP_REQUESTS = Counter(
    "securedev_http_requests_total",
    "Solicitudes HTTP de la aplicación",
    ["endpoint", "method", "status"],
)
HTTP_DURATION = Histogram(
    "securedev_http_request_duration_seconds",
    "Duración de solicitudes HTTP",
    ["endpoint"],
)
LOGIN_FAILURES = Counter(
    "securedev_login_failures_total",
    "Intentos de acceso fallidos",
)
# Métricas de incidentes de seguridad para la monitorización (Grafana).
CSRF_REJECTED = Counter(
    "securedev_csrf_rejected_total",
    "Solicitudes POST rechazadas por token CSRF inválido o ausente",
)
ACCESS_DENIED = Counter(
    "securedev_access_denied_total",
    "Intentos de acceso a tickets de otro usuario (IDOR bloqueado)",
)

SECURITY_HEADERS = {
    # V6: política de contenido restrictiva (sin scripts ni estilos en línea).
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def create_app(database_path=None):
    app = Flask(__name__)
    # V5: la clave se inyecta por variable de entorno; si no existe se genera una
    # aleatoria (las sesiones se invalidan al reiniciar, nunca se usa una clave fija).
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    app.config["DATABASE_PATH"] = str(
        database_path or os.getenv("DATABASE_PATH", str(Path(__file__).with_name("securedev.db")))
    )
    # V7: atributos de la cookie de sesión. SESSION_COOKIE_SECURE se activa al
    # publicar detrás de HTTPS (variable de entorno SESSION_COOKIE_SECURE=1).
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE") == "1",
    )

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    # V4: protección CSRF (patrón de token sincronizado almacenado en la sesión).
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def start_request_timer():
        g.request_started_at = time.perf_counter()

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                CSRF_REJECTED.inc()
                abort(400, description="Token CSRF inválido o ausente")

    @app.after_request
    def record_request(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.endpoint != "metrics":
            endpoint = request.endpoint or "unknown"
            HTTP_REQUESTS.labels(endpoint, request.method, str(response.status_code)).inc()
            HTTP_DURATION.labels(endpoint).observe(time.perf_counter() - g.request_started_at)
        return response

    with app.app_context():
        Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
        connection = db()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                ticket_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [
                    (1, "ana", generate_password_hash("ana123")),
                    (2, "bruno", generate_password_hash("bruno123")),
                ],
            )
            connection.executemany(
                "INSERT INTO tickets (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, "Revisión de despliegue", "Preparar evidencias de CI/CD."),
                    (2, 2, "Acceso al panel", "Revisar registros de acceso."),
                ],
            )
        connection.commit()

    def current_user():
        return session.get("user_id")

    def own_ticket_or_404(ticket_id):
        # V3: solo el propietario puede ver o comentar su ticket. Se responde 404
        # (y no 403) para no revelar la existencia de tickets ajenos.
        item = db().execute(
            "SELECT id, owner_id, title, body FROM tickets WHERE id = ? AND owner_id = ?",
            (ticket_id, current_user()),
        ).fetchone()
        if item is None:
            if db().execute("SELECT 1 FROM tickets WHERE id = ?", (ticket_id,)).fetchone():
                ACCESS_DENIED.inc()
            abort(404)
        return item

    @app.route("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? ORDER BY id", (current_user(),)
        ).fetchall()
        return render_template("index.html", tickets=tickets)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()  # evita fijación de sesión
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("index"))
            LOGIN_FAILURES.inc()
            error = "Credenciales inválidas"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/tickets/<int:ticket_id>")
    def ticket(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        item = own_ticket_or_404(ticket_id)
        comments = db().execute(
            "SELECT body FROM comments WHERE ticket_id = ? ORDER BY id", (ticket_id,)
        ).fetchall()
        return render_template("ticket.html", ticket=item, comments=comments)

    @app.post("/tickets/<int:ticket_id>/comments")
    def add_comment(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        own_ticket_or_404(ticket_id)
        body = request.form.get("body", "").strip()[:2000]
        if body:
            db().execute(
                "INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
                (ticket_id, current_user(), body),
            )
            db().commit()
        return redirect(url_for("ticket", ticket_id=ticket_id))

    @app.get("/search")
    def search():
        if not current_user():
            return redirect(url_for("login"))
        query = request.args.get("q", "")[:100]
        # V1: consulta parametrizada; además solo busca en tickets del usuario.
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? AND title LIKE ? ORDER BY id",
            (current_user(), f"%{query}%"),
        ).fetchall()
        return render_template("search.html", tickets=tickets, query=query)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        return app.response_class(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app


if __name__ == "__main__":
    # Solo para desarrollo local. En el contenedor la app se sirve con Gunicorn.
    create_app().run(host="127.0.0.1", port=8000)
