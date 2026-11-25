"""Simula incidentes de seguridad contra la aplicación para validar la
monitorización (Prometheus + Grafana). Solo para el laboratorio.

Uso (desde la carpeta del repositorio, con la red devsecops creada):
  docker run --rm --network devsecops -v "${PWD}/security:/s:ro" \
      python:3.15-slim-bookworm python /s/simular_incidentes.py http://securedev-app:8000
"""

import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "http://securedev-app:8000"


def nuevo_cliente():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )


def pedir(cliente, ruta, datos=None):
    cuerpo = urllib.parse.urlencode(datos).encode() if datos is not None else None
    try:
        with cliente.open(URL + ruta, data=cuerpo, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""


def token(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def fuerza_bruta(intentos=20):
    cliente = nuevo_cliente()
    _, html = pedir(cliente, "/login")
    for i in range(intentos):
        _, html = pedir(cliente, "/login",
                        {"username": "ana", "password": f"clave{i}", "csrf_token": token(html)})
    print(f"[1] Fuerza bruta: {intentos} intentos de login fallidos contra 'ana'")


def csrf(intentos=10):
    cliente = nuevo_cliente()
    codigos = [pedir(cliente, "/tickets/1/comments", {"body": "ataque csrf"})[0] for _ in range(intentos)]
    print(f"[2] CSRF: {intentos} POST sin token -> códigos {sorted(set(codigos))}")


def idor(intentos=10):
    cliente = nuevo_cliente()
    _, html = pedir(cliente, "/login")
    pedir(cliente, "/login", {"username": "ana", "password": "ana123", "csrf_token": token(html)})
    codigos = [pedir(cliente, "/tickets/2")[0] for _ in range(intentos)]
    print(f"[3] IDOR: 'ana' pidió {intentos} veces el ticket #2 de 'bruno' -> códigos {sorted(set(codigos))}")


if __name__ == "__main__":
    print(f"Simulando incidentes contra {URL}")
    fuerza_bruta()
    csrf()
    idor()
    print("Listo. Revisa el dashboard de Grafana y las alertas en Prometheus.")
