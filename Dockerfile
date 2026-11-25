FROM python:3.15-slim-bookworm

# V9: la aplicación se ejecuta con un usuario sin privilegios (no root).
RUN groupadd --system app \
 && useradd --system --gid app --no-create-home app \
 && mkdir -p /data && chown app:app /data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY templates ./templates
COPY static ./static

ENV PYTHONUNBUFFERED=1 DATABASE_PATH=/data/securedev.db
USER app
EXPOSE 8000
# V8: servidor WSGI de producción (Gunicorn) en lugar del servidor de desarrollo.
# Un solo proceso con hilos para que las métricas de Prometheus sean consistentes.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--no-control-socket", "app:create_app()"]
