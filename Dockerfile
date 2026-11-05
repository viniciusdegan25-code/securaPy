# SecuraPy API (Módulo F) — imagem da aplicação Flask servida pelo gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependências primeiro: o cache do Docker só refaz esta camada se o requirements mudar
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# A aplicação não precisa de root: roda com um usuário sem privilégios
RUN useradd --system --no-create-home --shell /usr/sbin/nologin securapy
USER securapy

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://localhost:8000/api/saude', timeout=3)"

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "api.app:create_app()"]
