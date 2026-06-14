FROM python:3.14-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /usr/local/bin/uv

COPY requirements.txt .
RUN uv venv /opt/venv \
    && uv pip install --python /opt/venv/bin/python -r requirements.txt


FROM python:3.14-slim

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

RUN rm -rf \
        /opt/venv/lib/python*/site-packages/pip* \
        /opt/venv/lib/python*/site-packages/setuptools* \
        /opt/venv/lib/python*/site-packages/wheel* \
        /usr/local/lib/python*/ensurepip/_bundled/pip*.whl \
        /usr/local/lib/python*/site-packages/pip* \
        /usr/local/lib/python*/site-packages/setuptools* \
        /usr/local/lib/python*/site-packages/wheel* \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
    && groupadd --gid 1000 appuser \
    && useradd \
        --uid 1000 \
        --gid appuser \
        --create-home \
        --home-dir /home/appuser \
        --shell /usr/sbin/nologin \
        appuser

COPY --chown=appuser:appuser app.py sophos_api.py ./
COPY --chown=appuser:appuser templates ./templates

USER appuser

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "240", "app:app"]
