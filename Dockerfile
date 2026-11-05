FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PROJECT_ENVIRONMENT=/opt/venv PATH=/opt/venv/bin:$PATH

RUN pip install --no-cache-dir uv

WORKDIR /srv/app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

# The named volume inherits this ownership, so the non-root user can write to it.
RUN useradd --uid 10001 --create-home sentinel \
    && mkdir -p /data/storage \
    && chown -R sentinel:sentinel /data/storage
USER sentinel

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
