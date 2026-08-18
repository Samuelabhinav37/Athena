FROM python:3.13.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/athena-venv/bin:$PATH

WORKDIR /opt/athena

RUN python -m venv /opt/athena-venv \
    && addgroup --system --gid 10001 athena \
    && adduser --system --uid 10001 --ingroup athena --home /nonexistent athena

COPY pyproject.toml README.md ./
COPY apps/api ./apps/api
COPY policies ./policies
COPY controls ./controls
COPY migrations ./migrations
COPY alembic.ini ./

RUN python -m pip install --no-cache-dir .

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "athena.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "apps/api/src", "--no-access-log"]
