import json
import logging
from pathlib import Path

import pytest
from athena.config import Settings
from athena.main import app
from fastapi.testclient import TestClient
from pydantic import ValidationError


def test_request_logging_preserves_safe_correlation_id(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="athena.requests")
    with TestClient(app) as client:
        response = client.get(
            "/health?token=must-not-be-logged", headers={"X-Request-ID": "demo-42"}
        )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "demo-42"
    event = json.loads(
        next(record.message for record in caplog.records if "http_request" in record.message)
    )
    assert event["method"] == "GET"
    assert event["path"] == "/health"
    assert event["status"] == 200
    assert event["request_id"] == "demo-42"
    assert "must-not-be-logged" not in caplog.text


def test_request_logging_replaces_unsafe_correlation_id() -> None:
    with TestClient(app) as client:
        response = client.get("/health", headers={"X-Request-ID": "bad id\nforged"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] != "bad id\nforged"
    assert len(response.headers["x-request-id"]) == 36


def test_production_configuration_rejects_development_security_defaults() -> None:
    with pytest.raises(ValidationError, match="Invalid production configuration") as captured:
        Settings(env="production")

    message = str(captured.value)
    assert "default database credential" in message
    assert "default Keycloak collector secret" in message
    assert "OIDC issuer must use HTTPS" in message


def test_production_configuration_accepts_explicit_secure_values() -> None:
    settings = Settings(
        env="production",
        database_url="postgresql+psycopg://athena:strong-password@db:5432/athena",
        keycloak_client_secret="separately-provisioned-secret",
        oidc_issuer="https://identity.example.test/realms/athena",
        auth_required=True,
    )

    assert settings.auth_required is True


def test_runtime_images_are_versioned_and_drop_root() -> None:
    api = Path("apps/api/Dockerfile").read_text(encoding="utf-8")
    web = Path("apps/web/Dockerfile").read_text(encoding="utf-8")

    assert api.startswith("FROM python:3.13.14-slim-bookworm\n")
    assert "USER 10001:10001" in api
    assert "--no-access-log" in api
    assert web.startswith("FROM node:24.14.1-alpine3.23 AS build\n")
    assert "FROM nginx:1.29.8-alpine" in web
    assert "USER nginx" in web
    assert "npm ci" in web


def test_demo_stack_requires_secrets_and_does_not_publish_data_services() -> None:
    compose = Path("compose.demo.yaml").read_text(encoding="utf-8")

    assert "POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD" in compose
    assert "KEYCLOAK_ADMIN_PASSWORD:?Set KEYCLOAK_ADMIN_PASSWORD" in compose
    assert '"5432:5432"' not in compose
    assert '"8181:8181"' not in compose
    assert "read_only: true" in compose
