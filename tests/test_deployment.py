import json
import logging
from pathlib import Path

import pytest
from athena import database
from athena.config import Settings
from athena.main import app
from fastapi.testclient import TestClient
from pydantic import ValidationError


def test_request_logging_preserves_safe_correlation_id() -> None:
    assert logging.getLogger("athena.requests").level == logging.INFO
    request_logger = logging.getLogger("athena.requests")
    assert request_logger.propagate is False
    records: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    capture_handler = CaptureHandler()
    request_logger.addHandler(capture_handler)
    try:
        with TestClient(app) as client:
            response = client.get(
                "/health?token=must-not-be-logged", headers={"X-Request-ID": "demo-42"}
            )
    finally:
        request_logger.removeHandler(capture_handler)

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "demo-42"
    event = json.loads(
        next(record.message for record in records if "http_request" in record.message)
    )
    assert event["method"] == "GET"
    assert event["path"] == "/health"
    assert event["status"] == 200
    assert event["request_id"] == "demo-42"
    assert "must-not-be-logged" not in "".join(record.message for record in records)


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
    assert "default application database credential" in message
    assert "default migration database credential" in message
    assert "default Keycloak collector secret" in message
    assert "OIDC issuer must use HTTPS" in message


def test_production_configuration_rejects_incomplete_tenant_isolation() -> None:
    with pytest.raises(ValidationError, match="tenant isolation is not production-ready"):
        Settings(
            env="production",
            database_url="postgresql+psycopg://athena_app:strong-app-password@db:5432/athena",
            migration_database_url=(
                "postgresql+psycopg://athena_migrator:strong-owner-password@db:5432/athena"
            ),
            system_tenant_id="production-system",
            keycloak_client_secret="separately-provisioned-secret",
            oidc_issuer="https://identity.example.test/realms/athena",
            auth_required=True,
        )


def test_configuration_rejects_multiple_api_workers_with_process_local_controls() -> None:
    with pytest.raises(ValidationError, match="process-local telemetry controls require one API"):
        Settings(api_worker_count=2)


def test_configuration_rejects_multiple_api_replicas_with_process_local_controls() -> None:
    with pytest.raises(ValidationError, match="process-local telemetry controls require one API"):
        Settings(api_replica_count=2)


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

    nginx = Path("apps/web/nginx.conf").read_text(encoding="utf-8")
    assert "resolver 127.0.0.11" in nginx
    assert "proxy_pass $api_upstream" in nginx
    assert "proxy_set_header X-Request-ID $http_x_request_id" in nginx


def test_demo_stack_requires_secrets_and_does_not_publish_data_services() -> None:
    compose = Path("compose.demo.yaml").read_text(encoding="utf-8")

    assert "POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD" in compose
    assert "KEYCLOAK_ADMIN_PASSWORD:?Set KEYCLOAK_ADMIN_PASSWORD" in compose
    assert '"5432:5432"' not in compose
    assert '"8181:8181"' not in compose
    assert "read_only: true" in compose
    assert "Host: localhost" in compose
    assert "ATHENA_KEYCLOAK_URL: http://keycloak:8080" in compose
    assert "ATHENA_OIDC_IDENTITY_SOURCE: keycloak" in compose
    assert "neo4j:2026.06.0-community" in compose
    assert "NEO4J_AUTH:?Set NEO4J_AUTH" in compose
    assert '"7474:7474"' not in compose
    assert '"7687:7687"' not in compose


def test_demo_exposes_only_an_explicit_profile_gated_schema_migration() -> None:
    compose = Path("compose.demo.yaml").read_text(encoding="utf-8")
    api_environment = compose.split("  api:", 1)[1].split("    depends_on:", 1)[0]

    assert "  migrate:" in compose
    assert 'command: ["alembic", "upgrade", "head"]' in compose
    assert 'profiles: ["migration"]' in compose
    assert "ATHENA_MIGRATION_DATABASE_URL:" in compose
    assert "ATHENA_MIGRATION_DATABASE_URL:" not in api_environment
    assert "condition: service_completed_successfully" not in compose


def test_existing_volume_upgrade_documents_interactive_runtime_password_provisioning() -> None:
    deployment = Path("docs/deployment.md").read_text(encoding="utf-8")

    assert "Existing PostgreSQL volumes" in deployment
    assert "\\password athena_app" in deployment


def test_administrative_session_factory_uses_separate_migration_identity(monkeypatch) -> None:
    settings = Settings(
        database_url="postgresql+psycopg://athena_app:runtime@runtime-db/athena",
        migration_database_url="postgresql+psycopg://athena_migrator:owner@admin-db/athena",
    )
    monkeypatch.setattr(database, "get_settings", lambda: settings)
    database.get_administrative_engine.cache_clear()
    try:
        factory = database.get_administrative_session_factory()
        assert str(factory.kw["bind"].url).startswith(
            "postgresql+psycopg://athena_migrator:***@admin-db/athena"
        )
        assert factory.kw["info"] == {}
    finally:
        database.get_administrative_engine.cache_clear()


def test_ci_supplies_graph_placeholders_for_compose_validation() -> None:
    workflow = Path(".github/workflows/security-gate.yml").read_text(encoding="utf-8")

    assert "NEO4J_AUTH: neo4j/ci-compose-validation" in workflow
    assert "NEO4J_PASSWORD: ci-compose-validation" in workflow


def test_ci_runs_postgresql_isolation_suite_as_an_explicit_required_step() -> None:
    workflow = Path(".github/workflows/security-gate.yml").read_text(encoding="utf-8")

    assert "name: Run PostgreSQL isolation tests" in workflow
    assert "pytest -q tests/test_tenant_constraints_postgres.py" in workflow
    assert "pytest -q --ignore=tests/test_tenant_constraints_postgres.py" in workflow


def test_dashboard_exposes_bounded_advisory_attack_paths() -> None:
    application = Path("apps/web/src/App.tsx").read_text(encoding="utf-8")

    assert "/v1/attack-paths/identities/${selectedId}?max_depth=6&limit=25" in application
    assert "Advisory only" in application
    assert "PostgreSQL evidence remains available" in application


def test_dashboard_exposes_machine_identity_posture_without_access_changes() -> None:
    application = Path("apps/web/src/App.tsx").read_text(encoding="utf-8")

    assert '"/v1/machine-identities?limit=200"' in application
    assert "Machine identity" in application
    assert "Read-only analysis" in application
    assert "no automatic access changes" in application
