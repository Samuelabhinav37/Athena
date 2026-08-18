from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from ATHENA-prefixed environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ATHENA_",
        extra="ignore",
    )

    env: str = "development"
    database_url: str = Field(
        default="postgresql+psycopg://athena:athena@localhost:5432/athena",
        min_length=1,
    )
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "athena"
    keycloak_client_id: str = "athena-collector"
    keycloak_client_secret: SecretStr = SecretStr("athena-local-collector-secret")
    opa_url: str = "http://localhost:8181"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "gemma3:4b"
    ollama_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    policy_directory: Path = Path("policies")
    control_directory: Path = Path("controls")
    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    github_org: str = ""
    github_token: SecretStr = SecretStr("")
    aws_enabled: bool = False
    aws_profile: str = ""
    aws_region: str = "us-east-1"
    auth_required: bool = True
    oidc_issuer: str = "http://localhost:8080/realms/athena"
    oidc_audience: str = "athena-api"
    oidc_jwks_url: str = ""

    @field_validator("ollama_url")
    @classmethod
    def require_local_ollama(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Ollama must use a local loopback HTTP endpoint")
        return value.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
