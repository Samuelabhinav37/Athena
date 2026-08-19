import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
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
    neo4j_enabled: bool = False
    neo4j_url: str = "neo4j://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("")
    neo4j_database: str = "neo4j"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "gemma3:4b"
    ollama_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    ai_provider: str = "ollama"
    azure_ai_endpoint: str = ""
    azure_ai_deployment: str = ""
    azure_ai_api_version: str = "2024-10-21"
    azure_ai_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    policy_directory: Path = Path("policies")
    control_directory: Path = Path("controls")
    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    github_org: str = ""
    github_token: SecretStr = SecretStr("")
    azure_enabled: bool = False
    azure_tenant_id: str = ""
    azure_subscription_id: str = ""
    azure_graph_url: str = "https://graph.microsoft.com"
    azure_management_url: str = "https://management.azure.com"
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

    @field_validator("ai_provider")
    @classmethod
    def require_supported_ai_provider(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"ollama", "azure_ai"}:
            raise ValueError("AI provider must be 'ollama' or 'azure_ai'")
        return normalized

    @field_validator("azure_ai_endpoint")
    @classmethod
    def require_guarded_azure_ai_endpoint(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlparse(value)
        hostname = (parsed.hostname or "").lower()
        allowed = hostname.endswith(".openai.azure.com") or hostname.endswith(
            ".services.ai.azure.com"
        )
        if parsed.scheme != "https" or not allowed or parsed.username or parsed.password:
            raise ValueError("Azure AI must use an HTTPS Azure AI endpoint without credentials")
        return value.rstrip("/")

    @field_validator("azure_ai_deployment")
    @classmethod
    def require_safe_azure_ai_deployment(cls, value: str) -> str:
        if value and re.fullmatch(r"[A-Za-z0-9._-]+", value) is None:
            raise ValueError("Azure AI deployment contains invalid characters")
        return value

    @field_validator("azure_ai_api_version")
    @classmethod
    def require_safe_azure_ai_api_version(cls, value: str) -> str:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:-preview)?", value) is None:
            raise ValueError("Azure AI API version must be a dated version")
        return value

    @model_validator(mode="after")
    def validate_ai_provider_configuration(self) -> "Settings":
        if self.ai_provider == "azure_ai" and (
            not self.azure_ai_endpoint or not self.azure_ai_deployment
        ):
            raise ValueError("Azure AI provider requires an endpoint and deployment")
        return self

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        if self.env.lower() != "production":
            return self
        errors = []
        if not self.auth_required:
            errors.append("authentication must be enabled")
        if "athena:athena@" in self.database_url:
            errors.append("the default database credential is forbidden")
        if self.keycloak_client_secret.get_secret_value() == "athena-local-collector-secret":
            errors.append("the default Keycloak collector secret is forbidden")
        if not self.oidc_issuer.startswith("https://"):
            errors.append("the OIDC issuer must use HTTPS")
        if errors:
            raise ValueError("Invalid production configuration: " + "; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
