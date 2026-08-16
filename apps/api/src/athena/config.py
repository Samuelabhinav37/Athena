from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
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
    policy_directory: Path = Path("policies")


@lru_cache
def get_settings() -> Settings:
    return Settings()
