from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_SECRET = "dev-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    gemini_api_key: str = Field(default="")
    gemini_model: str = Field(default="gemini-2.5-flash-lite")
    database_url: str = Field(default="postgresql://user:pass@localhost:5432/iam_analyzer")
    app_env: str = Field(default="development")
    max_policy_size_kb: int = Field(default=20)
    rate_limit_per_hour: int = Field(default=10)
    jwt_secret: str = Field(default=_WEAK_SECRET)
    jwt_access_ttl_minutes: int = Field(default=10080)
    jwt_refresh_ttl_days: int = Field(default=7)
    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="password")
    redis_url: str = Field(default="redis://localhost:6379/0")

    @model_validator(mode="after")
    def guard_production_secrets(self) -> "Settings":
        if self.app_env == "production" and self.jwt_secret == _WEAK_SECRET:
            raise RuntimeError(
                "JWT_SECRET must be set to a strong random value in production. "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return self
