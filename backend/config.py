from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    secret_key: str
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Optional — leave empty to disable Google login.
    google_client_id: str = ""
    google_client_secret: str = ""

    # pydantic-settings reads from .env automatically; validation errors surface
    # at startup before any request is served, which is intentional.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
