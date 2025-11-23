"""Application configuration"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings"""

    # App
    APP_NAME: str = "Knock Knock Web"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str = "sqlite:///./data/db/knockknock.db"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5000", "http://localhost:8000"]

    # File paths
    REPORTS_DIR: str = "./data/reports"
    SCANNER_CONFIG_PATH: str = "conf/config.yaml"

    # Scanner defaults
    MASSCAN_RATE_DEFAULT: int = 1000
    MAX_CONCURRENT_DEFAULT: int = 10
    HOST_TIMEOUT_DEFAULT: int = 1200
    PPS_MAX: int = 10000

    # Nuclei defaults
    NUCLEI_ENABLED_DEFAULT: bool = False
    NUCLEI_SEVERITY_DEFAULT: str = "critical,high"

    # SMTP (for email overrides)
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 25
    SMTP_USE_TLS: bool = False
    SMTP_FROM: str = "knockknock@example.com"

    # Admin bootstrap
    ADMIN_EMAIL: str = "admin@example.com"
    ADMIN_PASSWORD: str = "admin"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings(_env_file=".env", _env_file_encoding="utf-8")
