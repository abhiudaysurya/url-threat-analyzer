"""Configuration management using pydantic-settings"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration"""

    REDIS_URL: str = "redis://localhost:6379"
    SAFE_BROWSING_API_KEY: str = ""
    CACHE_TTL: int = 3600
    RATE_LIMIT: str = "10/minute"
    MAX_URL_LENGTH: int = 2048
    SCRAPER_TIMEOUT: int = 12000
    LOG_LEVEL: str = "INFO"
    MODEL_PATH: str = "app/ml/artifacts/model.pkl"
    SCALER_PATH: str = "app/ml/artifacts/scaler.pkl"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
