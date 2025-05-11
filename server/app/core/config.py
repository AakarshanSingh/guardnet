import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


class Settings(BaseSettings):
    API_V1_STR: str = "/api"
    PROJECT_NAME: str = "GuardNet Security Scanner"

    # Security settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecretkey12345abcdef")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    ALGORITHM: str = "HS256"

    # Database configuration
    # Uses PostgreSQL in production but falls back to SQLite for development
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./guardnet.db")
    print(DATABASE_URL)

    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost",
        "https://localhost",
    ]

    # Scanner settings
    SCAN_TIMEOUT: int = 300  # 5 minutes maximum for any scan to complete

    # Selenium settings
    SELENIUM_IMPLICIT_WAIT: int = 10

    # WPScan settings
    WPSCAN_ENABLED: bool = True
    WPSCAN_API_TOKEN: Optional[str] = os.getenv("WPSCAN_API_TOKEN", None)

    model_config = {"case_sensitive": True}


settings = Settings()
