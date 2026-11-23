import os
from functools import lru_cache
from pathlib import Path
from dotenv import load_dotenv

# Load backend/.env if present
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)


class Settings:
    def __init__(self) -> None:
        self.app_name: str = "FinSec Agent — AI SOC & Virtual Patching API"
        self.app_version: str = "1.0.0"

        # Public API key for /v1/* endpoints
        self.finsec_api_key: str = os.getenv("FINSEC_API_KEY", "finsec-demo-key-2026")

        # Internal sandbox settlement key (intentionally used in scenario 3)
        self.internal_settlement_key: str = os.getenv(
            "INTERNAL_SETTLEMENT_KEY", "internal_settlement_key_prod"
        )

        # Supabase (PostgreSQL) credentials
        self.supabase_url: str = os.getenv("SUPABASE_URL", "").strip()
        self.supabase_key: str = os.getenv("SUPABASE_KEY", "").strip()

        # Local SQLite fallback path (used automatically if SUPABASE_URL is empty)
        default_db = Path(__file__).resolve().parent.parent / "finsec_local.db"
        self.sqlite_db_path: str = os.getenv("SQLITE_DB_PATH", str(default_db))

        # LLM Configuration
        self.gemini_api_key: str = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "").strip()
        self.openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()

        # CORS
        raw_origins = os.getenv("CORS_ORIGINS", "*")
        self.cors_origins: list[str] = [
            o.strip() for o in raw_origins.split(",") if o.strip()
        ]

    @property
    def use_supabase(self) -> bool:
        return bool(self.supabase_url and self.supabase_key)


@lru_cache()
def get_settings() -> Settings:
    return Settings()
