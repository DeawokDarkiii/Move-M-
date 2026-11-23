"""Standalone CLI script to seed Supabase (or local SQLite) with 5 wallets and 300 clean baseline logs.

Usage:
    cd backend
    python scripts/seed_db.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import db  # noqa: E402


def main() -> None:
    print(f"[FinSec Seed] Connected mode: {db.mode}")
    result = db.init_and_seed_if_empty()
    wallets = db.get_wallets()
    clean_logs = db.get_clean_baseline_logs(limit=500)
    print(f"[FinSec Seed] Result: {result}")
    print(f"[FinSec Seed] Total wallets: {len(wallets)}")
    print(f"[FinSec Seed] Total clean baseline logs: {len(clean_logs)}")


if __name__ == "__main__":
    main()
