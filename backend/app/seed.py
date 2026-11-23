"""Seed data generator for FinSec Agent.

Generates:
- 5 sample fintech wallets (W_1001..W_1005) with 10,000,000 VND initial balance each
- 300 clean baseline api_logs rows (is_clean_baseline=True) evenly distributed across
  all 4 sandbox endpoints so Dry-Run false positive tests run against real DB rows.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

INITIAL_WALLETS: list[dict[str, Any]] = [
    {"id": "W_1001", "owner_id": "usr_an", "balance": 10_000_000},
    {"id": "W_1002", "owner_id": "usr_binh", "balance": 10_000_000},
    {"id": "W_1003", "owner_id": "usr_chi", "balance": 10_000_000},
    {"id": "W_1004", "owner_id": "usr_dung", "balance": 10_000_000},
    {"id": "W_1005", "owner_id": "usr_em", "balance": 10_000_000},
]

CUSTOMER_IPS = [
    "113.161.72.14",
    "14.161.22.88",
    "171.244.19.51",
    "27.72.60.102",
    "118.70.132.45",
]

CUSTOMER_USER_AGENTS = [
    "FinPay-iOS/4.8.2 (iPhone16,1; iOS 18.2)",
    "FinPay-Android/4.8.1 (Pixel 9; Android 15)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/605.1.15",
]


def generate_clean_baseline_logs(total: int = 300) -> list[dict[str, Any]]:
    """Build 300 deterministic, realistic, valid historical API logs.

    Distribution (75 each when total=300):
    1. GET  /sandbox/wallets/{id}             — matching actor_id == owner_id
    2. POST /sandbox/webhook/payment-success  — unique event_id, gateway IP 10.0.1.x
    3. POST /sandbox/withdraw                 — matching owner, spaced timestamps
    4. GET  /sandbox/admin/settlement         — internal_settlement_key_prod from 10.0.1.x
    """
    logs: list[dict[str, Any]] = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=24)
    step_seconds = int((23 * 3600) / max(total, 1))

    per_group = total // 4
    remainder = total - (per_group * 4)

    idx = 0

    # Group 1: Legitimate wallet balance reads (BOLA baseline)
    for i in range(per_group + remainder):
        wallet = INITIAL_WALLETS[i % len(INITIAL_WALLETS)]
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        logs.append(
            {
                "method": "GET",
                "path": f"/sandbox/wallets/{wallet['id']}",
                "status_code": 200,
                "ip_address": CUSTOMER_IPS[i % len(CUSTOMER_IPS)],
                "user_agent": CUSTOMER_USER_AGENTS[i % len(CUSTOMER_USER_AGENTS)],
                "actor_id": wallet["owner_id"],
                "api_key_id": None,
                "request_body": {},
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    # Group 2: Legitimate payment webhooks (Webhook Replay baseline)
    for i in range(per_group):
        wallet = INITIAL_WALLETS[i % len(INITIAL_WALLETS)]
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        event_id = f"evt_clean_{i + 1:04d}"
        amount = 200_000 + ((i % 5) * 100_000)
        logs.append(
            {
                "method": "POST",
                "path": "/sandbox/webhook/payment-success",
                "status_code": 200,
                "ip_address": f"10.0.1.{10 + (i % 15)}",
                "user_agent": "Napas-PaymentGateway/2.4",
                "actor_id": "gateway_napas",
                "api_key_id": None,
                "request_body": {
                    "event_id": event_id,
                    "wallet_id": wallet["id"],
                    "amount": amount,
                    "channel": "NAPAS_247",
                },
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    # Group 3: Legitimate customer withdrawals (Race Condition baseline — spaced minutes apart)
    for i in range(per_group):
        wallet = INITIAL_WALLETS[i % len(INITIAL_WALLETS)]
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        amount = 100_000 + ((i % 4) * 50_000)
        logs.append(
            {
                "method": "POST",
                "path": "/sandbox/withdraw",
                "status_code": 200,
                "ip_address": CUSTOMER_IPS[i % len(CUSTOMER_IPS)],
                "user_agent": CUSTOMER_USER_AGENTS[i % len(CUSTOMER_USER_AGENTS)],
                "actor_id": wallet["owner_id"],
                "api_key_id": None,
                "request_body": {
                    "wallet_id": wallet["id"],
                    "amount": amount,
                    "tx_ref": f"wd_clean_{i + 1:04d}",
                },
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    # Group 4: Legitimate internal settlement cron jobs (Internal API Key baseline — 10.0.1.0/24)
    for i in range(per_group):
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        logs.append(
            {
                "method": "GET",
                "path": "/sandbox/admin/settlement",
                "status_code": 200,
                "ip_address": f"10.0.1.{30 + (i % 40)}",
                "user_agent": "FinSec-SettlementCron/1.2",
                "actor_id": "svc_settlement_batch",
                "api_key_id": "internal_settlement_key_prod",
                "request_body": {},
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    return logs
