"""Seed data generator for FinSec Agent.

Generates:
- 5 representative fintech system accounts (W_1001..W_1005) with 10,000,000 VND initial balance each
- 2,000 clean baseline api_logs rows (is_clean_baseline=True) distributed across all 7 fintech
  sandbox endpoints (Wallets, Payment Webhook, Withdraw, Internal Settlement, Auth Login,
  Transfer, Partner Webhook Register) so Dry-Run false positive verification runs against a
  meaningful, multi-endpoint real DB dataset.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_BASELINE_COUNT = 2000

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
    "115.79.140.23",
    "42.112.90.18",
]

CUSTOMER_USER_AGENTS = [
    "FinPay-iOS/4.8.2 (iPhone16,1; iOS 18.2)",
    "FinPay-Android/4.8.1 (Pixel 9; Android 15)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/605.1.15",
]

PARTNER_CALLBACK_URLS = [
    "https://api.merchant-partner.vn/webhooks/payment",
    "https://hooks.retail-pos.vn/v2/settlement",
    "https://notify.ecommerce-vn.com/finpay/callback",
    "https://gw.erp-accounting.vn/api/payment-notify",
]


def generate_clean_baseline_logs(total: int = DEFAULT_BASELINE_COUNT) -> list[dict[str, Any]]:
    """Build deterministic, realistic, valid historical API logs across all 7 fintech endpoints."""
    logs: list[dict[str, Any]] = []
    # Spread across 72 hours so legitimate per-actor spacing is always > 20 seconds (zero race false positives)
    base_time = datetime.now(timezone.utc) - timedelta(hours=72)
    step_seconds = max(30, int((71 * 3600) / max(total, 1)))

    # 7 endpoint groups
    per_group = total // 7
    remainder = total - (per_group * 7)
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
        event_id = f"evt_clean_{i + 1:05d}"
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
                    "tx_ref": f"wd_clean_{i + 1:05d}",
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

    # Group 5: Legitimate customer logins (Credential Stuffing / ATO baseline)
    for i in range(per_group):
        wallet = INITIAL_WALLETS[i % len(INITIAL_WALLETS)]
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        logs.append(
            {
                "method": "POST",
                "path": "/sandbox/auth/login",
                "status_code": 200,
                "ip_address": CUSTOMER_IPS[i % len(CUSTOMER_IPS)],
                "user_agent": CUSTOMER_USER_AGENTS[i % len(CUSTOMER_USER_AGENTS)],
                "actor_id": wallet["owner_id"],
                "api_key_id": None,
                "request_body": {
                    "username": wallet["owner_id"],
                    "mfa_verified": True,
                    "device_trusted": True,
                },
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    # Group 6: Legitimate P2P transfers (Parameter Tampering / Mass Assignment baseline)
    for i in range(per_group):
        src = INITIAL_WALLETS[i % len(INITIAL_WALLETS)]
        dst = INITIAL_WALLETS[(i + 1) % len(INITIAL_WALLETS)]
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        logs.append(
            {
                "method": "POST",
                "path": "/sandbox/transfer",
                "status_code": 200,
                "ip_address": CUSTOMER_IPS[i % len(CUSTOMER_IPS)],
                "user_agent": CUSTOMER_USER_AGENTS[i % len(CUSTOMER_USER_AGENTS)],
                "actor_id": src["owner_id"],
                "api_key_id": None,
                "request_body": {
                    "from_wallet": src["id"],
                    "to_wallet": dst["id"],
                    "amount": 150_000 + ((i % 6) * 50_000),
                },
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    # Group 7: Legitimate Partner Webhook Registrations (SSRF baseline — public HTTPS URLs only)
    for i in range(per_group):
        ts = (base_time + timedelta(seconds=idx * step_seconds)).isoformat()
        logs.append(
            {
                "method": "POST",
                "path": "/sandbox/webhooks/register",
                "status_code": 200,
                "ip_address": CUSTOMER_IPS[i % len(CUSTOMER_IPS)],
                "user_agent": "MerchantPortal/3.1",
                "actor_id": "usr_chi",
                "api_key_id": None,
                "request_body": {
                    "callback_url": PARTNER_CALLBACK_URLS[i % len(PARTNER_CALLBACK_URLS)],
                    "events": ["payment.success"],
                },
                "is_clean_baseline": True,
                "created_at": ts,
            }
        )
        idx += 1

    return logs
