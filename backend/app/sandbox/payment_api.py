"""4 Simulated Fintech Payment Gateway APIs with Intentional Real Vulnerabilities + Normal Traffic.

Vulnerabilities (until FinSec AI Virtual Patching Policy is enforced in Middleware):
1. POST /sandbox/webhook/payment-success  -> Webhook Replay (missing event_id idempotency check)
2. GET  /sandbox/wallets/{wallet_id}      -> BOLA / IDOR (missing actor_id == wallet.owner_id check)
3. GET  /sandbox/admin/settlement         -> Leaked Internal API Key (no internal CIDR whitelist)
4. POST /sandbox/withdraw                 -> Race Condition TOCTOU (async delay without lock)
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import get_settings
from app.db import db

router = APIRouter(prefix="/sandbox", tags=["Payment Sandbox (Vulnerable Target)"])


class WebhookPaymentPayload(BaseModel):
    event_id: str = Field(..., examples=["evt_pay_99881"])
    wallet_id: str = Field(..., examples=["W_1001"])
    amount: int = Field(..., gt=0, examples=[5000000])
    channel: Optional[str] = Field(default="NAPAS_247")
    note: Optional[str] = Field(default=None)


class WithdrawPayload(BaseModel):
    wallet_id: str = Field(..., examples=["W_1001"])
    amount: int = Field(..., gt=0, examples=[4000000])
    tx_ref: Optional[str] = Field(default=None)
    note: Optional[str] = Field(default=None)


def extract_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def extract_actor_id(
    x_actor_id: Optional[str], authorization: Optional[str]
) -> Optional[str]:
    if x_actor_id:
        return x_actor_id.strip()
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        # Demo token format: "jwt_usr_an" or plain "usr_an"
        if token.startswith("jwt_"):
            return token[4:]
        return token
    return None


def _log_sandbox_request(
    request: Request,
    status_code: int,
    actor_id: Optional[str] = None,
    api_key_id: Optional[str] = None,
    request_body: Optional[dict[str, Any]] = None,
) -> None:
    db.insert_api_log(
        {
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "ip_address": extract_client_ip(request),
            "user_agent": request.headers.get("user-agent", "unknown"),
            "actor_id": actor_id,
            "api_key_id": api_key_id,
            "request_body": request_body or {},
            "is_clean_baseline": False,
        }
    )


# ------------------------------------------------------------------
# 1. Webhook Payment Success (VULNERABLE: Webhook Replay / No Idempotency)
# ------------------------------------------------------------------
@router.post("/webhook/payment-success")
async def payment_success_webhook(
    payload: WebhookPaymentPayload,
    request: Request,
    x_actor_id: Optional[str] = Header(default="gateway_webhook"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    actor_id = extract_actor_id(x_actor_id, authorization)
    wallet = db.get_wallet(payload.wallet_id)
    if not wallet:
        _log_sandbox_request(request, 404, actor_id=actor_id, request_body=payload.model_dump())
        raise HTTPException(status_code=404, detail=f"Wallet {payload.wallet_id} not found")

    # INTENTIONAL VULNERABILITY: No deduplication check on payload.event_id!
    # Replaying the exact same event_id repeatedly credits the wallet every single time.
    new_balance = int(wallet["balance"]) + int(payload.amount)
    updated_wallet = db.update_wallet_balance(payload.wallet_id, new_balance)
    ledger = db.add_ledger_entry(
        wallet_id=payload.wallet_id,
        tx_ref=payload.event_id,
        amount=payload.amount,
        entry_type="DEPOSIT",
    )

    _log_sandbox_request(
        request,
        200,
        actor_id=actor_id,
        request_body=payload.model_dump(),
    )

    return {
        "status": "credited",
        "event_id": payload.event_id,
        "wallet_id": payload.wallet_id,
        "credited_amount": payload.amount,
        "new_balance": updated_wallet["balance"] if updated_wallet else new_balance,
        "ledger_id": ledger["id"],
    }


# ------------------------------------------------------------------
# 2. Get Wallet Details (VULNERABLE: BOLA / IDOR — No Owner Check)
# ------------------------------------------------------------------
@router.get("/wallets/{wallet_id}")
async def get_wallet_info(
    wallet_id: str,
    request: Request,
    x_actor_id: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    actor_id = extract_actor_id(x_actor_id, authorization)
    wallet = db.get_wallet(wallet_id)
    if not wallet:
        _log_sandbox_request(request, 404, actor_id=actor_id)
        raise HTTPException(status_code=404, detail=f"Wallet {wallet_id} not found")

    # INTENTIONAL VULNERABILITY (OWASP API1:2023 BOLA):
    # Fails to verify whether actor_id == wallet["owner_id"]!
    ledger_entries = db.get_ledger_entries(wallet_id=wallet_id, limit=5)

    _log_sandbox_request(request, 200, actor_id=actor_id)

    return {
        "wallet_id": wallet["id"],
        "owner_id": wallet["owner_id"],
        "balance": wallet["balance"],
        "currency": "VND",
        "requested_by": actor_id,
        "recent_ledger": ledger_entries,
    }


# ------------------------------------------------------------------
# 3. Admin Settlement Export (VULNERABLE: Leaked Internal Key / No IP Whitelist)
# ------------------------------------------------------------------
@router.get("/admin/settlement")
async def admin_settlement_report(
    request: Request,
    x_internal_api_key: Optional[str] = Header(default=None),
    x_actor_id: Optional[str] = Header(default="svc_settlement_batch"),
) -> dict[str, Any]:
    settings = get_settings()
    if not x_internal_api_key or x_internal_api_key != settings.internal_settlement_key:
        _log_sandbox_request(
            request,
            401,
            actor_id=x_actor_id,
            api_key_id=x_internal_api_key or "missing_key",
        )
        raise HTTPException(status_code=401, detail="Invalid or missing X-Internal-Api-Key")

    # INTENTIONAL VULNERABILITY: Accepts internal_settlement_key_prod from ANY public IP!
    wallets = db.get_wallets()
    total_float = sum(int(w["balance"]) for w in wallets)

    _log_sandbox_request(
        request,
        200,
        actor_id=x_actor_id,
        api_key_id=x_internal_api_key,
    )

    return {
        "batch_id": f"STL-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}",
        "total_wallets": len(wallets),
        "total_float_vnd": total_float,
        "wallets": wallets,
        "warning": "SENSITIVE_INTERNAL_SETTLEMENT_DATA",
    }


# ------------------------------------------------------------------
# 4. Wallet Withdraw (VULNERABLE: Async Race Condition / Double Spend)
# ------------------------------------------------------------------
@router.post("/withdraw")
async def withdraw_funds(
    payload: WithdrawPayload,
    request: Request,
    x_actor_id: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    actor_id = extract_actor_id(x_actor_id, authorization)
    wallet = db.get_wallet(payload.wallet_id)
    if not wallet:
        _log_sandbox_request(request, 404, actor_id=actor_id, request_body=payload.model_dump())
        raise HTTPException(status_code=404, detail=f"Wallet {payload.wallet_id} not found")

    if not actor_id:
        actor_id = wallet["owner_id"]

    # INTENTIONAL VULNERABILITY (TOCTOU Race Condition):
    # Check balance BEFORE async I/O delay without any row/distributed lock!
    checked_balance = int(wallet["balance"])
    if checked_balance < payload.amount:
        _log_sandbox_request(request, 400, actor_id=actor_id, request_body=payload.model_dump())
        raise HTTPException(status_code=400, detail="Insufficient wallet balance")

    # Simulated slow bank payout call allowing concurrent requests to pass balance check
    await asyncio.sleep(0.18)

    # Re-read latest balance and deduct (pushing wallet negative on concurrent double-spend!)
    latest_wallet = db.get_wallet(payload.wallet_id)
    current_bal = int(latest_wallet["balance"]) if latest_wallet else checked_balance
    new_balance = current_bal - int(payload.amount)

    updated = db.update_wallet_balance(payload.wallet_id, new_balance)
    tx_ref = payload.tx_ref or f"wd_{uuid.uuid4().hex[:10]}"
    ledger = db.add_ledger_entry(
        wallet_id=payload.wallet_id,
        tx_ref=tx_ref,
        amount=-int(payload.amount),
        entry_type="WITHDRAW",
    )

    _log_sandbox_request(
        request,
        200,
        actor_id=actor_id,
        request_body={**payload.model_dump(), "tx_ref": tx_ref},
    )

    return {
        "status": "withdrawn",
        "wallet_id": payload.wallet_id,
        "withdrawn_amount": payload.amount,
        "tx_ref": tx_ref,
        "new_balance": updated["balance"] if updated else new_balance,
        "ledger_id": ledger["id"],
    }
