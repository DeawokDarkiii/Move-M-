"""FinSec Agent — FastAPI Application Entrypoint.

Mounts:
- CORS Middleware
- slowapi Rate Limiter
- Live Dynamic Virtual Patching Middleware (protects /sandbox/* with ACTIVE DB rules in <5ms)
- /sandbox/* Payment Gateway Target APIs
- /v1/* Public Commercial SOC & Virtual Patching Service APIs (Swagger UI at /docs)
"""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.db import db
from app.policy.engine import (
    evaluate_rule,
    get_active_rules_cached,
    get_actor_lock,
)
from app.routers.api_v1 import limiter, router as api_v1_router
from app.sandbox.payment_api import (
    extract_actor_id,
    extract_client_ip,
    router as sandbox_router,
)

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    seed_info = db.init_and_seed_if_empty()
    print(f"[FinSec Startup] Ready -> {seed_info}")
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Autonomous AI SOC & Safe Virtual Patching Platform for Fintech Operations.\n\n"
        "**Public Evaluation API Key (`X-API-Key`):** `finsec-demo-key-2026`\n\n"
        "- `/v1/logs/ingest`: Ingest external API logs\n"
        "- `/v1/incidents/investigate`: Trigger ReAct AI SOC Agent with Dry-Run blast-radius verification\n"
        "- `/v1/policies/{rule_id}/enforce` & `/rollback`: Real-time middleware virtual patching\n"
        "- `/v1/sandbox/reset`: Clean reset preserving 300 `is_clean_baseline=TRUE` records"
    ),
    lifespan=lifespan,
)

# Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins if "*" not in settings.cors_origins else ["*"],
    allow_credentials=False if "*" in settings.cors_origins else True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------
# Live Dynamic Virtual Patching Middleware (<5ms cached evaluation)
# ------------------------------------------------------------------
@app.middleware("http")
async def dynamic_virtual_patching_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/sandbox/"):
        return await call_next(request)

    active_rules = get_active_rules_cached()
    if not active_rules:
        return await call_next(request)

    t0 = time.perf_counter()

    # Safely parse JSON body (caches request._body so downstream FastAPI reads it normally)
    request_body: dict[str, Any] = {}
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            raw_bytes = await request.body()
            if raw_bytes:
                parsed = json.loads(raw_bytes.decode("utf-8"))
                if isinstance(parsed, dict):
                    request_body = parsed
        except Exception:
            request_body = {}

    ip_address = extract_client_ip(request)
    actor_id = extract_actor_id(
        request.headers.get("x-actor-id"),
        request.headers.get("authorization"),
    )
    api_key_id = request.headers.get("x-internal-api-key")
    user_agent = request.headers.get("user-agent", "unknown")

    req_context = {
        "method": request.method,
        "path": path,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "actor_id": actor_id,
        "api_key_id": api_key_id,
        "request_body": request_body,
    }

    held_lock = None
    for rule in active_rules:
        rule_spec = rule.get("rule_spec") or {}
        if evaluate_rule(rule_spec, req_context, is_live=True):
            status_code = 429 if rule_spec.get("action") == "BLOCK_429" else 403
            eval_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            # Record blocked attempt in api_logs for live SOC visibility
            db.insert_api_log(
                {
                    "method": request.method,
                    "path": path,
                    "status_code": status_code,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "actor_id": actor_id,
                    "api_key_id": api_key_id,
                    "request_body": request_body,
                    "is_clean_baseline": False,
                }
            )

            return JSONResponse(
                status_code=status_code,
                content={
                    "blocked": True,
                    "enforced_by": "FinSec AI Virtual Patching Middleware",
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "condition_type": rule_spec.get("condition_type"),
                    "reason": rule_spec.get("reason", "Blocked by FinSec AI Policy"),
                    "eval_latency_ms": eval_ms,
                },
            )

        # If a CONCURRENCY_LOCK rule covers this path and allowed the request, hold per-key lock during handler execution
        if (
            rule_spec.get("condition_type") == "CONCURRENCY_LOCK"
            and path.startswith(str(rule_spec.get("target_path_prefix") or ""))
        ):
            params = rule_spec.get("params") or {}
            lock_key_field = str(params.get("lock_key") or "actor_id")
            key_val = (
                request_body.get("wallet_id")
                if lock_key_field == "wallet_id"
                else (actor_id or request_body.get("wallet_id") or ip_address)
            )
            if key_val:
                held_lock = get_actor_lock(f"{rule_spec.get('target_path_prefix')}:{key_val}")

    if held_lock is not None:
        async with held_lock:
            return await call_next(request)

    return await call_next(request)


# Mount Routers
app.include_router(sandbox_router)
app.include_router(api_v1_router)


@app.get("/", tags=["Health"])
async def root() -> dict[str, Any]:
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "db_mode": db.mode,
        "docs_url": "/docs",
        "demo_api_key_header": {"X-API-Key": settings.finsec_api_key},
    }


@app.get("/health", tags=["Health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "db_mode": db.mode}
