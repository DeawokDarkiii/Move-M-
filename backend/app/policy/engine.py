"""Declarative Virtual Patching Policy Engine (Zero eval/exec).

Supports 5 declarative condition types mapped to fintech attack scenarios:
1. DEDUP_BODY_FIELD      -> Webhook Replay (blocks duplicate event_id / tx_ref)
2. ENFORCE_OWNER_MATCH   -> BOLA / IDOR (blocks wallet access when actor_id != owner_id)
3. IP_WHITELIST_FOR_KEY  -> Leaked Internal API Key (enforces CIDR whitelist)
4. CONCURRENCY_LOCK      -> Race Condition Withdraw (blocks concurrent/burst requests per actor/wallet)
5. IP_BLOCKLIST          -> Explicit IP/CIDR blocklist on a path prefix

Provides:
- `evaluate_rule(rule_spec, req_context, state=None, is_live=False) -> bool`
- `dry_run_policy_rule(rule_spec, attack_logs=None) -> dict`
- 2-second cached active rule lookup for <5ms Live Middleware enforcement
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from app.db import db

SUPPORTED_CONDITIONS = {
    "DEDUP_BODY_FIELD",
    "ENFORCE_OWNER_MATCH",
    "IP_WHITELIST_FOR_KEY",
    "CONCURRENCY_LOCK",
    "IP_BLOCKLIST",
}


class RuleSpec(BaseModel):
    target_path_prefix: str = Field(
        ..., description="URL path prefix to protect, e.g. /sandbox/webhook/payment-success"
    )
    condition_type: Literal[
        "DEDUP_BODY_FIELD",
        "ENFORCE_OWNER_MATCH",
        "IP_WHITELIST_FOR_KEY",
        "CONCURRENCY_LOCK",
        "IP_BLOCKLIST",
    ]
    params: dict[str, Any] = Field(default_factory=dict)
    action: Literal["BLOCK_403", "BLOCK_429"] = "BLOCK_403"
    reason: str = Field(
        default="Blocked by FinSec AI Policy",
        description="Human-readable block reason returned to caller",
    )


# ------------------------------------------------------------------
# Active Rule Cache (2-second TTL for <5ms middleware latency)
# ------------------------------------------------------------------
_CACHE_TTL_SECONDS = 2.0
_cached_active_rules: list[dict[str, Any]] = []
_cached_rules_ts: float = 0.0
_cached_wallet_owners: dict[str, str] = {}
_cached_owners_ts: float = 0.0

# Live concurrency state for CONCURRENCY_LOCK
_live_locks: dict[str, asyncio.Lock] = {}
_live_last_seen: dict[str, float] = {}


def invalidate_policy_cache() -> None:
    global _cached_rules_ts, _cached_owners_ts
    _cached_rules_ts = 0.0
    _cached_owners_ts = 0.0


def reset_concurrency_state() -> None:
    _live_locks.clear()
    _live_last_seen.clear()


def get_active_rules_cached() -> list[dict[str, Any]]:
    global _cached_active_rules, _cached_rules_ts
    now = time.monotonic()
    if now - _cached_rules_ts > _CACHE_TTL_SECONDS:
        _cached_active_rules = db.list_policy_rules(status="ACTIVE")
        _cached_rules_ts = now
    return _cached_active_rules


def get_wallet_owners_cached() -> dict[str, str]:
    global _cached_wallet_owners, _cached_owners_ts
    now = time.monotonic()
    if now - _cached_owners_ts > _CACHE_TTL_SECONDS or not _cached_wallet_owners:
        wallets = db.get_wallets()
        _cached_wallet_owners = {w["id"]: w["owner_id"] for w in wallets}
        _cached_owners_ts = now
    return _cached_wallet_owners


def get_actor_lock(key: str) -> asyncio.Lock:
    if key not in _live_locks:
        _live_locks[key] = asyncio.Lock()
    return _live_locks[key]


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _ip_in_cidrs(ip_str: str, cidrs: list[str]) -> bool:
    if not ip_str or not cidrs:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if ip_obj in net:
                return True
        except ValueError:
            if ip_str.strip() == cidr.strip():
                return True
    return False


def _parse_iso_timestamp(ts: Any) -> Optional[float]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            cleaned = ts.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned).timestamp()
        except ValueError:
            return None
    return None


def validate_rule_spec(rule_spec: dict[str, Any]) -> RuleSpec:
    """Strictly validate a rule spec via Pydantic (never eval/exec)."""
    return RuleSpec.model_validate(rule_spec)


# ------------------------------------------------------------------
# Core Unified Rule Evaluator (used by BOTH Live Middleware & Dry-Run)
# ------------------------------------------------------------------
def evaluate_rule(
    rule_spec: dict[str, Any],
    req_context: dict[str, Any],
    *,
    state: Optional[dict[str, Any]] = None,
    is_live: bool = False,
) -> bool:
    """Return True if the request MUST BE BLOCKED by rule_spec, else False.

    `req_context` keys:
      - method: str
      - path: str
      - ip_address: str
      - user_agent: Optional[str]
      - actor_id: Optional[str]
      - api_key_id: Optional[str]
      - request_body: dict
      - created_at: Optional[str | float]
    """
    try:
        spec = validate_rule_spec(rule_spec)
    except Exception:
        return False

    path = str(req_context.get("path") or "")
    if not path.startswith(spec.target_path_prefix):
        return False

    ip_address = str(req_context.get("ip_address") or "")
    actor_id = req_context.get("actor_id")
    api_key_id = req_context.get("api_key_id")
    body = req_context.get("request_body") or {}
    if not isinstance(body, dict):
        body = {}

    params = spec.params or {}
    block_ips = params.get("block_ips") or []
    if block_ips and _ip_in_cidrs(ip_address, block_ips):
        return True

    # 1. DEDUP_BODY_FIELD (Webhook Replay protection)
    if spec.condition_type == "DEDUP_BODY_FIELD":
        field_name = str(params.get("field") or "event_id")
        field_val = body.get(field_name)
        if not field_val:
            return False
        field_val_str = str(field_val)

        if is_live:
            return db.tx_ref_exists(field_val_str)

        # Dry-run stateful tracking across evaluated corpus
        if state is not None:
            seen_set: set[str] = state.setdefault("seen_dedup_values", set())
            if field_val_str in seen_set:
                return True
            seen_set.add(field_val_str)
            return False
        return db.tx_ref_exists(field_val_str)

    # 2. ENFORCE_OWNER_MATCH (BOLA / IDOR protection)
    if spec.condition_type == "ENFORCE_OWNER_MATCH":
        regex_pattern = str(params.get("path_param_regex") or r"/sandbox/wallets/([^/?]+)")
        match = re.search(regex_pattern, path)
        if not match:
            return False
        wallet_id = match.group(1)
        owners_map = (
            state.get("wallet_owners")
            if state is not None and "wallet_owners" in state
            else get_wallet_owners_cached()
        )
        expected_owner = owners_map.get(wallet_id)
        if expected_owner is None:
            return False
        if not actor_id or str(actor_id) != str(expected_owner):
            return True
        return False

    # 3. IP_WHITELIST_FOR_KEY (Leaked Internal API Key protection)
    if spec.condition_type == "IP_WHITELIST_FOR_KEY":
        target_key = params.get("api_key_id")
        allowed_cidrs = params.get("allowed_cidrs") or ["10.0.1.0/24"]
        if target_key and api_key_id and str(api_key_id) != str(target_key):
            # Still protect the path if it's an admin endpoint, or only match that key
            if not params.get("enforce_for_all_keys_on_path", True):
                return False
        if not _ip_in_cidrs(ip_address, allowed_cidrs):
            return True
        return False

    # 4. CONCURRENCY_LOCK (Race Condition Withdraw protection)
    if spec.condition_type == "CONCURRENCY_LOCK":
        lock_key_field = str(params.get("lock_key") or "actor_id")
        window_seconds = float(params.get("window_seconds", 2.0))

        if lock_key_field == "wallet_id":
            key_val = body.get("wallet_id") or actor_id or ip_address
        else:
            key_val = actor_id or body.get("wallet_id") or ip_address

        if not key_val:
            return False
        lock_key = f"{spec.target_path_prefix}:{key_val}"

        if is_live:
            now_mono = time.monotonic()
            lock = get_actor_lock(lock_key)
            if lock.locked():
                return True
            last_ts = _live_last_seen.get(lock_key)
            if last_ts is not None and (now_mono - last_ts) < window_seconds:
                return True
            _live_last_seen[lock_key] = now_mono
            return False

        # Dry-run evaluation over time-ordered log events
        if state is not None:
            last_seen_map: dict[str, float] = state.setdefault("concurrency_last_seen", {})
            ts = _parse_iso_timestamp(req_context.get("created_at"))
            if ts is None:
                return False
            prev_ts = last_seen_map.get(lock_key)
            if prev_ts is not None and abs(ts - prev_ts) < window_seconds:
                return True
            last_seen_map[lock_key] = ts
            return False
        return False

    # 5. IP_BLOCKLIST
    if spec.condition_type == "IP_BLOCKLIST":
        blocked_ips = params.get("blocked_ips") or []
        blocked_cidrs = params.get("blocked_cidrs") or []
        return _ip_in_cidrs(ip_address, [*blocked_ips, *blocked_cidrs])

    return False


# ------------------------------------------------------------------
# Dry-Run Blast Radius Simulation against Real DB Baseline (300 rows)
# ------------------------------------------------------------------
def dry_run_policy_rule(
    rule_spec: dict[str, Any],
    attack_logs: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Evaluate a proposed JSON policy rule against:
    1. ALL historical clean baseline logs in DB (is_clean_baseline = TRUE, 300 rows)
    2. Recent attack/non-baseline logs in DB (or explicitly passed attack_logs)

    Returns real DB-computed blast-radius & effectiveness metrics.
    """
    try:
        validated = validate_rule_spec(rule_spec)
        normalized_spec = validated.model_dump()
    except Exception as exc:
        return {
            "valid": False,
            "error": f"Invalid rule_spec schema: {exc}",
            "total_clean": 0,
            "blocked_clean": 0,
            "false_positive_rate": 100.0,
            "total_attack_logs": 0,
            "blocked_attack_logs": 0,
            "attack_blocked_rate": 0.0,
            "attack_blocked": False,
            "safe_to_enforce": False,
            "sample_false_positives": [],
        }

    wallet_owners = {w["id"]: w["owner_id"] for w in db.get_wallets()}

    # 1. Evaluate against ALL clean baseline logs (ordered chronologically ascending)
    clean_logs = db.get_clean_baseline_logs(limit=500)
    clean_logs_sorted = sorted(
        clean_logs, key=lambda r: str(r.get("created_at") or "")
    )
    clean_state: dict[str, Any] = {"wallet_owners": wallet_owners}

    blocked_clean_samples: list[dict[str, Any]] = []
    passed_clean_samples: list[dict[str, Any]] = []
    clean_endpoint_counts: dict[str, int] = {}
    blocked_clean_count = 0
    for log in clean_logs_sorted:
        p = str(log.get("path") or "")
        ep_group = (
            "/sandbox/wallets/{id}"
            if p.startswith("/sandbox/wallets/")
            else (p or "other")
        )
        clean_endpoint_counts[ep_group] = clean_endpoint_counts.get(ep_group, 0) + 1

        if evaluate_rule(normalized_spec, log, state=clean_state, is_live=False):
            blocked_clean_count += 1
            if len(blocked_clean_samples) < 5:
                blocked_clean_samples.append(
                    {
                        "id": log.get("id"),
                        "method": log.get("method"),
                        "path": log.get("path"),
                        "ip_address": log.get("ip_address"),
                        "actor_id": log.get("actor_id"),
                    }
                )
        elif len(passed_clean_samples) < 4 and (
            not passed_clean_samples
            or all(s["path"] != log.get("path") for s in passed_clean_samples)
        ):
            passed_clean_samples.append(
                {
                    "id": log.get("id"),
                    "method": log.get("method"),
                    "path": log.get("path"),
                    "ip_address": log.get("ip_address"),
                    "actor_id": log.get("actor_id") or log.get("api_key_id") or "gateway",
                }
            )

    total_clean = len(clean_logs_sorted)
    false_positive_rate = (
        round((blocked_clean_count / total_clean) * 100.0, 2) if total_clean else 0.0
    )

    # 2. Evaluate against recent attack logs targeting this path (or all non-baseline logs)
    if attack_logs is None:
        non_baseline = db.get_recent_non_baseline_logs(limit=50)
        # Focus on logs matching target_path_prefix (and exclude clean normal-traffic probes if possible)
        target_prefix = normalized_spec["target_path_prefix"]
        attack_candidates = [
            r for r in non_baseline if str(r.get("path") or "").startswith(target_prefix)
        ]
        # Exclude previously blocked 403/429 logs so we measure against the original attack requests
        unblocked_attacks = [
            r for r in attack_candidates if int(r.get("status_code") or 200) < 400
        ]
        attack_logs_eval = unblocked_attacks or attack_candidates or non_baseline
    else:
        attack_logs_eval = list(attack_logs)

    attack_logs_sorted = sorted(
        attack_logs_eval, key=lambda r: str(r.get("created_at") or "")
    )
    attack_state: dict[str, Any] = {"wallet_owners": wallet_owners}
    blocked_attack_count = 0
    for log in attack_logs_sorted:
        if evaluate_rule(normalized_spec, log, state=attack_state, is_live=False):
            blocked_attack_count += 1

    total_attack = len(attack_logs_sorted)
    attack_blocked_rate = (
        round((blocked_attack_count / total_attack) * 100.0, 2)
        if total_attack > 0
        else 0.0
    )

    # For dedup / concurrency rules without IP blocklist, the 1st request is baseline and repeats (N-1)/N are blocked.
    # If >= 75% of attack burst is blocked (or 100% of repeats), the attack vector is neutralized.
    attack_blocked = (
        blocked_attack_count > 0
        and (
            attack_blocked_rate >= 75.0
            or (
                normalized_spec["condition_type"] in {"DEDUP_BODY_FIELD", "CONCURRENCY_LOCK"}
                and total_attack >= 2
                and blocked_attack_count >= total_attack - 1
            )
        )
    )
    safe_to_enforce = blocked_clean_count == 0 and (attack_blocked or total_attack == 0)

    # Include latest high-volume scale simulation context if available
    scale_context: Optional[dict[str, Any]] = None
    try:
        from app.sandbox.scenario_engine import LAST_SCALE_CONTEXT

        if LAST_SCALE_CONTEXT.get("last_clean_transactions", 0) > 0:
            scale_context = {
                "scenario_id": LAST_SCALE_CONTEXT["last_scenario_id"],
                "clean_transactions_verified": LAST_SCALE_CONTEXT["last_clean_transactions"],
                "false_positives": 0 if blocked_clean_count == 0 else blocked_clean_count,
            }
    except Exception:
        scale_context = None

    return {
        "valid": True,
        "total_clean": total_clean,
        "blocked_clean": blocked_clean_count,
        "false_positive_rate": false_positive_rate,
        "total_attack_logs": total_attack,
        "blocked_attack_logs": blocked_attack_count,
        "attack_blocked_rate": attack_blocked_rate,
        "attack_blocked": attack_blocked,
        "safe_to_enforce": safe_to_enforce,
        "sample_false_positives": blocked_clean_samples,
        "sample_passed_clean": passed_clean_samples,
        "clean_breakdown_by_endpoint": clean_endpoint_counts,
        "scale_context": scale_context,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
