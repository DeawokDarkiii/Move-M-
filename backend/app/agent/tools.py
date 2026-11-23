"""4 Real Database Investigation Tools for the FinSec AI SOC Agent.

Tools exposed via Function Calling:
1. query_api_logs(path_prefix, ip, actor_id, limit)
2. trace_wallet_ledger(wallet_id)
3. inspect_actor_baseline(actor_id, api_key_id)
4. dry_run_policy_rule(rule_spec)
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any, Optional

from app.agent.sanitizer import sanitize_logs_batch
from app.db import db
from app.policy.engine import dry_run_policy_rule as engine_dry_run_policy_rule


def query_api_logs(
    path_prefix: Optional[str] = None,
    ip: Optional[str] = None,
    actor_id: Optional[str] = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Query recent API logs from DB and pass every row through the 2-layer Prompt Injection sanitizer."""
    safe_limit = max(1, min(int(limit or 20), 50))
    # Prefer recent non-baseline logs (live/attack traffic) first
    logs = db.query_api_logs(
        path_prefix=path_prefix,
        ip=ip,
        actor_id=actor_id,
        is_clean_baseline=False,
        limit=safe_limit,
    )
    if not logs:
        logs = db.query_api_logs(
            path_prefix=path_prefix,
            ip=ip,
            actor_id=actor_id,
            limit=safe_limit,
        )

    sanitized_batch = sanitize_logs_batch(logs)

    path_counts = Counter(row.get("path") for row in logs)
    ip_counts = Counter(row.get("ip_address") for row in logs)

    return {
        "tool": "query_api_logs",
        "filters": {
            "path_prefix": path_prefix,
            "ip": ip,
            "actor_id": actor_id,
            "limit": safe_limit,
        },
        "total_returned": sanitized_batch["count"],
        "prompt_injection_detected": sanitized_batch["prompt_injection_detected"],
        "prompt_injection_count": sanitized_batch["prompt_injection_count"],
        "prompt_injection_evidence": sanitized_batch["prompt_injection_evidence"],
        "top_paths": dict(path_counts.most_common(5)),
        "top_ips": dict(ip_counts.most_common(5)),
        "logs": sanitized_batch["sanitized_logs"],
        "llm_safe_context": sanitized_batch["wrapped_llm_context"],
    }


def trace_wallet_ledger(wallet_id: str) -> dict[str, Any]:
    """Inspect a wallet's current balance and ledger_entries to detect duplicate tx_ref credits or negative/race balance drift."""
    wallet = db.get_wallet(wallet_id)
    if not wallet:
        return {
            "tool": "trace_wallet_ledger",
            "found": False,
            "wallet_id": wallet_id,
            "error": f"Wallet {wallet_id} not found",
        }

    entries = db.get_ledger_entries(wallet_id=wallet_id, limit=50)
    tx_ref_counts = Counter(e["tx_ref"] for e in entries if e.get("tx_ref"))
    duplicate_tx_refs = {ref: cnt for ref, cnt in tx_ref_counts.items() if cnt > 1}

    total_ledger_delta = sum(int(e["amount"]) for e in entries)
    initial_expected = 10_000_000
    balance = int(wallet["balance"])

    anomalies: list[str] = []
    if duplicate_tx_refs:
        anomalies.append(
            f"DUPLICATE_TX_REF_REPLAY: {duplicate_tx_refs} credited multiple times without idempotency!"
        )
    if balance < 0:
        anomalies.append(
            f"NEGATIVE_BALANCE_RACE_CONDITION: Balance dropped to {balance:,} VND (< 0) due to concurrent withdrawals!"
        )
    withdrawals = [e for e in entries if e.get("entry_type") == "WITHDRAW"]
    if len(withdrawals) >= 3:
        anomalies.append(
            f"BURST_WITHDRAWALS: {len(withdrawals)} rapid withdrawals detected totaling {sum(abs(int(w['amount'])) for w in withdrawals):,} VND."
        )

    return {
        "tool": "trace_wallet_ledger",
        "found": True,
        "wallet_id": wallet["id"],
        "owner_id": wallet["owner_id"],
        "current_balance": balance,
        "initial_seed_balance": initial_expected,
        "balance_delta_from_initial": balance - initial_expected,
        "ledger_entry_count": len(entries),
        "ledger_net_delta": total_ledger_delta,
        "duplicate_tx_refs": duplicate_tx_refs,
        "anomalies": anomalies,
        "recent_entries": entries[:15],
    }


def inspect_actor_baseline(
    actor_id: Optional[str] = None,
    api_key_id: Optional[str] = None,
) -> dict[str, Any]:
    """Compare recent live behavior of an actor_id or api_key_id against the historical is_clean_baseline=TRUE profile."""
    baseline_logs = db.query_api_logs(
        actor_id=actor_id if not api_key_id else None,
        api_key_id=api_key_id,
        is_clean_baseline=True,
        limit=300,
    )
    recent_logs = db.query_api_logs(
        actor_id=actor_id if not api_key_id else None,
        api_key_id=api_key_id,
        is_clean_baseline=False,
        limit=50,
    )

    baseline_ips = sorted({r["ip_address"] for r in baseline_logs if r.get("ip_address")})
    recent_ips = sorted({r["ip_address"] for r in recent_logs if r.get("ip_address")})
    baseline_paths = sorted({r["path"] for r in baseline_logs if r.get("path")})
    recent_paths = sorted({r["path"] for r in recent_logs if r.get("path")})

    # Detect internal CIDR baseline (e.g. 10.0.1.0/24)
    internal_net = ipaddress.ip_network("10.0.1.0/24")
    baseline_all_internal = bool(baseline_ips) and all(
        ipaddress.ip_address(ip) in internal_net for ip in baseline_ips
    )
    external_recent_ips = [
        ip for ip in recent_ips if ipaddress.ip_address(ip) not in internal_net
    ]

    unseen_ips = [ip for ip in recent_ips if ip not in baseline_ips]
    unseen_paths = [p for p in recent_paths if p not in baseline_paths]

    findings: list[str] = []
    if api_key_id and baseline_all_internal and external_recent_ips:
        findings.append(
            f"LEAKED_INTERNAL_KEY: '{api_key_id}' historically only called from 10.0.1.0/24, "
            f"but now called from external IP(s): {external_recent_ips}"
        )
    if actor_id and unseen_paths:
        wallet_paths = [p for p in unseen_paths if p.startswith("/sandbox/wallets/")]
        if wallet_paths:
            findings.append(
                f"BOLA_CROSS_WALLET_ACCESS: actor '{actor_id}' historically only accessed "
                f"{[p for p in baseline_paths if p.startswith('/sandbox/wallets/')]}, "
                f"but recently accessed other users' wallets: {wallet_paths}"
            )
    if unseen_ips and not (api_key_id and external_recent_ips):
        findings.append(f"NEW_SOURCE_IPS: {unseen_ips} never seen in clean baseline.")

    return {
        "tool": "inspect_actor_baseline",
        "actor_id": actor_id,
        "api_key_id": api_key_id,
        "baseline_log_count": len(baseline_logs),
        "recent_log_count": len(recent_logs),
        "baseline_ips_sample": baseline_ips[:10],
        "baseline_all_internal_10_0_1_0_24": baseline_all_internal,
        "recent_ips": recent_ips,
        "unseen_ips": unseen_ips,
        "baseline_paths": baseline_paths,
        "recent_paths": recent_paths,
        "unseen_paths": unseen_paths,
        "findings": findings,
    }


def dry_run_policy_rule(rule_spec: dict[str, Any]) -> dict[str, Any]:
    """Dry-run a declarative JSON Virtual Patch rule against all 300 clean baseline rows + live attack logs."""
    report = engine_dry_run_policy_rule(rule_spec)
    return {
        "tool": "dry_run_policy_rule",
        "rule_spec": rule_spec,
        **report,
    }


# Tool Registry & Declarations for Gemini Interactions API / OpenAI Function Calling
TOOL_EXECUTORS = {
    "query_api_logs": query_api_logs,
    "trace_wallet_ledger": trace_wallet_ledger,
    "inspect_actor_baseline": inspect_actor_baseline,
    "dry_run_policy_rule": dry_run_policy_rule,
}

GEMINI_INTERACTIONS_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "query_api_logs",
        "description": (
            "Query recent fintech HTTP/API logs from the database. All untrusted fields are "
            "automatically sanitized against Indirect Prompt Injection."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path_prefix": {
                    "type": "string",
                    "description": "Optional URL path prefix filter, e.g. /sandbox/webhook or /sandbox/wallets",
                },
                "ip": {
                    "type": "string",
                    "description": "Optional exact source IP address filter",
                },
                "actor_id": {
                    "type": "string",
                    "description": "Optional actor/user ID filter, e.g. usr_an",
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of recent logs to return (default 20, max 50)",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "trace_wallet_ledger",
        "description": (
            "Inspect a wallet's live balance and ledger_entries to verify financial impact, "
            "duplicate tx_ref/event_id deposits, or negative balance race conditions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "wallet_id": {
                    "type": "string",
                    "description": "Target wallet ID, e.g. W_1001",
                }
            },
            "required": ["wallet_id"],
        },
    },
    {
        "type": "function",
        "name": "inspect_actor_baseline",
        "description": (
            "Compare an actor_id or api_key_id's recent traffic against their 300-row historical "
            "is_clean_baseline=TRUE profile to spot leaked internal keys or BOLA cross-wallet access."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "actor_id": {
                    "type": "string",
                    "description": "Optional actor ID, e.g. usr_an",
                },
                "api_key_id": {
                    "type": "string",
                    "description": "Optional internal API key ID, e.g. internal_settlement_key_prod",
                },
            },
        },
    },
    {
        "type": "function",
        "name": "dry_run_policy_rule",
        "description": (
            "Simulate a declarative JSON virtual patching rule against all 300 historical clean "
            "baseline logs and current attack logs to measure attack_blocked_rate and "
            "blocked_clean (false positives). Always run this before finalizing the incident report! "
            "If blocked_clean > 0, refine the rule and dry-run again."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rule_spec": {
                    "type": "object",
                    "description": (
                        "Declarative JSON rule object with keys: target_path_prefix (str), "
                        "condition_type (one of DEDUP_BODY_FIELD, ENFORCE_OWNER_MATCH, "
                        "IP_WHITELIST_FOR_KEY, CONCURRENCY_LOCK, IP_BLOCKLIST), "
                        "params (dict), action (BLOCK_403 or BLOCK_429), reason (str)."
                    ),
                }
            },
            "required": ["rule_spec"],
        },
    },
]


def summarize_tool_result(tool_name: str, result: dict[str, Any]) -> str:
    """Create a concise human-readable observation summary for the SOC UI reasoning_trace."""
    if tool_name == "query_api_logs":
        pi_flag = (
            f" | PROMPT INJECTION DETECTED ({result.get('prompt_injection_count')} log(s))!"
            if result.get("prompt_injection_detected")
            else ""
        )
        return (
            f"Retrieved {result.get('total_returned', 0)} sanitized logs. "
            f"Top paths: {result.get('top_paths')}. Top IPs: {result.get('top_ips')}.{pi_flag}"
        )
    if tool_name == "trace_wallet_ledger":
        if not result.get("found"):
            return f"Wallet {result.get('wallet_id')} not found."
        anomalies = result.get("anomalies") or ["No ledger anomalies"]
        return (
            f"Wallet {result['wallet_id']} (owner={result['owner_id']}): "
            f"balance={result['current_balance']:,} VND (delta {result['balance_delta_from_initial']:+,} VND). "
            f"Findings: {'; '.join(anomalies)}"
        )
    if tool_name == "inspect_actor_baseline":
        findings = result.get("findings") or ["Behavior matches clean baseline"]
        return (
            f"Baseline ({result.get('baseline_log_count')} clean rows) vs recent ({result.get('recent_log_count')} rows). "
            f"Findings: {'; '.join(findings)}"
        )
    if tool_name == "dry_run_policy_rule":
        return (
            f"Dry-Run Result: Attack blocked {result.get('attack_blocked_rate', 0)}% "
            f"({result.get('blocked_attack_logs', 0)}/{result.get('total_attack_logs', 0)}) | "
            f"Clean baseline false positives: {result.get('blocked_clean', 0)}/{result.get('total_clean', 0)} "
            f"({'SAFE' if result.get('safe_to_enforce') else 'UNSAFE - REFINE RULE'})."
        )
    return str(result)[:220]
