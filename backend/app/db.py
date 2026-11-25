"""Database adapter supporting Supabase (PostgreSQL) with automatic local SQLite fallback.

When SUPABASE_URL and SUPABASE_KEY are configured in environment variables, all reads
and writes execute directly against the 5 PostgreSQL tables on Supabase.
When not configured (e.g., local demo or CI tests), it seamlessly runs the exact same
5-table schema against a local SQLite database so every feature works end-to-end.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.config import get_settings
from app.seed import DEFAULT_BASELINE_COUNT, INITIAL_WALLETS, generate_clean_baseline_logs

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS wallets (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 10000000
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  wallet_id TEXT REFERENCES wallets(id) ON DELETE CASCADE,
  tx_ref TEXT NOT NULL,
  amount INTEGER NOT NULL,
  entry_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_wallet_id ON ledger_entries(wallet_id);
CREATE INDEX IF NOT EXISTS idx_ledger_tx_ref ON ledger_entries(tx_ref);

CREATE TABLE IF NOT EXISTS api_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  ip_address TEXT NOT NULL,
  user_agent TEXT,
  actor_id TEXT,
  api_key_id TEXT,
  request_body TEXT DEFAULT '{}',
  is_clean_baseline INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_logs_baseline ON api_logs(is_clean_baseline);
CREATE INDEX IF NOT EXISTS idx_api_logs_created_at ON api_logs(created_at);

CREATE TABLE IF NOT EXISTS policy_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'DRAFT',
  rule_spec TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  owasp_tag TEXT,
  reasoning_trace TEXT NOT NULL,
  attack_timeline TEXT NOT NULL,
  proposed_rule TEXT,
  dry_run_report TEXT,
  hotfix_diff TEXT,
  status TEXT DEFAULT 'OPEN',
  created_at TEXT NOT NULL
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json_field(val: Any, default: Any) -> Any:
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return default


class DatabaseClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._lock = threading.RLock()
        self._supabase = None
        self._mode = "sqlite"

        if self.settings.use_supabase:
            try:
                from supabase import create_client

                client = create_client(
                    self.settings.supabase_url, self.settings.supabase_key
                )
                # Verify connectivity and that the 5 tables exist in Supabase
                client.table("wallets").select("id").limit(1).execute()
                self._supabase = client
                self._mode = "supabase"
                print("[FinSec DB] Connected to Supabase PostgreSQL successfully.")
            except Exception as exc:
                print(
                    "[FinSec DB] Supabase not ready (run backend/sql/schema.sql in Supabase SQL Editor). "
                    f"Falling back to local SQLite temporarily: {exc}"
                )
                self._supabase = None
                self._mode = "sqlite"

        if self._mode == "sqlite":
            self._ensure_sqlite_schema()

    @property
    def mode(self) -> str:
        return self._mode

    @contextlib.contextmanager
    def _sqlite_conn(self):
        conn = sqlite3.connect(self.settings.sqlite_db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _ensure_sqlite_schema(self) -> None:
        Path(self.settings.sqlite_db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._sqlite_conn() as conn:
            conn.executescript(SQLITE_SCHEMA)
            conn.commit()

    # ------------------------------------------------------------------
    # Initialization & Seed
    # ------------------------------------------------------------------
    def init_and_seed_if_empty(self) -> dict[str, Any]:
        if self._mode == "sqlite":
            self._ensure_sqlite_schema()
        try:
            wallets = self.get_wallets()
            seeded_wallets = 0
            if not wallets:
                for w in INITIAL_WALLETS:
                    self._upsert_wallet(w)
                    seeded_wallets += 1

            clean_logs = self.get_clean_baseline_logs(limit=DEFAULT_BASELINE_COUNT + 100)
            seeded_logs = 0
            if len(clean_logs) < DEFAULT_BASELINE_COUNT:
                # Replace legacy 300-row baseline with full 2,000-row multi-endpoint baseline
                if clean_logs:
                    if self._mode == "supabase":
                        self._supabase.table("api_logs").delete().eq("is_clean_baseline", True).execute()
                    else:
                        with self._lock, self._sqlite_conn() as conn:
                            conn.execute("DELETE FROM api_logs WHERE is_clean_baseline = 1")
                            conn.commit()
                baseline_rows = generate_clean_baseline_logs(DEFAULT_BASELINE_COUNT)
                seeded_logs = self.insert_api_logs_bulk(baseline_rows)

            return {
                "db_mode": self._mode,
                "seeded_wallets": seeded_wallets,
                "seeded_clean_baseline_logs": seeded_logs,
            }
        except Exception as exc:
            if self._mode == "supabase":
                print(
                    "[FinSec DB] Supabase write/seed blocked (likely RLS with publishable key). "
                    "Use Supabase Secret Key (sb_secret_...) or run DISABLE ROW LEVEL SECURITY in SQL Editor. "
                    f"Falling back to SQLite temporarily: {exc}"
                )
                self._supabase = None
                self._mode = "sqlite"
                return self.init_and_seed_if_empty()
            raise

    def _upsert_wallet(self, wallet: dict[str, Any]) -> None:
        if self._mode == "supabase":
            self._supabase.table("wallets").upsert(wallet).execute()
            return
        with self._lock, self._sqlite_conn() as conn:
            conn.execute(
                """
                INSERT INTO wallets (id, owner_id, balance)
                VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id, balance=excluded.balance
                """,
                (wallet["id"], wallet["owner_id"], int(wallet["balance"])),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Wallets
    # ------------------------------------------------------------------
    def get_wallets(self) -> list[dict[str, Any]]:
        if self._mode == "supabase":
            res = self._supabase.table("wallets").select("*").order("id").execute()
            return list(res.data or [])
        with self._lock, self._sqlite_conn() as conn:
            rows = conn.execute("SELECT id, owner_id, balance FROM wallets ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def get_wallet(self, wallet_id: str) -> Optional[dict[str, Any]]:
        if self._mode == "supabase":
            res = self._supabase.table("wallets").select("*").eq("id", wallet_id).limit(1).execute()
            return res.data[0] if res.data else None
        with self._lock, self._sqlite_conn() as conn:
            row = conn.execute(
                "SELECT id, owner_id, balance FROM wallets WHERE id = ?", (wallet_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_wallet_balance(self, wallet_id: str, new_balance: int) -> Optional[dict[str, Any]]:
        if self._mode == "supabase":
            res = (
                self._supabase.table("wallets")
                .update({"balance": int(new_balance)})
                .eq("id", wallet_id)
                .execute()
            )
            return res.data[0] if res.data else None
        with self._lock, self._sqlite_conn() as conn:
            conn.execute(
                "UPDATE wallets SET balance = ? WHERE id = ?",
                (int(new_balance), wallet_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id, owner_id, balance FROM wallets WHERE id = ?", (wallet_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # Ledger Entries
    # ------------------------------------------------------------------
    def add_ledger_entry(
        self, wallet_id: str, tx_ref: str, amount: int, entry_type: str
    ) -> dict[str, Any]:
        created_at = _now_iso()
        if self._mode == "supabase":
            res = (
                self._supabase.table("ledger_entries")
                .insert(
                    {
                        "wallet_id": wallet_id,
                        "tx_ref": tx_ref,
                        "amount": int(amount),
                        "entry_type": entry_type,
                        "created_at": created_at,
                    }
                )
                .execute()
            )
            return res.data[0]
        with self._lock, self._sqlite_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO ledger_entries (wallet_id, tx_ref, amount, entry_type, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (wallet_id, tx_ref, int(amount), entry_type, created_at),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "wallet_id": wallet_id,
                "tx_ref": tx_ref,
                "amount": int(amount),
                "entry_type": entry_type,
                "created_at": created_at,
            }

    def get_ledger_entries(
        self, wallet_id: Optional[str] = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        if self._mode == "supabase":
            q = self._supabase.table("ledger_entries").select("*")
            if wallet_id:
                q = q.eq("wallet_id", wallet_id)
            res = q.order("id", desc=True).limit(limit).execute()
            return list(res.data or [])
        with self._lock, self._sqlite_conn() as conn:
            if wallet_id:
                rows = conn.execute(
                    """
                    SELECT id, wallet_id, tx_ref, amount, entry_type, created_at
                    FROM ledger_entries WHERE wallet_id = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (wallet_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, wallet_id, tx_ref, amount, entry_type, created_at
                    FROM ledger_entries ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def tx_ref_exists(self, tx_ref: str) -> bool:
        if not tx_ref:
            return False
        if self._mode == "supabase":
            res = (
                self._supabase.table("ledger_entries")
                .select("id")
                .eq("tx_ref", tx_ref)
                .limit(1)
                .execute()
            )
            return bool(res.data)
        with self._lock, self._sqlite_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM ledger_entries WHERE tx_ref = ? LIMIT 1", (tx_ref,)
            ).fetchone()
            return row is not None

    # ------------------------------------------------------------------
    # API Logs
    # ------------------------------------------------------------------
    def _normalize_log_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "method": row["method"],
            "path": row["path"],
            "status_code": int(row["status_code"]),
            "ip_address": row["ip_address"],
            "user_agent": row.get("user_agent"),
            "actor_id": row.get("actor_id"),
            "api_key_id": row.get("api_key_id"),
            "request_body": _parse_json_field(row.get("request_body"), {}),
            "is_clean_baseline": bool(row.get("is_clean_baseline", False)),
            "created_at": row.get("created_at"),
        }

    def insert_api_log(self, log: dict[str, Any]) -> dict[str, Any]:
        created_at = log.get("created_at") or _now_iso()
        body = log.get("request_body") or {}
        if self._mode == "supabase":
            payload = {
                "method": log["method"],
                "path": log["path"],
                "status_code": int(log["status_code"]),
                "ip_address": log["ip_address"],
                "user_agent": log.get("user_agent"),
                "actor_id": log.get("actor_id"),
                "api_key_id": log.get("api_key_id"),
                "request_body": body,
                "is_clean_baseline": bool(log.get("is_clean_baseline", False)),
                "created_at": created_at,
            }
            res = self._supabase.table("api_logs").insert(payload).execute()
            return self._normalize_log_row(res.data[0])

        with self._lock, self._sqlite_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO api_logs (
                    method, path, status_code, ip_address, user_agent,
                    actor_id, api_key_id, request_body, is_clean_baseline, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log["method"],
                    log["path"],
                    int(log["status_code"]),
                    log["ip_address"],
                    log.get("user_agent"),
                    log.get("actor_id"),
                    log.get("api_key_id"),
                    json.dumps(body, ensure_ascii=False),
                    1 if log.get("is_clean_baseline", False) else 0,
                    created_at,
                ),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "method": log["method"],
                "path": log["path"],
                "status_code": int(log["status_code"]),
                "ip_address": log["ip_address"],
                "user_agent": log.get("user_agent"),
                "actor_id": log.get("actor_id"),
                "api_key_id": log.get("api_key_id"),
                "request_body": body,
                "is_clean_baseline": bool(log.get("is_clean_baseline", False)),
                "created_at": created_at,
            }

    def insert_api_logs_bulk(self, logs: list[dict[str, Any]]) -> int:
        if not logs:
            return 0
        if self._mode == "supabase":
            chunk_size = 100
            inserted = 0
            for i in range(0, len(logs), chunk_size):
                chunk = []
                for log in logs[i : i + chunk_size]:
                    chunk.append(
                        {
                            "method": log["method"],
                            "path": log["path"],
                            "status_code": int(log["status_code"]),
                            "ip_address": log["ip_address"],
                            "user_agent": log.get("user_agent"),
                            "actor_id": log.get("actor_id"),
                            "api_key_id": log.get("api_key_id"),
                            "request_body": log.get("request_body") or {},
                            "is_clean_baseline": bool(log.get("is_clean_baseline", False)),
                            "created_at": log.get("created_at") or _now_iso(),
                        }
                    )
                self._supabase.table("api_logs").insert(chunk).execute()
                inserted += len(chunk)
            return inserted

        with self._lock, self._sqlite_conn() as conn:
            conn.executemany(
                """
                INSERT INTO api_logs (
                    method, path, status_code, ip_address, user_agent,
                    actor_id, api_key_id, request_body, is_clean_baseline, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        log["method"],
                        log["path"],
                        int(log["status_code"]),
                        log["ip_address"],
                        log.get("user_agent"),
                        log.get("actor_id"),
                        log.get("api_key_id"),
                        json.dumps(log.get("request_body") or {}, ensure_ascii=False),
                        1 if log.get("is_clean_baseline", False) else 0,
                        log.get("created_at") or _now_iso(),
                    )
                    for log in logs
                ],
            )
            conn.commit()
            return len(logs)

    def query_api_logs(
        self,
        path_prefix: Optional[str] = None,
        ip: Optional[str] = None,
        actor_id: Optional[str] = None,
        api_key_id: Optional[str] = None,
        is_clean_baseline: Optional[bool] = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if self._mode == "supabase":
            q = self._supabase.table("api_logs").select("*")
            if path_prefix:
                q = q.like("path", f"{path_prefix}%")
            if ip:
                q = q.eq("ip_address", ip)
            if actor_id:
                q = q.eq("actor_id", actor_id)
            if api_key_id:
                q = q.eq("api_key_id", api_key_id)
            if is_clean_baseline is not None:
                q = q.eq("is_clean_baseline", is_clean_baseline)
            res = q.order("id", desc=True).limit(limit).execute()
            return [self._normalize_log_row(r) for r in (res.data or [])]

        clauses: list[str] = []
        params: list[Any] = []
        if path_prefix:
            clauses.append("path LIKE ?")
            params.append(f"{path_prefix}%")
        if ip:
            clauses.append("ip_address = ?")
            params.append(ip)
        if actor_id:
            clauses.append("actor_id = ?")
            params.append(actor_id)
        if api_key_id:
            clauses.append("api_key_id = ?")
            params.append(api_key_id)
        if is_clean_baseline is not None:
            clauses.append("is_clean_baseline = ?")
            params.append(1 if is_clean_baseline else 0)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM api_logs {where_sql} ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._sqlite_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._normalize_log_row(dict(r)) for r in rows]

    def get_clean_baseline_logs(self, limit: int = 2500) -> list[dict[str, Any]]:
        if self._mode == "supabase" and limit > 1000:
            all_rows: list[dict[str, Any]] = []
            page_size = 1000
            offset = 0
            while len(all_rows) < limit:
                end = min(offset + page_size - 1, limit - 1)
                res = (
                    self._supabase.table("api_logs")
                    .select("*")
                    .eq("is_clean_baseline", True)
                    .order("created_at", desc=True)
                    .range(offset, end)
                    .execute()
                )
                batch = [self._normalize_log_row(r) for r in (res.data or [])]
                all_rows.extend(batch)
                if len(batch) < page_size:
                    break
                offset += page_size
            return all_rows
        return self.query_api_logs(is_clean_baseline=True, limit=limit)

    def get_recent_non_baseline_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.query_api_logs(is_clean_baseline=False, limit=limit)

    # ------------------------------------------------------------------
    # Policy Rules
    # ------------------------------------------------------------------
    def _normalize_rule(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "status": row["status"],
            "rule_spec": _parse_json_field(row.get("rule_spec"), {}),
            "created_at": row.get("created_at"),
        }

    def upsert_policy_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        created_at = rule.get("created_at") or _now_iso()
        if self._mode == "supabase":
            payload = {
                "id": rule["id"],
                "name": rule["name"],
                "status": rule.get("status", "DRAFT"),
                "rule_spec": rule["rule_spec"],
                "created_at": created_at,
            }
            res = self._supabase.table("policy_rules").upsert(payload).execute()
            return self._normalize_rule(res.data[0])

        with self._lock, self._sqlite_conn() as conn:
            conn.execute(
                """
                INSERT INTO policy_rules (id, name, status, rule_spec, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    status=excluded.status,
                    rule_spec=excluded.rule_spec
                """,
                (
                    rule["id"],
                    rule["name"],
                    rule.get("status", "DRAFT"),
                    json.dumps(rule["rule_spec"], ensure_ascii=False),
                    created_at,
                ),
            )
            conn.commit()
            return {
                "id": rule["id"],
                "name": rule["name"],
                "status": rule.get("status", "DRAFT"),
                "rule_spec": rule["rule_spec"],
                "created_at": created_at,
            }

    def get_policy_rule(self, rule_id: str) -> Optional[dict[str, Any]]:
        if self._mode == "supabase":
            res = self._supabase.table("policy_rules").select("*").eq("id", rule_id).limit(1).execute()
            return self._normalize_rule(res.data[0]) if res.data else None
        with self._lock, self._sqlite_conn() as conn:
            row = conn.execute("SELECT * FROM policy_rules WHERE id = ?", (rule_id,)).fetchone()
            return self._normalize_rule(dict(row)) if row else None

    def list_policy_rules(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        if self._mode == "supabase":
            q = self._supabase.table("policy_rules").select("*")
            if status:
                q = q.eq("status", status)
            res = q.order("created_at", desc=True).execute()
            return [self._normalize_rule(r) for r in (res.data or [])]
        with self._lock, self._sqlite_conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM policy_rules WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM policy_rules ORDER BY created_at DESC"
                ).fetchall()
            return [self._normalize_rule(dict(r)) for r in rows]

    def update_policy_rule_status(self, rule_id: str, status: str) -> Optional[dict[str, Any]]:
        if self._mode == "supabase":
            res = (
                self._supabase.table("policy_rules")
                .update({"status": status})
                .eq("id", rule_id)
                .execute()
            )
            return self._normalize_rule(res.data[0]) if res.data else None
        with self._lock, self._sqlite_conn() as conn:
            conn.execute("UPDATE policy_rules SET status = ? WHERE id = ?", (status, rule_id))
            conn.commit()
            row = conn.execute("SELECT * FROM policy_rules WHERE id = ?", (rule_id,)).fetchone()
            return self._normalize_rule(dict(row)) if row else None

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------
    def _normalize_incident(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "title": row["title"],
            "severity": row["severity"],
            "owasp_tag": row.get("owasp_tag"),
            "reasoning_trace": _parse_json_field(row.get("reasoning_trace"), []),
            "attack_timeline": _parse_json_field(row.get("attack_timeline"), []),
            "proposed_rule": _parse_json_field(row.get("proposed_rule"), None),
            "dry_run_report": _parse_json_field(row.get("dry_run_report"), None),
            "hotfix_diff": row.get("hotfix_diff"),
            "status": row.get("status", "OPEN"),
            "created_at": row.get("created_at"),
        }

    def save_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        created_at = incident.get("created_at") or _now_iso()
        if self._mode == "supabase":
            payload = {
                "id": incident["id"],
                "title": incident["title"],
                "severity": incident["severity"],
                "owasp_tag": incident.get("owasp_tag"),
                "reasoning_trace": incident.get("reasoning_trace", []),
                "attack_timeline": incident.get("attack_timeline", []),
                "proposed_rule": incident.get("proposed_rule"),
                "dry_run_report": incident.get("dry_run_report"),
                "hotfix_diff": incident.get("hotfix_diff"),
                "status": incident.get("status", "OPEN"),
                "created_at": created_at,
            }
            res = self._supabase.table("incidents").upsert(payload).execute()
            return self._normalize_incident(res.data[0])

        with self._lock, self._sqlite_conn() as conn:
            conn.execute(
                """
                INSERT INTO incidents (
                    id, title, severity, owasp_tag, reasoning_trace,
                    attack_timeline, proposed_rule, dry_run_report,
                    hotfix_diff, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    severity=excluded.severity,
                    owasp_tag=excluded.owasp_tag,
                    reasoning_trace=excluded.reasoning_trace,
                    attack_timeline=excluded.attack_timeline,
                    proposed_rule=excluded.proposed_rule,
                    dry_run_report=excluded.dry_run_report,
                    hotfix_diff=excluded.hotfix_diff,
                    status=excluded.status
                """,
                (
                    incident["id"],
                    incident["title"],
                    incident["severity"],
                    incident.get("owasp_tag"),
                    json.dumps(incident.get("reasoning_trace", []), ensure_ascii=False),
                    json.dumps(incident.get("attack_timeline", []), ensure_ascii=False),
                    json.dumps(incident.get("proposed_rule"), ensure_ascii=False)
                    if incident.get("proposed_rule") is not None
                    else None,
                    json.dumps(incident.get("dry_run_report"), ensure_ascii=False)
                    if incident.get("dry_run_report") is not None
                    else None,
                    incident.get("hotfix_diff"),
                    incident.get("status", "OPEN"),
                    created_at,
                ),
            )
            conn.commit()
            return self.get_incident(incident["id"])  # type: ignore[return-value]

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        if self._mode == "supabase":
            res = self._supabase.table("incidents").select("*").eq("id", incident_id).limit(1).execute()
            return self._normalize_incident(res.data[0]) if res.data else None
        with self._lock, self._sqlite_conn() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            return self._normalize_incident(dict(row)) if row else None

    def list_incidents(self, limit: int = 20) -> list[dict[str, Any]]:
        if self._mode == "supabase":
            res = self._supabase.table("incidents").select("*").order("created_at", desc=True).limit(limit).execute()
            return [self._normalize_incident(r) for r in (res.data or [])]
        with self._lock, self._sqlite_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._normalize_incident(dict(r)) for r in rows]

    def update_incident_status(self, incident_id: str, status: str) -> Optional[dict[str, Any]]:
        if self._mode == "supabase":
            res = (
                self._supabase.table("incidents")
                .update({"status": status})
                .eq("id", incident_id)
                .execute()
            )
            return self._normalize_incident(res.data[0]) if res.data else None
        with self._lock, self._sqlite_conn() as conn:
            conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
            conn.commit()
            return self.get_incident(incident_id)

    def mark_incidents_by_rule_status(self, rule_id: str, incident_status: str) -> None:
        incidents = self.list_incidents(limit=50)
        for inc in incidents:
            prop = inc.get("proposed_rule") or {}
            if isinstance(prop, dict) and prop.get("id") == rule_id:
                self.update_incident_status(inc["id"], incident_status)

    # ------------------------------------------------------------------
    # Sandbox Reset (preserves all 300 is_clean_baseline=TRUE rows!)
    # ------------------------------------------------------------------
    def reset_sandbox(self) -> dict[str, Any]:
        if self._mode == "supabase":
            # Delete non-baseline logs, ledger entries, rules, incidents
            self._supabase.table("api_logs").delete().eq("is_clean_baseline", False).execute()
            self._supabase.table("ledger_entries").delete().neq("id", -1).execute()
            self._supabase.table("policy_rules").delete().neq("id", "").execute()
            self._supabase.table("incidents").delete().neq("id", "").execute()
            for w in INITIAL_WALLETS:
                self._upsert_wallet(w)
            clean_count = len(self.get_clean_baseline_logs(limit=DEFAULT_BASELINE_COUNT + 100))
            if clean_count < DEFAULT_BASELINE_COUNT:
                if clean_count > 0:
                    self._supabase.table("api_logs").delete().eq("is_clean_baseline", True).execute()
                clean_count = self.insert_api_logs_bulk(generate_clean_baseline_logs(DEFAULT_BASELINE_COUNT))
            return {
                "status": "reset_complete",
                "wallets_restored": len(INITIAL_WALLETS),
                "clean_baseline_preserved": clean_count,
                "active_rules_cleared": True,
            }

        with self._lock, self._sqlite_conn() as conn:
            conn.execute("DELETE FROM api_logs WHERE is_clean_baseline = 0")
            conn.execute("DELETE FROM ledger_entries")
            conn.execute("DELETE FROM policy_rules")
            conn.execute("DELETE FROM incidents")
            for w in INITIAL_WALLETS:
                conn.execute(
                    """
                    INSERT INTO wallets (id, owner_id, balance)
                    VALUES (?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id, balance=excluded.balance
                    """,
                    (w["id"], w["owner_id"], int(w["balance"])),
                )
            conn.commit()
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM api_logs WHERE is_clean_baseline = 1"
            ).fetchone()
            clean_count = int(row["cnt"]) if row else 0

        if clean_count < DEFAULT_BASELINE_COUNT:
            if clean_count > 0:
                with self._lock, self._sqlite_conn() as conn:
                    conn.execute("DELETE FROM api_logs WHERE is_clean_baseline = 1")
                    conn.commit()
            clean_count = self.insert_api_logs_bulk(generate_clean_baseline_logs(DEFAULT_BASELINE_COUNT))

        return {
            "status": "reset_complete",
            "wallets_restored": len(INITIAL_WALLETS),
            "clean_baseline_preserved": clean_count,
            "active_rules_cleared": True,
        }


db = DatabaseClient()
