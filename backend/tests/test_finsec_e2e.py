"""End-to-end tests for FinSec Agent:
- Seed 5 wallets + 300 clean baseline rows
- All 4 fintech attacks (Webhook Replay, BOLA/IDOR, Leaked Internal Key, Race Condition)
- Scenario 5: Indirect Prompt Injection detection & immunity
- AI Agent investigation + Dry-Run (0/300 false positives on clean baseline)
- Live Middleware enforcement (403/429 on re-attack) while Normal Traffic stays 200 OK
- 1-click Rollback & Reset Sandbox preserving 300 clean baseline rows
"""

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure test runs on an isolated SQLite DB
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SQLITE_DB_PATH"] = str(Path(__file__).resolve().parent / "test_finsec.db")
os.environ["FINSEC_API_KEY"] = "finsec-demo-key-2026"

from app.main import app  # noqa: E402

HEADERS = {"X-API-Key": "finsec-demo-key-2026"}


@pytest.fixture(scope="module")
def client():
    db_file = Path(os.environ["SQLITE_DB_PATH"])
    if db_file.exists():
        db_file.unlink()
    with TestClient(app) as c:
        yield c
    if db_file.exists():
        db_file.unlink()


def test_01_seed_and_auth_guard(client: TestClient):
    # Missing API key -> 401
    r_unauth = client.get("/v1/sandbox/state")
    assert r_unauth.status_code == 401

    r = client.get("/v1/sandbox/state", headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["clean_baseline_count"] == 300
    assert len(data["wallets"]) == 5
    assert all(w["balance"] == 10_000_000 for w in data["wallets"])


def test_02_webhook_replay_with_prompt_injection_and_virtual_patch(client: TestClient):
    # Reset first
    client.post("/v1/sandbox/reset", headers=HEADERS)

    # 1. Trigger Webhook Replay WITH Indirect Prompt Injection
    sim = client.post(
        "/v1/sandbox/simulate/prompt_injection",
        headers=HEADERS,
        json={"with_prompt_injection": True},
    )
    assert sim.status_code == 200
    sim_data = sim.json()
    assert sim_data["succeeded_200"] == 5
    w1 = next(w for w in sim_data["wallets"] if w["id"] == "W_1001")
    # 10,000,000 + 5 * 5,000,000 = 35,000,000
    assert w1["balance"] == 35_000_000

    # 2. Run AI SOC Investigation
    inv = client.post("/v1/incidents/investigate", headers=HEADERS, json={})
    assert inv.status_code == 200
    report = inv.json()
    assert report["severity"] == "CRITICAL"
    assert report["prompt_injection_detected"] is True
    assert len(report["prompt_injection_evidence"]) >= 1
    assert len(report["reasoning_trace"]) >= 3
    assert report["proposed_rule"]["rule_spec"]["condition_type"] == "DEDUP_BODY_FIELD"
    assert report["dry_run_report"]["total_clean"] == 300
    assert report["dry_run_report"]["blocked_clean"] == 0
    assert report["dry_run_report"]["attack_blocked"] is True

    # 3. Enforce Virtual Patch
    rule_id = report["proposed_rule"]["id"]
    enf = client.post(f"/v1/policies/{rule_id}/enforce", headers=HEADERS)
    assert enf.status_code == 200
    assert enf.json()["rule"]["status"] == "ACTIVE"

    # 4. Re-attack -> MUST be blocked 403 by live middleware!
    sim2 = client.post("/v1/sandbox/simulate/webhook_replay", headers=HEADERS, json={})
    assert sim2.status_code == 200
    assert sim2.json()["blocked_count"] == 5
    assert sim2.json()["succeeded_200"] == 0
    w1_after = next(w for w in sim2.json()["wallets"] if w["id"] == "W_1001")
    assert w1_after["balance"] == 35_000_000  # Unchanged!

    # 5. Normal customer traffic -> MUST remain 200 OK!
    norm = client.post("/v1/sandbox/simulate/normal_traffic", headers=HEADERS, json={})
    assert norm.status_code == 200
    assert norm.json()["succeeded_200"] == 3
    assert norm.json()["blocked_count"] == 0

    # 6. Rollback -> rule becomes ROLLED_BACK
    rb = client.post(f"/v1/policies/{rule_id}/rollback", headers=HEADERS)
    assert rb.status_code == 200
    assert rb.json()["rule"]["status"] == "ROLLED_BACK"


def test_03_bola_idor_full_lifecycle(client: TestClient):
    client.post("/v1/sandbox/reset", headers=HEADERS)

    sim = client.post("/v1/sandbox/simulate/bola_idor", headers=HEADERS, json={})
    assert sim.status_code == 200
    assert sim.json()["succeeded_200"] == 4

    inv = client.post("/v1/incidents/investigate", headers=HEADERS, json={})
    report = inv.json()
    assert report["proposed_rule"]["rule_spec"]["condition_type"] == "ENFORCE_OWNER_MATCH"
    assert report["dry_run_report"]["total_clean"] == 300
    assert report["dry_run_report"]["blocked_clean"] == 0
    assert report["dry_run_report"]["attack_blocked_rate"] == 100.0

    rule_id = report["proposed_rule"]["id"]
    client.post(f"/v1/policies/{rule_id}/enforce", headers=HEADERS)

    # Re-attack -> all 4 blocked
    sim2 = client.post("/v1/sandbox/simulate/bola_idor", headers=HEADERS, json={})
    assert sim2.json()["blocked_count"] == 4

    # Normal traffic -> all 3 succeed 200 OK
    norm = client.post("/v1/sandbox/simulate/normal_traffic", headers=HEADERS, json={})
    assert norm.json()["succeeded_200"] == 3


def test_04_leaked_internal_key_full_lifecycle(client: TestClient):
    client.post("/v1/sandbox/reset", headers=HEADERS)

    sim = client.post("/v1/sandbox/simulate/leaked_key", headers=HEADERS, json={})
    assert sim.status_code == 200
    assert sim.json()["succeeded_200"] == 3

    inv = client.post("/v1/incidents/investigate", headers=HEADERS, json={})
    report = inv.json()
    assert report["proposed_rule"]["rule_spec"]["condition_type"] == "IP_WHITELIST_FOR_KEY"
    assert report["dry_run_report"]["total_clean"] == 300
    assert report["dry_run_report"]["blocked_clean"] == 0
    assert report["dry_run_report"]["attack_blocked_rate"] == 100.0

    rule_id = report["proposed_rule"]["id"]
    client.post(f"/v1/policies/{rule_id}/enforce", headers=HEADERS)

    sim2 = client.post("/v1/sandbox/simulate/leaked_key", headers=HEADERS, json={})
    assert sim2.json()["blocked_count"] == 3

    norm = client.post("/v1/sandbox/simulate/normal_traffic", headers=HEADERS, json={})
    assert norm.json()["succeeded_200"] == 3


def test_05_race_condition_and_reset_preserves_baseline(client: TestClient):
    client.post("/v1/sandbox/reset", headers=HEADERS)

    sim = client.post("/v1/sandbox/simulate/race_condition", headers=HEADERS, json={})
    assert sim.status_code == 200
    assert sim.json()["succeeded_200"] == 5
    w1 = next(w for w in sim.json()["wallets"] if w["id"] == "W_1001")
    # 10,000,000 - 5 * 4,000,000 = -10,000,000 (double-spend!)
    assert w1["balance"] == -10_000_000

    inv = client.post("/v1/incidents/investigate", headers=HEADERS, json={})
    report = inv.json()
    assert report["proposed_rule"]["rule_spec"]["condition_type"] == "CONCURRENCY_LOCK"
    assert report["dry_run_report"]["total_clean"] == 300
    assert report["dry_run_report"]["blocked_clean"] == 0
    assert report["dry_run_report"]["attack_blocked"] is True

    rule_id = report["proposed_rule"]["id"]
    client.post(f"/v1/policies/{rule_id}/enforce", headers=HEADERS)

    sim2 = client.post("/v1/sandbox/simulate/race_condition", headers=HEADERS, json={})
    assert sim2.json()["blocked_count"] == 5

    # Reset sandbox -> restores wallets and preserves all 300 clean baseline rows
    reset = client.post("/v1/sandbox/reset", headers=HEADERS)
    assert reset.status_code == 200
    assert reset.json()["clean_baseline_preserved"] == 300
    state = client.get("/v1/sandbox/state", headers=HEADERS).json()
    assert all(w["balance"] == 10_000_000 for w in state["wallets"])
    assert state["active_rules_count"] == 0
    assert state["clean_baseline_count"] == 300
