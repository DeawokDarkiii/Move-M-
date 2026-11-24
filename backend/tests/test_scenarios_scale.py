"""Tests for 900-Scenario Catalog, High-Volume A/B Simulation & AI Shield Toggle."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

os.environ["FINSEC_SKIP_DOTENV"] = "1"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["GEMINI_API_KEY"] = ""
os.environ.setdefault("SQLITE_DB_PATH", str(Path(__file__).resolve().parent / "test_finsec.db"))
os.environ["FINSEC_API_KEY"] = "finsec-demo-key-2026"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402

HEADERS = {"X-API-Key": "finsec-demo-key-2026"}


def test_900_scenario_catalog_and_high_volume_ab_comparison() -> None:
    with TestClient(app) as client:
        # 1. Verify catalog has 900 scenarios
        r_cat = client.get("/v1/scenarios/catalog?page=1&page_size=20", headers=HEADERS)
        assert r_cat.status_code == 200
        cat = r_cat.json()
        assert cat["total_catalog"] == 900
        assert len(cat["items"]) == 20

        # Filter by red_team_blitz + mega scale
        r_flt = client.get(
            "/v1/scenarios/catalog?category=red_team_blitz&scale_tier=mega",
            headers=HEADERS,
        )
        assert r_flt.status_code == 200
        assert r_flt.json()["total_filtered"] == 30  # 15 contexts * 2 red_team_blitz * 1 tier

        # 2. Ensure AI Shield OFF first -> run 50,000-tx 4-vector simultaneous attack
        r_off = client.post(
            "/v1/policies/ai-shield/toggle",
            headers=HEADERS,
            json={"enabled": False},
        )
        assert r_off.status_code == 200
        assert r_off.json()["active_rules_count"] == 0

        r_sim_off = client.post(
            "/v1/sandbox/simulate-scale",
            headers=HEADERS,
            json={
                "total_transactions": 50000,
                "vectors": ["webhook_replay", "bola_idor", "leaked_key", "race_condition"],
                "attack_ratio_pct": 4.0,
                "with_prompt_injection": True,
            },
        )
        assert r_sim_off.status_code == 200
        sim_off = r_sim_off.json()
        assert sim_off["total_transactions"] == 50000
        # Traditional 5-layer bank/fintech security already blocks ~64%-82% of attacks
        assert 60.0 <= sim_off["without_ai"]["block_rate_pct"] <= 85.0
        assert len(sim_off["without_ai"]["traditional_layers"]) == 5
        assert sim_off["without_ai"]["attacks_blocked"] > 0
        assert sim_off["without_ai"]["false_positives"] > 0
        assert sim_off["without_ai"]["financial_loss_vnd"] > 0
        # When AI Shield is OFF, live block rate equals traditional WAF baseline
        assert sim_off["with_ai_live"]["block_rate_pct"] == sim_off["without_ai"]["block_rate_pct"]
        assert sim_off["with_ai_live"]["ai_extra_blocked"] == 0
        assert sim_off["with_ai_full_shield"]["block_rate_pct"] == 100.0
        assert sim_off["with_ai_full_shield"]["ai_extra_blocked"] > 0
        assert len(sim_off["accounts_comparison"]) == 5
        assert len(sim_off["vector_breakdown"]) == 4
        # Verify realistic non-uniform per-account distribution & Fintech roles
        assert all(acc.get("role_label") for acc in sim_off["accounts_comparison"])
        leaked_counts = [acc["without_ai_records_leaked"] for acc in sim_off["accounts_comparison"]]
        assert len(set(leaked_counts)) > 1, f"Expected non-uniform leaked counts, got {leaked_counts}"

        # 3. Toggle AI Shield ON -> re-run 50,000-tx scenario -> 100% blocked, 0 loss, 0 false positives
        r_on = client.post(
            "/v1/policies/ai-shield/toggle",
            headers=HEADERS,
            json={"enabled": True},
        )
        assert r_on.status_code == 200
        assert r_on.json()["active_rules_count"] >= 4

        r_sim_on = client.post(
            "/v1/sandbox/simulate-scale",
            headers=HEADERS,
            json={
                "total_transactions": 50000,
                "vectors": ["webhook_replay", "bola_idor", "leaked_key", "race_condition"],
                "attack_ratio_pct": 4.0,
                "with_prompt_injection": True,
            },
        )
        assert r_sim_on.status_code == 200
        sim_on = r_sim_on.json()
        assert sim_on["with_ai_live"]["block_rate_pct"] == 100.0
        assert sim_on["with_ai_live"]["financial_loss_vnd"] == 0
        assert sim_on["with_ai_live"]["false_positives"] == 0
        assert sim_on["with_ai_live"]["financial_saved_vnd"] == sim_on["without_ai"]["financial_loss_vnd"]

    db_file = Path(os.environ["SQLITE_DB_PATH"])
    if db_file.exists():
        db_file.unlink()
