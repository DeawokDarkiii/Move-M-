"""Tests for Dual-Layer SOC Incident Report Exporter & API Export Endpoints."""

from __future__ import annotations

import json
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


def test_incident_analysis_and_export_formats() -> None:
    with TestClient(app) as client:
        # Reset sandbox & trigger webhook replay attack
        r_reset = client.post("/v1/sandbox/reset", headers=HEADERS)
        assert r_reset.status_code == 200

        r_sim = client.post(
            "/v1/sandbox/simulate/webhook_replay",
            headers=HEADERS,
            json={"with_prompt_injection": True},
        )
        assert r_sim.status_code == 200

        # Investigate incident
        r_inv = client.post("/v1/incidents/investigate", headers=HEADERS, json={})
        assert r_inv.status_code == 200
        inc = r_inv.json()
        inc_id = inc["id"]
        assert "structured_analysis" in inc
        assert "executive_summary" in inc["structured_analysis"]
        assert "technical_analysis" in inc["structured_analysis"]
        assert "CWE-" in inc["structured_analysis"]["technical_analysis"]["cwe_mapping"]

        # GET /analysis
        r_ana = client.get(f"/v1/incidents/{inc_id}/analysis", headers=HEADERS)
        assert r_ana.status_code == 200
        assert r_ana.json()["incident_id"] == inc_id

        # Export Markdown
        r_md = client.get(f"/v1/incidents/{inc_id}/export?format=markdown", headers=HEADERS)
        assert r_md.status_code == 200
        assert "text/markdown" in r_md.headers["content-type"]
        assert "Tóm tắt Điều hành" in r_md.text
        assert "Phân tích Kỹ thuật Chuyên sâu" in r_md.text
        assert "OWASP API Top 10" in r_md.text

        # Export HTML (Print-to-PDF)
        r_html = client.get(f"/v1/incidents/{inc_id}/export?format=html", headers=HEADERS)
        assert r_html.status_code == 200
        assert "text/html" in r_html.headers["content-type"]
        assert "window.print()" in r_html.text
        assert inc_id in r_html.text

        # Export JSON (SIEM)
        r_json = client.get(f"/v1/incidents/{inc_id}/export?format=json", headers=HEADERS)
        assert r_json.status_code == 200
        parsed = json.loads(r_json.text)
        assert parsed["id"] == inc_id
        assert parsed["structured_analysis"]["technical_analysis"]["condition_type"] == "DEDUP_BODY_FIELD"

    db_file = Path(os.environ["SQLITE_DB_PATH"])
    if db_file.exists():
        db_file.unlink()
