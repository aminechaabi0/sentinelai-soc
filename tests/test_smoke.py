"""Minimal smoke tests; install pytest and httpx to run with TestClient."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("SENTINEL_API_KEY", "test-key")
os.environ.setdefault("WAZUH_WEBHOOK_TOKEN", "test-webhook")

from fastapi.testclient import TestClient
from app.main import app, init_db
init_db()

client = TestClient(app)
HEADERS = {"X-API-Key": "test-key"}


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_demo_seed_and_events():
    response = client.post("/api/demo/seed", headers=HEADERS, json={})
    assert response.status_code == 200
    assert response.json()["created"] == 5
    events = client.get("/api/events", headers=HEADERS)
    assert events.status_code == 200
    assert len(events.json()["items"]) >= 5


def test_wazuh_receiver():
    payload = {"timestamp":"2026-10-11T10:00:00Z", "rule":{"id":"5710","level":10,"description":"SSH failure"}, "agent":{"name":"test-host"}, "data":{"srcip":"198.51.100.23"}}
    response = client.post("/api/integrations/wazuh", headers={"X-Webhook-Token":"test-webhook"}, json=payload)
    assert response.status_code == 200
    assert response.json()["accepted"] is True
