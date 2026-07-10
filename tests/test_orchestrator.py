import pytest

from app.collectors.base import CollectorResult
from app.db.models import Asset, Finding, Scan
from app.db.session import SessionLocal
from app.engine import orchestrator


@pytest.mark.asyncio
async def test_orchestrator_persists_results_and_completes(monkeypatch):
    async def fake_crtsh(domain):
        return CollectorResult(name="crtsh", assets=[{
            "asset_type": "domain", "value": f"api.{domain}", "source": "crtsh", "details": {}
        }])

    async def fake_dns(domain):
        return CollectorResult(name="dns", findings=[{
            "title": "Test finding", "severity": 3, "category": "test", "source": "dns",
            "evidence": {"domain": domain}, "remediation": "Fix it."
        }])

    monkeypatch.setattr(orchestrator.crtsh, "collect", fake_crtsh)
    monkeypatch.setattr(orchestrator.dns, "collect", fake_dns)

    with SessionLocal() as db:
        scan = Scan(target="example.com", status="running", summary={})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    await orchestrator.process_scan(scan_id)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "completed"
        assert scan.summary["assets"] == 1
        assert scan.summary["findings"] == 1
        assert db.query(Asset).filter(Asset.scan_id == scan_id).count() == 1
        assert db.query(Finding).filter(Finding.scan_id == scan_id).count() == 1
