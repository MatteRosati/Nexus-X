from app.db.models import Finding, Scan
from app.db.session import SessionLocal


def test_report_escapes_untrusted_content(client, auth_headers):
    payload = "</pre><script>alert('xss')</script><pre>"
    with SessionLocal() as db:
        scan = Scan(target="example.com", status="completed", summary={"assets": 0, "findings": 1})
        db.add(scan)
        db.flush()
        db.add(Finding(
            scan_id=scan.id,
            title=payload,
            severity=3,
            category="test",
            source="test",
            evidence={"payload": payload},
            remediation=payload,
        ))
        db.commit()
        scan_id = scan.id

    response = client.get(f"/api/v1/scans/{scan_id}/report", headers=auth_headers)
    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;alert" in response.text
