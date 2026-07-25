import pytest

from app.collectors.censys import _extract_hits


def test_censys_hit_extraction_supports_result_hits():
    payload = {"result": {"hits": [{"host": {"ip": "203.0.113.10"}}]}}
    assert _extract_hits(payload)[0]["host"]["ip"] == "203.0.113.10"


@pytest.mark.asyncio
async def test_dns_collector_returns_structured_result(monkeypatch):
    from app.collectors import dns as dns_collector

    async def fake_resolve(_resolver, name, record_type):
        data = {
            ("example.com", "A"): (["203.0.113.10"], None),
            ("example.com", "MX"): (["10 mail.example.com."], None),
            ("example.com", "TXT"): (["v=spf1 -all"], None),
            ("_dmarc.example.com", "TXT"): (["v=DMARC1; p=reject"], None),
        }
        return data.get((name, record_type), ([], "no_answer"))

    monkeypatch.setattr(dns_collector, "_resolve", fake_resolve)
    result = await dns_collector.collect("example.com")
    assert result.name == "dns"
    assert any(asset["asset_type"] == "ip" for asset in result.assets)
    assert not any("DMARC record not observed" in finding["title"] for finding in result.findings)


@pytest.mark.asyncio
async def test_http_audit_collector_detects_software_disclosure(httpx_mock):
    from app.collectors import http_audit

    httpx_mock.add_response(
        url="https://example.com",
        headers={
            "Server": "nginx/1.14.0",
            "X-Powered-By": "PHP/7.4.3",
        },
        status_code=200,
    )

    result = await http_audit.collect("example.com")
    assert result.name == "http_audit"
    assert len(result.assets) == 1
    assert result.assets[0]["asset_type"] == "web_property"
    # Should detect missing HSTS/CSP/X-Frame/X-Content-Type + Server disclosure + PHP EOL
    assert any("version disclosure" in f["title"].lower() for f in result.findings)
    assert any("php" in f["title"].lower() for f in result.findings)

