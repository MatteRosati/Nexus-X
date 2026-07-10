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
