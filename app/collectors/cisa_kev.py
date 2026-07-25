from typing import Any

import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "cisa_kev"
CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Local baseline fallback for offline resilience
_CRITICAL_KEV_BASELINE = [
    ("CVE-2021-44228", "Apache Log4j2 RCE (Log4Shell)", "Critical RCE in Log4j2. Upgrade log4j to >= 2.17.1."),
    ("CVE-2023-34362", "MOVEit Transfer RCE", "SQL injection in MOVEit Transfer. Apply vendor patch immediately."),
    ("CVE-2023-22515", "Confluence Data Center RCE", "Privilege escalation vulnerability in Atlassian Confluence."),
    ("CVE-2023-46604", "Apache ActiveMQ RCE", "Remote code execution in Apache ActiveMQ. Upgrade ActiveMQ."),
]


async def collect(domain: str) -> CollectorResult:
    settings = get_settings()
    timeout = httpx.Timeout(min(8.0, settings.collector_timeout_seconds))
    headers = {"User-Agent": "Mead-EASM/2.0 (+defensive asset inventory)"}

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"cisa_kev_entries_loaded": 0}

    kev_vulnerabilities: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            resp = await client.get(CISA_KEV_FEED_URL)
            if resp.status_code == 200:
                payload = resp.json()
                items = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
                metadata["cisa_kev_entries_loaded"] = len(items)
                kev_vulnerabilities = items
    except Exception as exc:
        metadata["cisa_kev_fetch_error"] = str(exc)

    if not kev_vulnerabilities:
        # Use baseline metadata if offline
        metadata["used_offline_baseline"] = True

    assets.append({
        "asset_type": "threat_intel",
        "value": "CISA Known Exploited Vulnerabilities Catalog",
        "source": NAME,
        "details": {"feed_url": CISA_KEV_FEED_URL, "active_entries": metadata.get("cisa_kev_entries_loaded", len(_CRITICAL_KEV_BASELINE))},
    })

    return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)
