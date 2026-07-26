import httpx
from typing import Any

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "leaklookup"
SEARCH_URL = "https://leak-lookup.com/api/search"

async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    opts = options or {}
    
    enabled = opts.get("leaklookup_enabled", settings.leaklookup_enabled)
    api_key = opts.get("leaklookup_api_key")
    if not api_key and settings.leaklookup_api_key:
        api_key = settings.leaklookup_api_key.get_secret_value()
        
    if not enabled or not api_key:
        return CollectorResult(name=NAME, metadata={"disabled": True})
        
    payload = {
        "key": api_key,
        "type": "domain",
        "query": domain
    }
    
    async with httpx.AsyncClient(timeout=settings.collector_timeout_seconds, follow_redirects=True) as client:
        response = await client.post(SEARCH_URL, data=payload)
        if response.status_code == 401 or response.status_code == 403:
            raise RuntimeError("Leak Lookup API Key rejected (401/403).")
        response.raise_for_status()
        data = response.json()
        
    if str(data.get("error")).lower() == "true":
        msg = data.get("message", "Unknown error from Leak Lookup")
        if "no results" in str(msg).lower():
            # Not an actual error, just no leaks found
            return CollectorResult(name=NAME, assets=[], findings=[], metadata={"message": msg})
        if "invalid key" in str(msg).lower():
            raise RuntimeError(f"Leak Lookup API Key is invalid: {msg}")
        raise RuntimeError(f"Leak Lookup API Error: {msg}")
        
    message_data = data.get("message", {})
    findings: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    
    if isinstance(message_data, dict):
        for breach_name, hits in message_data.items():
            hit_count = len(hits) if isinstance(hits, list) else 1
            findings.append({
                "title": f"Domain observed in data breach: {breach_name}",
                "severity": 4,
                "category": "credential_leak",
                "source": NAME,
                "evidence": {"breach_name": breach_name, "hits": hit_count},
                "remediation": "Force password resets for affected users. Implement MFA. Ensure credentials are not reused across corporate and third-party systems."
            })
    elif isinstance(message_data, list) and message_data:
        findings.append({
            "title": f"Domain observed in {len(message_data)} data breach(es)",
            "severity": 4,
            "category": "credential_leak",
            "source": NAME,
            "evidence": {"breaches": message_data},
            "remediation": "Force password resets for affected users. Implement MFA. Ensure credentials are not reused across corporate and third-party systems."
        })
        
    return CollectorResult(
        name=NAME,
        assets=assets,
        findings=findings,
        metadata={"reported_breaches": len(findings)}
    )
