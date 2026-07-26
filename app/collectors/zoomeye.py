import asyncio
from typing import Any

import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "zoomeye"
SEARCH_URL = "https://api.zoomeye.ai/host/search"
_SENSITIVE_PORTS = {
    2375: (4, "Docker API"),
    2379: (4, "etcd"),
    2380: (4, "etcd peer"),
    6443: (4, "Kubernetes API"),
    9200: (4, "Elasticsearch"),
    11211: (4, "Memcached"),
    27017: (4, "MongoDB"),
    6379: (4, "Redis"),
    3389: (3, "RDP"),
    5900: (3, "VNC"),
    445: (3, "SMB"),
    3306: (3, "MySQL"),
    5432: (3, "PostgreSQL"),
    1433: (3, "Microsoft SQL Server"),
}
_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(get_settings().zoomeye_max_concurrency)
    return _semaphore


def _escape_query_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    opts = options or {}
    
    enabled = opts.get("zoomeye_enabled", settings.zoomeye_enabled)
    api_key = opts.get("zoomeye_api_key")
    if not api_key and settings.zoomeye_api_key:
        api_key = settings.zoomeye_api_key.get_secret_value()
        
    if not enabled or not api_key:
        return CollectorResult(name=NAME, metadata={"disabled": True})

    escaped = _escape_query_value(domain)
    # Search for anything related to the domain
    query = f"site:{escaped}"
    
    headers = {
        "API-KEY": api_key,
        "Accept": "application/json",
        "User-Agent": "Mead-EASM/2.0",
    }
    params = {"query": query, "page": 1}

    async with _get_semaphore():
        # Polite sleep to respect ZoomEye's free tier rate limit
        await asyncio.sleep(2)
        
        async with httpx.AsyncClient(timeout=settings.collector_timeout_seconds, follow_redirects=False) as client:
            response = await client.get(SEARCH_URL, params=params, headers=headers)
            if response.status_code == 401:
                raise RuntimeError("ZoomEye rejected the API Key (401). Verify ZOOMEYE_API_KEY.")
            if response.status_code == 402:
                 raise RuntimeError("ZoomEye Payment Required (402). Out of points or quota exceeded.")
            if response.status_code == 403:
                raise RuntimeError("ZoomEye denied the request (403).")
            if response.status_code == 429:
                raise RuntimeError("ZoomEye rate limit reached (429). Reduce concurrency or retry later.")
            
            response.raise_for_status()
            payload = response.json()

    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected ZoomEye response format")
        
    matches = payload.get("matches", [])
    if not isinstance(matches, list):
        matches = []
        
    matches = matches[:settings.zoomeye_max_results]

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    observed_sensitive: set[tuple[str, int]] = set()

    for hit in matches:
        ip = hit.get("ip")
        if ip:
            assets.append({"asset_type": "ip", "value": ip, "source": NAME, "details": {"zoomeye": True}})
            
        portinfo = hit.get("portinfo")
        if isinstance(portinfo, dict):
            port = portinfo.get("port")
            service_name = portinfo.get("service")
            if isinstance(port, int):
                endpoint = ip or domain
                assets.append({
                    "asset_type": "service",
                    "value": f"{endpoint}:{port}",
                    "source": NAME,
                    "details": {"port": port, "service": service_name, "zoomeye": True},
                })
                
                if port in _SENSITIVE_PORTS and (endpoint, port) not in observed_sensitive:
                    observed_sensitive.add((endpoint, port))
                    severity, sensitive_name = _SENSITIVE_PORTS[port]
                    findings.append({
                        "title": f"Potentially sensitive Internet-exposed service observed: {sensitive_name}",
                        "severity": severity,
                        "category": "external_exposure",
                        "source": NAME,
                        "evidence": {"endpoint": endpoint, "port": port, "service": service_name},
                        "remediation": "Confirm business necessity and ownership, restrict network access to trusted sources, require strong authentication, and verify the service is fully patched. This is an exposure observation, not proof of a vulnerability.",
                    })

    total = payload.get("total", len(matches))
    return CollectorResult(
        name=NAME,
        assets=assets,
        findings=findings,
        metadata={"query": query, "returned_hits": len(matches), "reported_total": total, "max_results_cap": settings.zoomeye_max_results},
    )
