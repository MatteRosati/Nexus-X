import asyncio
from typing import Any

import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "censys"
SEARCH_URL = "https://api.platform.censys.io/v3/global/search/query"
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
        _semaphore = asyncio.Semaphore(get_settings().censys_max_concurrency)
    return _semaphore


def _escape_query_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _extract_hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    paths = [
        ("result", "hits"),
        ("result", "results"),
        ("hits",),
        ("results",),
    ]
    for path in paths:
        node: Any = payload
        for key in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if isinstance(node, list):
            return [item for item in node if isinstance(item, dict)]
    return []


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _collect_ports(hit: dict[str, Any]) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    host = hit.get("host") if isinstance(hit.get("host"), dict) else {}
    candidates = _as_list(host.get("services")) + _as_list(hit.get("matched_services"))
    for service in candidates:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        if isinstance(port, int):
            services.append({
                "port": port,
                "transport": service.get("transport_protocol") or service.get("transport"),
                "protocol": service.get("protocol") or service.get("service_name"),
            })
    return services


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    opts = options or {}
    
    enabled = opts.get("censys_enabled", settings.censys_enabled)
    api_key = opts.get("censys_api_key")
    if not api_key and settings.censys_pat:
        api_key = settings.censys_pat.get_secret_value()
        
    if not enabled or not api_key:
        return CollectorResult(name=NAME, metadata={"disabled": True})

    escaped = _escape_query_value(domain)
    query = (
        f'(host.dns.names: "{escaped}" or '
        f'host.dns.reverse_dns.names: "{escaped}" or '
        f'web.hostname: "{escaped}")'
    )
    fields = [
        "host.ip",
        "host.dns.names",
        "host.dns.reverse_dns.names",
        "host.services.port",
        "host.services.transport_protocol",
        "host.services.protocol",
        "web.hostname",
        "web.port",
        "web.endpoints.ip",
    ]
    params = {}
    if settings.censys_organization_id:
        params["organization_id"] = settings.censys_organization_id
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": "Mead-EASM/2.0",
    }
    body = {"query": query, "page_size": settings.censys_max_results, "fields": fields}

    async with _get_semaphore():
        async with httpx.AsyncClient(timeout=settings.collector_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(SEARCH_URL, params=params, headers=headers, json=body)
            if response.status_code == 401:
                raise RuntimeError("Censys rejected the PAT (401). Verify CENSYS_PAT.")
            if response.status_code == 403:
                raise RuntimeError("Censys denied the request (403). Verify plan entitlements, API Access role and organization ID.")
            if response.status_code == 429:
                raise RuntimeError("Censys rate limit reached (429). Reduce concurrency or retry later.")
            response.raise_for_status()
            payload = response.json()

    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected Censys response format")
    hits = _extract_hits(payload)
    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    observed_sensitive: set[tuple[str, int]] = set()

    for hit in hits:
        host = hit.get("host") if isinstance(hit.get("host"), dict) else {}
        web = hit.get("web") if isinstance(hit.get("web"), dict) else {}
        ip = host.get("ip") if isinstance(host.get("ip"), str) else None
        if ip:
            assets.append({"asset_type": "ip", "value": ip, "source": NAME, "details": {"censys": True}})

        dns_data = host.get("dns") if isinstance(host.get("dns"), dict) else {}
        for key in ("names",):
            for name in _as_list(dns_data.get(key)):
                if isinstance(name, str):
                    assets.append({"asset_type": "domain", "value": name.lower().rstrip("."), "source": NAME, "details": {"observed_on_ip": ip}})
        reverse_dns = dns_data.get("reverse_dns") if isinstance(dns_data.get("reverse_dns"), dict) else {}
        for name in _as_list(reverse_dns.get("names")):
            if isinstance(name, str):
                assets.append({"asset_type": "domain", "value": name.lower().rstrip("."), "source": NAME, "details": {"reverse_dns_for": ip}})

        hostname = web.get("hostname") if isinstance(web.get("hostname"), str) else None
        if hostname:
            assets.append({"asset_type": "web_property", "value": hostname.lower().rstrip("."), "source": NAME, "details": {"port": web.get("port")}})

        for service in _collect_ports(hit):
            port = service["port"]
            endpoint = ip or hostname or domain
            assets.append({
                "asset_type": "service",
                "value": f"{endpoint}:{port}",
                "source": NAME,
                "details": service,
            })
            if port in _SENSITIVE_PORTS and (endpoint, port) not in observed_sensitive:
                observed_sensitive.add((endpoint, port))
                severity, service_name = _SENSITIVE_PORTS[port]
                findings.append({
                    "title": f"Potentially sensitive Internet-exposed service observed: {service_name}",
                    "severity": severity,
                    "category": "external_exposure",
                    "source": NAME,
                    "evidence": {"endpoint": endpoint, "port": port, "service": service},
                    "remediation": "Confirm business necessity and ownership, restrict network access to trusted sources, require strong authentication, and verify the service is fully patched. This is an exposure observation, not proof of a vulnerability.",
                })

    result_node = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    total = result_node.get("total") or payload.get("total")
    return CollectorResult(
        name=NAME,
        assets=assets,
        findings=findings,
        metadata={"query": query, "returned_hits": len(hits), "reported_total": total, "page_size": settings.censys_max_results},
    )
