import json
from collections import Counter

import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings
from app.core.domain import is_subdomain_or_equal

NAME = "crtsh"


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    timeout = httpx.Timeout(settings.collector_timeout_seconds)
    headers = {"User-Agent": "Mead-EASM/2.0 (+defensive asset inventory)"}
    body = bytearray()

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=False) as client:
        async with client.stream("GET", "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > settings.crtsh_max_response_bytes:
                    raise RuntimeError("crt.sh response exceeded the configured size limit")

    parsed = json.loads(body)
    if not isinstance(parsed, list):
        raise RuntimeError("Unexpected crt.sh response format")

    truncated = len(parsed) > settings.crtsh_max_entries
    entries = parsed[: settings.crtsh_max_entries]
    names = Counter()
    wildcard_count = 0

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        candidates = []
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                candidates.extend(value.splitlines())
        for raw_name in candidates:
            name = raw_name.strip().lower().rstrip(".")
            if name.startswith("*."):
                wildcard_count += 1
                name = name[2:]
            try:
                ascii_name = name.encode("idna").decode("ascii")
            except UnicodeError:
                continue
            if is_subdomain_or_equal(ascii_name, domain):
                names[ascii_name] += 1

    assets = [
        {
            "asset_type": "domain",
            "value": name,
            "source": NAME,
            "details": {"certificate_observations": count},
        }
        for name, count in sorted(names.items())
    ]

    return CollectorResult(
        name=NAME,
        assets=assets,
        metadata={
            "response_entries": len(parsed),
            "processed_entries": len(entries),
            "unique_in_scope_domains": len(assets),
            "wildcard_name_observations": wildcard_count,
            "truncated": truncated,
        },
    )
