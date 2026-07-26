from datetime import datetime, timezone
from typing import Any

import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "whois_rdap"
RDAP_BASE_URL = "https://rdap.org/domain"


def _parse_iso_datetime(value: str) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        clean_val = value.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_val).astimezone(timezone.utc)
    except Exception:
        return None


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    timeout = httpx.Timeout(min(10.0, settings.collector_timeout_seconds))
    headers = {"User-Agent": "Mead-EASM/2.0 (+defensive asset inventory)", "Accept": "application/rdap+json, application/json"}

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}

    url = f"{RDAP_BASE_URL}/{domain}"
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 404:
                metadata["rdap_status"] = "not_found"
                return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        metadata["rdap_error"] = str(exc)
        return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)

    if not isinstance(data, dict):
        return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)

    # Extract Expiration & Registration dates from events
    events = data.get("events") if isinstance(data.get("events"), list) else []
    expiration_date: datetime | None = None
    registration_date: datetime | None = None
    last_update_date: datetime | None = None

    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        date_str = str(event.get("eventDate", ""))
        parsed_dt = _parse_iso_datetime(date_str)
        if action in ("expiration", "registration expiration", "expires"):
            expiration_date = parsed_dt
        elif action in ("registration", "created"):
            registration_date = parsed_dt
        elif action in ("last changed", "last update", "updated"):
            last_update_date = parsed_dt

    # Extract Registrar Name
    entities = data.get("entities") if isinstance(data.get("entities"), list) else []
    registrar_name = "Unknown Registrar"
    for entity in entities:
        if isinstance(entity, dict) and "registrar" in [str(r).lower() for r in entity.get("roles", [])]:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for entry in vcard[1]:
                    if isinstance(entry, list) and len(entry) > 3 and entry[0] == "fn":
                        registrar_name = str(entry[3])
                        break

    # Extract Nameservers
    nameservers: list[str] = []
    ns_entries = data.get("nameservers") if isinstance(data.get("nameservers"), list) else []
    for ns in ns_entries:
        if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
            nameservers.append(ns["ldhName"].lower().rstrip("."))

    details: dict[str, Any] = {
        "registrar": registrar_name,
        "nameservers": nameservers,
        "handle": data.get("handle"),
        "status": data.get("status"),
    }
    if expiration_date:
        details["expiration_date"] = expiration_date.isoformat()
    if registration_date:
        details["registration_date"] = registration_date.isoformat()

    assets.append({
        "asset_type": "domain",
        "value": domain,
        "source": NAME,
        "details": details,
    })

    # Evaluate Expiration Findings
    if expiration_date:
        now = datetime.now(timezone.utc)
        days_until_exp = (expiration_date - now).days
        metadata["days_until_expiration"] = days_until_exp

        if days_until_exp <= 7:
            findings.append({
                "title": f"Critical domain expiration risk ({days_until_exp} days remaining)",
                "severity": 5,
                "category": "domain_governance",
                "source": NAME,
                "evidence": {"domain": domain, "expiration_date": expiration_date.isoformat(), "days_remaining": days_until_exp, "registrar": registrar_name},
                "remediation": "Renew the domain registration immediately to prevent domain takeover or service disruption.",
            })
        elif days_until_exp <= 30:
            findings.append({
                "title": f"Impending domain expiration ({days_until_exp} days remaining)",
                "severity": 3,
                "category": "domain_governance",
                "source": NAME,
                "evidence": {"domain": domain, "expiration_date": expiration_date.isoformat(), "days_remaining": days_until_exp, "registrar": registrar_name},
                "remediation": "Schedule domain renewal with your registrar before expiration.",
            })

    return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)
