from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "dns"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME", "TXT", "CAA")


def _clean_dns_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


async def _resolve(resolver: dns.asyncresolver.Resolver, name: str, record_type: str) -> tuple[list[str], str | None]:
    try:
        answer = await resolver.resolve(name, record_type)
        return [str(item) for item in answer], None
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "no_answer"
    except dns.resolver.NoNameservers:
        return [], "no_nameservers"
    except dns.exception.Timeout:
        return [], "timeout"
    except dns.exception.DNSException as exc:
        return [], exc.__class__.__name__.lower()


async def collect(domain: str) -> CollectorResult:
    settings = get_settings()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = min(5.0, settings.collector_timeout_seconds)
    resolver.lifetime = min(10.0, settings.collector_timeout_seconds)

    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    for record_type in RECORD_TYPES:
        values, error = await _resolve(resolver, domain, record_type)
        records[record_type] = values
        if error:
            errors[record_type] = error

    dmarc_values, dmarc_error = await _resolve(resolver, f"_dmarc.{domain}", "TXT")
    records["DMARC"] = dmarc_values
    if dmarc_error:
        errors["DMARC"] = dmarc_error

    assets: list[dict[str, Any]] = [{"asset_type": "domain", "value": domain, "source": NAME, "details": {"dns_records": records}}]
    for ip in records["A"] + records["AAAA"]:
        assets.append({"asset_type": "ip", "value": ip, "source": NAME, "details": {"resolved_from": domain}})
    for raw in records["MX"]:
        parts = raw.split()
        if parts:
            assets.append({"asset_type": "mail_host", "value": _clean_dns_name(parts[-1]), "source": NAME, "details": {"mx_record": raw}})
    for record_type in ("NS", "CNAME"):
        for raw in records[record_type]:
            assets.append({"asset_type": "dns_name", "value": _clean_dns_name(raw), "source": NAME, "details": {"record_type": record_type}})

    txt_joined = " ".join(records["TXT"]).lower()
    dmarc_joined = " ".join(dmarc_values).lower()
    findings: list[dict[str, Any]] = []

    if "v=spf1" not in txt_joined:
        findings.append({
            "title": "SPF record not observed",
            "severity": 2,
            "category": "email_security",
            "source": NAME,
            "evidence": {"domain": domain, "txt_records": records["TXT"]},
            "remediation": "Publish and maintain an SPF policy that accurately authorizes the systems permitted to send mail for this domain.",
        })

    if records["MX"] and "v=dmarc1" not in dmarc_joined:
        findings.append({
            "title": "DMARC record not observed for a mail-enabled domain",
            "severity": 3,
            "category": "email_security",
            "source": NAME,
            "evidence": {"domain": domain, "mx_records": records["MX"]},
            "remediation": "Deploy DMARC at _dmarc.<domain>, begin with monitoring, then move to quarantine or reject after validating legitimate senders.",
        })
    elif "v=dmarc1" in dmarc_joined and "p=none" in dmarc_joined:
        findings.append({
            "title": "DMARC policy is monitoring-only (p=none)",
            "severity": 2,
            "category": "email_security",
            "source": NAME,
            "evidence": {"domain": domain, "dmarc_records": dmarc_values},
            "remediation": "After reviewing DMARC reports and aligning legitimate senders, progress toward p=quarantine or p=reject.",
        })

    if not records["CAA"]:
        findings.append({
            "title": "CAA record not observed",
            "severity": 1,
            "category": "certificate_governance",
            "source": NAME,
            "evidence": {"domain": domain},
            "remediation": "Consider publishing CAA records to constrain which certificate authorities may issue certificates for the domain.",
        })

    return CollectorResult(
        name=NAME,
        assets=assets,
        findings=findings,
        metadata={"record_counts": {k: len(v) for k, v in records.items()}, "resolution_status": errors},
    )
