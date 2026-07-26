import ipaddress
from typing import Any

import dns.asyncresolver
import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "cloud_ranges"

CLOUDFLARE_IPS_URL = "https://www.cloudflare.com/ips-v4"
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    timeout = httpx.Timeout(min(8.0, settings.collector_timeout_seconds))
    headers = {"User-Agent": "Mead-EASM/2.0 (+defensive asset inventory)"}

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"resolved_ips": [], "matched_providers": []}

    # 1. Resolve A records for the domain
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 6.0
    target_ips: list[str] = []

    try:
        answers = await resolver.resolve(domain, "A")
        target_ips = [str(rdata) for rdata in answers]
    except Exception as exc:
        metadata["dns_resolution_error"] = str(exc)

    if not target_ips:
        return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)

    metadata["resolved_ips"] = target_ips

    # 2. Check Cloudflare IPv4 Ranges
    cf_cidrs: list[ipaddress.IPv4Network] = []
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            resp = await client.get(CLOUDFLARE_IPS_URL)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            cf_cidrs.append(ipaddress.IPv4Network(line))
                        except ValueError:
                            pass
    except Exception as exc:
        metadata["cloudflare_fetch_error"] = str(exc)

    # 3. Check AWS IP Ranges
    aws_cidrs: list[tuple[ipaddress.IPv4Network, str]] = []
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            resp = await client.get(AWS_IP_RANGES_URL)
            if resp.status_code == 200:
                data = resp.json()
                prefixes = data.get("prefixes") if isinstance(data.get("prefixes"), list) else []
                for item in prefixes[:2000]:  # Cap prefix processing
                    if isinstance(item, dict) and isinstance(item.get("ip_prefix"), str):
                        try:
                            net = ipaddress.IPv4Network(item["ip_prefix"])
                            region = str(item.get("region", "global"))
                            aws_cidrs.append((net, region))
                        except ValueError:
                            pass
    except Exception as exc:
        metadata["aws_fetch_error"] = str(exc)

    # Match resolved IPs against CIDRs
    for ip_str in target_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ValueError:
            continue

        matched_provider: str | None = None
        matched_details: dict[str, Any] = {}

        # Check Cloudflare
        for cidr in cf_cidrs:
            if ip_obj in cidr:
                matched_provider = "Cloudflare CDN / WAF"
                matched_details = {"provider": "Cloudflare", "cidr": str(cidr)}
                break

        # Check AWS if not Cloudflare
        if not matched_provider:
            for cidr, region in aws_cidrs:
                if ip_obj in cidr:
                    matched_provider = f"Amazon AWS ({region})"
                    matched_details = {"provider": "AWS", "region": region, "cidr": str(cidr)}
                    break

        if matched_provider:
            metadata["matched_providers"].append({"ip": ip_str, "provider": matched_provider})
            assets.append({
                "asset_type": "ip",
                "value": ip_str,
                "source": NAME,
                "details": {"cloud_infrastructure": matched_details},
            })

            findings.append({
                "title": f"Public cloud / CDN infrastructure identified: {matched_provider}",
                "severity": 1,
                "category": "infrastructure_discovery",
                "source": NAME,
                "evidence": {"ip": ip_str, "provider_details": matched_details, "domain": domain},
                "remediation": "Verify cloud asset tags and access controls on hosted cloud resources.",
            })

    return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)
