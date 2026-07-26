import dns.asyncresolver
import httpx
from typing import Any

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "subdomain_takeover"

_TAKEOVER_SIGNATURES = [
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3 Bucket Takeover", "The CNAME points to a non-existent AWS S3 bucket. An attacker can create an S3 bucket with this name to take over the subdomain."),
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages Takeover", "The CNAME points to an unclaimed GitHub Pages site."),
    ("herokuapp.com", "Heroku | No such app", "Heroku App Takeover", "The CNAME points to a deleted or non-existent Heroku application."),
    ("azurewebsites.net", "404 Web App not found", "Azure App Service Takeover", "The CNAME points to a deleted Azure App Service."),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify Store Takeover", "The CNAME points to an unconfigured Shopify store."),
    ("wordpress.com", "Do you want to register", "WordPress.com Subdomain Takeover", "The CNAME points to an unallocated WordPress.com blog."),
]


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    timeout = httpx.Timeout(min(6.0, settings.collector_timeout_seconds))
    headers = {"User-Agent": "Mead-EASM/2.0 (+defensive asset inventory)"}

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"checked_cnames": []}

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 6.0

    cnames: list[str] = []
    try:
        answers = await resolver.resolve(domain, "CNAME")
        cnames = [str(rdata).rstrip(".").lower() for rdata in answers]
    except Exception:
        pass

    if not cnames:
        return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)

    metadata["checked_cnames"] = cnames

    for cname_target in cnames:
        for domain_pattern, body_signature, takeover_title, description in _TAKEOVER_SIGNATURES:
            if domain_pattern in cname_target:
                # Check HTTP response body for error signature
                test_url = f"http://{domain}"
                try:
                    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
                        resp = await client.get(test_url)
                        if body_signature.lower() in resp.text.lower():
                            findings.append({
                                "title": f"High Risk: {takeover_title} detected on {domain}",
                                "severity": 4,
                                "category": "subdomain_takeover",
                                "source": NAME,
                                "evidence": {"domain": domain, "cname_target": cname_target, "signature_matched": body_signature},
                                "remediation": f"{description} Remove the dangling CNAME record from DNS or claim the cloud resource.",
                            })
                except Exception as exc:
                    metadata[f"error_{cname_target}"] = str(exc)

    return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)
