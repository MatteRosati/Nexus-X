import re
from typing import Any

import httpx

from app.collectors.base import CollectorResult
from app.core.config import get_settings

NAME = "http_audit"

_SECURITY_HEADERS = {
    "strict-transport-security": (
        "HTTP Strict Transport Security (HSTS) missing",
        2,
        "email_security",
        "Enable HSTS header to enforce HTTPS connections and protect against downgrade attacks.",
    ),
    "content-security-policy": (
        "Content Security Policy (CSP) header missing",
        1,
        "web_security",
        "Publish a Content-Security-Policy header to mitigate Cross-Site Scripting (XSS) and data injection risks.",
    ),
    "x-frame-options": (
        "X-Frame-Options header missing",
        1,
        "web_security",
        "Configure X-Frame-Options (DENY or SAMEORIGIN) to protect against Clickjacking attacks.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options header missing",
        1,
        "web_security",
        "Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing response types.",
    ),
}

_VERSION_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")

_DEPRECATED_PATTERNS = [
    (re.compile(r"php/[567]\.", re.IGNORECASE), "Deprecated PHP version exposed (PHP 5/6/7 EOL)", 3, "Upgrade PHP to a currently supported 8.x release and hide the X-Powered-By header."),
    (re.compile(r"nginx/1\.(?:[0-9]|1[0-7])\.", re.IGNORECASE), "Legacy Nginx Web Server (< 1.18)", 2, "Upgrade Nginx to a stable supported version and disable server version disclosure (server_tokens off)."),
    (re.compile(r"apache/2\.[0-3]\.", re.IGNORECASE), "Legacy Apache Server (< 2.4)", 3, "Upgrade Apache to a modern version and set ServerTokens Prod."),
    (re.compile(r"asp\.net", re.IGNORECASE), "ASP.NET Version Disclosure", 2, "Remove X-AspNet-Version and X-Powered-By headers in web.config."),
]


async def collect(domain: str, options: dict | None = None) -> CollectorResult:
    settings = get_settings()
    timeout = httpx.Timeout(min(10.0, settings.collector_timeout_seconds))
    headers = {"User-Agent": "Mead-EASM/2.0 (+defensive asset inventory)"}

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"scanned_protocols": []}

    target_urls = [f"https://{domain}", f"http://{domain}"]
    successful_response: httpx.Response | None = None
    used_url: str = ""

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True, verify=False) as client:
        for url in target_urls:
            try:
                response = await client.get(url)
                successful_response = response
                used_url = str(response.url)
                metadata["scanned_protocols"].append({"url": url, "status_code": response.status_code, "final_url": used_url})
                break
            except httpx.HTTPError as exc:
                metadata["scanned_protocols"].append({"url": url, "error": str(exc)})

    if successful_response is None:
        return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)

    resp_headers = {k.lower(): v for k, v in successful_response.headers.items()}

    assets.append({
        "asset_type": "web_property",
        "value": domain,
        "source": NAME,
        "details": {
            "final_url": used_url,
            "status_code": successful_response.status_code,
            "server_header": resp_headers.get("server"),
            "powered_by": resp_headers.get("x-powered-by"),
        },
    })

    # 1. Verification of missing HTTP Security Headers
    for header_name, (title, severity, category, remediation) in _SECURITY_HEADERS.items():
        if header_name not in resp_headers:
            findings.append({
                "title": title,
                "severity": severity,
                "category": category,
                "source": NAME,
                "evidence": {"domain": domain, "checked_header": header_name, "url": used_url},
                "remediation": remediation,
            })

    # 2. Verification of Version & Software Disclosures
    disclosed_software: list[str] = []
    for header_name in _VERSION_DISCLOSURE_HEADERS:
        if header_name in resp_headers:
            val = resp_headers[header_name]
            disclosed_software.append(f"{header_name}: {val}")

            # Check for deprecated / EOL software patterns
            for pattern, title, severity, remediation in _DEPRECATED_PATTERNS:
                if pattern.search(val):
                    findings.append({
                        "title": title,
                        "severity": severity,
                        "category": "software_governance",
                        "source": NAME,
                        "evidence": {"header": header_name, "value": val, "url": used_url},
                        "remediation": remediation,
                    })

    if disclosed_software:
        findings.append({
            "title": "Web server software version disclosure in HTTP headers",
            "severity": 2,
            "category": "information_disclosure",
            "source": NAME,
            "evidence": {"disclosures": disclosed_software, "url": used_url},
            "remediation": "Suppress detailed server and banner headers (e.g. server_tokens off in Nginx, ServerTokens Prod in Apache, expose_php = Off in php.ini).",
        })

    return CollectorResult(name=NAME, assets=assets, findings=findings, metadata=metadata)
