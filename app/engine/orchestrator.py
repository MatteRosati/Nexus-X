import asyncio
import logging
from datetime import datetime, timezone
from typing import Awaitable, Callable

from sqlalchemy import func, select

from app.collectors import (
    censys,
    cisa_kev,
    cloud_ranges,
    crtsh,
    dns,
    http_audit,
    subdomain_takeover,
    whois_rdap,
    zoomeye,
    leaklookup,
)
from app.collectors.base import CollectorResult
from app.core.config import get_settings
from app.db.models import Asset, CollectorRun, Finding, Scan
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)
Collector = tuple[str, Callable[[str], Awaitable[CollectorResult]]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _merge_dict(existing: dict, incoming: dict) -> dict:
    merged = dict(existing or {})
    for key, value in (incoming or {}).items():
        if key not in merged:
            merged[key] = value
        elif merged[key] != value:
            current = merged[key]
            if not isinstance(current, list):
                current = [current]
            if value not in current:
                current.append(value)
            merged[key] = current
    return merged


def _persist_result(scan_id: str, run_id: str, result: CollectorResult) -> None:
    with SessionLocal() as db:
        for item in result.assets:
            asset_type = str(item.get("asset_type", "unknown"))[:32]
            value = str(item.get("value", ""))[:512]
            if not value:
                continue
            source = str(item.get("source", result.name))[:64]
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            asset = db.scalar(select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type == asset_type, Asset.value == value))
            if asset is None:
                asset = Asset(scan_id=scan_id, asset_type=asset_type, value=value, sources=[source], details=details)
                db.add(asset)
                db.flush()
            else:
                sources = list(asset.sources or [])
                if source not in sources:
                    sources.append(source)
                asset.sources = sources
                asset.details = _merge_dict(asset.details, details)

        for item in result.findings:
            severity = int(item.get("severity", 1))
            severity = max(1, min(5, severity))
            db.add(Finding(
                scan_id=scan_id,
                title=str(item.get("title", "Untitled finding"))[:255],
                severity=severity,
                category=str(item.get("category", "general"))[:64],
                source=str(item.get("source", result.name))[:64],
                evidence=item.get("evidence") if isinstance(item.get("evidence"), dict) else {},
                remediation=str(item.get("remediation", "Review and remediate as appropriate.")),
            ))

        run = db.get(CollectorRun, run_id)
        if run:
            run.status = "completed"
            run.completed_at = _utcnow()
            run.item_count = len(result.assets) + len(result.findings)
            run.metadata_json = result.metadata
        db.commit()


def _mark_run_failed(run_id: str, message: str) -> None:
    with SessionLocal() as db:
        run = db.get(CollectorRun, run_id)
        if run:
            run.status = "failed"
            run.completed_at = _utcnow()
            run.error = message[:4000]
            db.commit()


async def _execute_collector(scan_id: str, domain: str, collector: Collector) -> tuple[str, bool, str | None]:
    name, function = collector
    with SessionLocal() as db:
        run = CollectorRun(scan_id=scan_id, collector_name=name, status="running", metadata_json={})
        db.add(run)
        db.commit()
        run_id = run.id

    try:
        result = await function(domain)
        _persist_result(scan_id, run_id, result)
        return name, True, None
    except Exception as exc:
        message = f"{exc.__class__.__name__}: {exc}"
        _mark_run_failed(run_id, message)
        logger.exception("Collector failed", extra={"scan_id": scan_id, "collector": name, "target": domain})
        return name, False, message


async def _process_scan(scan_id: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        domain = scan.target

    settings = get_settings()
    collectors: list[Collector] = [
        (crtsh.NAME, crtsh.collect),
        (dns.NAME, dns.collect),
        (http_audit.NAME, http_audit.collect),
        (whois_rdap.NAME, whois_rdap.collect),
        (cloud_ranges.NAME, cloud_ranges.collect),
        (subdomain_takeover.NAME, subdomain_takeover.collect),
        (cisa_kev.NAME, cisa_kev.collect),
    ]
    if settings.censys_enabled:
        collectors.append((censys.NAME, censys.collect))
    if settings.zoomeye_enabled:
        collectors.append((zoomeye.NAME, zoomeye.collect))
    if settings.leaklookup_enabled:
        collectors.append((leaklookup.NAME, leaklookup.collect))

    logger.info("Starting scan", extra={"scan_id": scan_id, "target": domain})
    results = await asyncio.gather(*[_execute_collector(scan_id, domain, collector) for collector in collectors])
    successes = [item for item in results if item[1]]
    failures = [item for item in results if not item[1]]

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        asset_count = db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan_id)) or 0
        finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)) or 0
        severity_counts = {
            str(level): db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id, Finding.severity == level)) or 0
            for level in range(1, 6)
        }
        scan.completed_at = _utcnow()
        scan.summary = {
            "assets": asset_count,
            "findings": finding_count,
            "findings_by_severity": severity_counts,
            "collectors_succeeded": [name for name, _, _ in successes],
            "collectors_failed": [name for name, _, _ in failures],
        }
        if successes and failures:
            scan.status = "partial_failed"
            scan.error = "; ".join(f"{name}: {error}" for name, _, error in failures)[:4000]
        elif failures and not successes:
            scan.status = "failed"
            scan.error = "; ".join(f"{name}: {error}" for name, _, error in failures)[:4000]
        else:
            scan.status = "completed"
            scan.error = None
        db.commit()

    logger.info("Scan finished", extra={"scan_id": scan_id, "target": domain})


async def process_scan(scan_id: str) -> None:
    try:
        await _process_scan(scan_id)
    except Exception as exc:
        message = f"Unhandled scan failure: {exc.__class__.__name__}: {exc}"
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.completed_at = _utcnow()
                scan.error = message[:4000]
                db.commit()
        logger.exception("Unhandled scan failure", extra={"scan_id": scan_id})
