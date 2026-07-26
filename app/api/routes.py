from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, selectinload

from app.api.schemas import FindingOut, RuntimeMeta, ScanCreate, ScanDetailOut, ScanOut
from app.core.config import Settings, get_settings
from app.core.domain import ensure_authorized_scope
from app.core.security import require_api_key
from app.db.models import Finding, Scan
from app.db.session import get_db
from app.report.generator import render_report

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    try:
        ensure_authorized_scope(payload.domain, settings.allowed_domains, settings.allow_arbitrary_targets)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    queued = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"]))) or 0
    if queued >= settings.max_queued_scans:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Scan queue is full")

    scan = Scan(target=payload.domain, status="queued", summary={})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=list[ScanOut])
def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)))


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.assets), selectinload(Scan.findings), selectinload(Scan.collector_runs))
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.assets.sort(key=lambda x: (x.asset_type, x.value))
    scan.findings.sort(key=lambda x: (-x.severity, x.title))
    scan.collector_runs.sort(key=lambda x: x.started_at)
    return scan


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def get_findings(scan_id: str, db: Session = Depends(get_db)):
    if db.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity.desc(), Finding.created_at)))


@router.get("/scans/{scan_id}/report")
def get_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.assets), selectinload(Scan.findings), selectinload(Scan.collector_runs))
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    html = render_report(scan)
    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/meta", response_model=RuntimeMeta)
def runtime_meta(settings: Settings = Depends(get_settings)):
    return RuntimeMeta(
        censys_enabled=settings.censys_enabled,
        censys_configured=bool(settings.censys_pat),
        zoomeye_enabled=settings.zoomeye_enabled,
        zoomeye_configured=bool(settings.zoomeye_api_key),
        leaklookup_enabled=settings.leaklookup_enabled,
        leaklookup_configured=bool(settings.leaklookup_api_key),
        authorized_scope_count=len(settings.allowed_domains),
        arbitrary_targets_allowed=settings.allow_arbitrary_targets,
    )
