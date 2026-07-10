import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.models import Scan
from app.db.session import SessionLocal
from app.engine.orchestrator import process_scan

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def recover_stale_scans() -> int:
    settings = get_settings()
    cutoff = utcnow() - timedelta(minutes=settings.scan_stale_after_minutes)
    with SessionLocal() as db:
        result = db.execute(
            update(Scan)
            .where(Scan.status == "running", Scan.started_at < cutoff)
            .values(status="queued", started_at=None, error="Recovered after worker interruption")
        )
        db.commit()
        return result.rowcount or 0


def claim_next_scan() -> str | None:
    with SessionLocal() as db:
        with db.begin():
            scan = db.scalar(
                select(Scan)
                .where(Scan.status == "queued")
                .order_by(Scan.created_at)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if scan is None:
                return None
            scan.status = "running"
            scan.started_at = utcnow()
            scan.completed_at = None
            scan.error = None
            scan.attempts += 1
            scan_id = scan.id
        return scan_id


async def run_worker() -> None:
    settings = get_settings()
    recovered = recover_stale_scans()
    if recovered:
        logger.warning("Recovered stale scans", extra={"count": recovered})

    active: set[asyncio.Task] = set()
    while True:
        done = {task for task in active if task.done()}
        for task in done:
            active.remove(task)
            try:
                task.result()
            except Exception:
                logger.exception("Unhandled scan task failure")

        while len(active) < settings.worker_concurrency:
            scan_id = claim_next_scan()
            if scan_id is None:
                break
            active.add(asyncio.create_task(process_scan(scan_id)))

        await asyncio.sleep(settings.worker_poll_seconds)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("Worker started")
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
