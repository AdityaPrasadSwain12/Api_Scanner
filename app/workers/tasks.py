from app.core.config import get_settings
from app.db import SessionLocal
from app.services.orchestrator import Orchestrator
from app.workers.celery_app import celery_app


@celery_app.task(name="scanner.run_scan", bind=True, acks_late=True)
def run_scan(self, scan_id: str) -> None:
    with SessionLocal() as db:
        Orchestrator(db, get_settings()).run_sync(scan_id)
