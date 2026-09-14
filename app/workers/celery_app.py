from celery import Celery

from app.core.config import get_settings

settings = get_settings()
celery_app = Celery(
    "api_scanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=settings.scan_timeout + 60,
    task_soft_time_limit=settings.scan_timeout,
    worker_prefetch_multiplier=1,
    worker_concurrency=1,
    task_always_eager=settings.task_always_eager,
    task_store_eager_result=False,
)
