import os

from celery import Celery
from celery.signals import worker_process_init

from app.core.config import settings
from app.core.logging import configure_logging

# macOS starts pool children with "spawn"; without this flag Celery never sets them up.
os.environ.setdefault("FORKED_BY_MULTIPROCESSING", "1")

celery_app = Celery(
    "sentinelti",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    # A killed worker hands the job back; the LangGraph checkpoint resumes it.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=900,
    task_time_limit=960,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
)


@worker_process_init.connect
def _on_worker_start(**_):
    configure_logging()
