"""Background tasks run by the durable worker (``manage.py db_worker``)."""

from django.tasks import task

from . import services


@task
def run_discovery(attempt_id: int) -> None:
    services.run_attempt(attempt_id)
