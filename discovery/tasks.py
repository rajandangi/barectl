"""Background tasks run by the durable worker (``manage.py db_worker``)."""

from django.tasks import task


@task
def run_discovery(attempt_id: int) -> None:
    # Imported here: the services module enqueues this task, so it imports this module.
    from .services import run_attempt

    run_attempt(attempt_id)
