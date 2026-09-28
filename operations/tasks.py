"""Background tasks run by the durable worker (``manage.py db_worker``)."""

from django.tasks import task


@task
def run_remote_operation(operation_id: int) -> None:
    # Imported here: the lifecycle module enqueues this task, so it imports this module.
    from .lifecycle import run

    run(operation_id)
