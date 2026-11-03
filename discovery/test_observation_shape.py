"""Observation rows attached to a snapshot keep typed columns (ADR 0003)."""

from django.apps import apps
from django.db import models
from django.test import SimpleTestCase

from discovery.models import DiscoverySnapshot

# Bounded values that belong to one row rather than observations of their own: the
# pre-rule offsite settings and a run's validated site-identifier list.
JSON_COLUMNS = frozenset(
    {
        ("backups.BackupObservation", "offsite"),
        ("backups.BackupObservation", "copy"),
        ("jobs.JobObservation", "sites"),
    }
)


class ObservationShapeTests(SimpleTestCase):
    def test_snapshot_observations_do_not_hide_rows_in_json_columns(self) -> None:
        offenders = {
            f"{model._meta.label}.{field.name}"
            for model in apps.get_models()
            for field in model._meta.fields
            if isinstance(field, models.JSONField)
            and (model._meta.label, field.name) not in JSON_COLUMNS
            and any(
                isinstance(item, models.ForeignKey) and item.remote_field.model is DiscoverySnapshot
                for item in model._meta.fields
            )
        }
        self.assertEqual(
            sorted(offenders),
            [],
            "store each observation in typed columns or a child table, never one JSON value",
        )
