"""The view-evidence permission: reading a site's logs is separate from applying changes.

Viewers keep viewing changes and sites but do not read log content; Site operators and
Administrators do (Phase C #389, docs/logs.md#permission).
"""

from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.db.migrations.state import StateApps

CODENAME = "view_evidence"
LABEL = "Can view evidence"
GRANTED_PRESETS = ("Site operator", "Administrator")


def grant(apps: StateApps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    database = schema_editor.connection.alias
    content_type = (
        apps.get_model("contenttypes", "ContentType")
        .objects.using(database)
        .get(app_label="operations", model="changereview")
    )
    permission, _ = (
        apps.get_model("auth", "Permission")
        .objects.using(database)
        .get_or_create(
            content_type=content_type,
            codename=CODENAME,
            defaults={"name": LABEL},
        )
    )
    groups = (
        apps.get_model("auth", "Group").objects.using(database).filter(name__in=GRANTED_PRESETS)
    )
    for group in groups:
        group.permissions.add(permission)


def withdraw(apps: StateApps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    database = schema_editor.connection.alias
    apps.get_model("auth", "Permission").objects.using(database).filter(
        content_type__app_label="operations", codename=CODENAME
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("operations", "0003_alter_changereview_options_and_more"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.RunPython(grant, withdraw),
    ]
