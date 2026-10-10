"""docs/adr/0035-one-change-engine-with-effect-derived-consent.md: the Viewer, Site operator
and Administrator presets, granted to accounts from the terminal."""

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor

# (app label, model, codename, name); Django names the default permissions the same way.
VIEWER = (
    ("servers", "server", "view_server", "Can view server"),
    ("operations", "remoteoperation", "view_site", "Can view sites"),
    ("operations", "remoteoperation", "view_evidence", "Can view native evidence"),
)
SITE_OPERATOR = (
    *VIEWER,
    ("discovery", "discoveryattempt", "add_discoveryattempt", "Can add discovery attempt"),
    ("operations", "remoteoperation", "prepare_change", "Can prepare changes"),
    (
        "operations",
        "remoteoperation",
        "apply_site_change",
        "Can apply changes confined to one site",
    ),
)
ADMINISTRATOR = (
    *SITE_OPERATOR,
    ("servers", "server", "add_server", "Can add server"),
    ("servers", "server", "change_server", "Can change server"),
    ("servers", "server", "delete_server", "Can delete server"),
    (
        "operations",
        "remoteoperation",
        "apply_shared_change",
        "Can apply changes that affect shared services",
    ),
    (
        "operations",
        "remoteoperation",
        "apply_destructive_change",
        "Can apply changes that lose data",
    ),
)
PRESETS = {"Viewer": VIEWER, "Site operator": SITE_OPERATOR, "Administrator": ADMINISTRATOR}


def create_presets(apps: Apps, _schema_editor: BaseDatabaseSchemaEditor) -> None:
    # Permissions are otherwise created only after every migration has run.
    content_type_model = apps.get_model("contenttypes", "ContentType")
    group_model = apps.get_model("auth", "Group")
    permission_model = apps.get_model("auth", "Permission")
    for name, granted in PRESETS.items():
        group, _ = group_model.objects.get_or_create(name=name)
        permissions = []
        for label, model, codename, title in granted:
            content_type, _ = content_type_model.objects.get_or_create(app_label=label, model=model)
            permission, _ = permission_model.objects.get_or_create(
                content_type=content_type, codename=codename, defaults={"name": title}
            )
            permissions.append(permission)
        group.permissions.set(permissions)


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("contenttypes", "0002_remove_content_type_name"),
        ("discovery", "0001_initial"),
        ("operations", "0001_initial"),
        ("servers", "0001_initial"),
    ]

    operations = [migrations.RunPython(create_presets, migrations.RunPython.noop)]
