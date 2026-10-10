import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bootstrap", "0014_packagephpdefaultrequest"),
        ("discovery", "0003_application_observations"),
        ("node_runtimes", "0001_initial"),
        ("servers", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="NodeRuntimeSnapshot",
            fields=[
                (
                    "snapshot",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="node_runtime",
                        serialize=False,
                        to="discovery.discoverysnapshot",
                    ),
                ),
                ("default", models.CharField(blank=True, max_length=20)),
                ("installed", models.TextField(blank=True)),
                ("site_pins", models.TextField(blank=True)),
                ("failure", models.TextField(blank=True)),
            ],
            options={
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="RuntimeChange",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("version", models.CharField(max_length=20)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                ("ssh_alias", models.CharField(max_length=253)),
                ("host_key", models.CharField(blank=True, max_length=200)),
                ("status", models.CharField(default="active", max_length=12)),
                ("failure", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(null=True)),
                (
                    "requested_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="node_runtime_changes",
                        to="servers.server",
                    ),
                ),
            ],
            options={
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="RuntimeChangeStep",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("position", models.PositiveSmallIntegerField()),
                (
                    "change",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="steps",
                        to="node_runtimes.runtimechange",
                    ),
                ),
                (
                    "preparation",
                    models.OneToOneField(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="bootstrap.planpreparation",
                    ),
                ),
                (
                    "run",
                    models.OneToOneField(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="bootstrap.applyrun",
                    ),
                ),
            ],
            options={
                "default_permissions": (),
            },
        ),
        migrations.AddConstraint(
            model_name="runtimechange",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status", "active")),
                fields=("server",),
                name="one_active_node_runtime_change",
            ),
        ),
        migrations.AddConstraint(
            model_name="runtimechangestep",
            constraint=models.UniqueConstraint(
                fields=("change", "position"), name="one_step_per_node_runtime_change"
            ),
        ),
    ]
