import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("bootstrap", "0013_alter_planevidence_kind_packagephpdefault_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="PlanNodeRuntime",
            fields=[
                ("version", models.CharField(max_length=20)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                ("architecture", models.CharField(max_length=10)),
                ("digest", models.CharField(max_length=64)),
                ("default_before", models.CharField(blank=True, max_length=20)),
                ("pin_before", models.CharField(blank=True, max_length=20)),
                ("executable", models.CharField(max_length=200)),
                ("installs_runtime", models.BooleanField()),
                (
                    "plan",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="node_runtime",
                        serialize=False,
                        to="bootstrap.configurationplan",
                    ),
                ),
            ],
            options={
                "abstract": False,
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="RunNodeRuntime",
            fields=[
                ("version", models.CharField(max_length=20)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                ("architecture", models.CharField(max_length=10)),
                ("digest", models.CharField(max_length=64)),
                ("default_before", models.CharField(blank=True, max_length=20)),
                ("pin_before", models.CharField(blank=True, max_length=20)),
                ("executable", models.CharField(max_length=200)),
                ("installs_runtime", models.BooleanField()),
                (
                    "run",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="node_runtime",
                        serialize=False,
                        to="bootstrap.applyrun",
                    ),
                ),
            ],
            options={
                "abstract": False,
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="RuntimeRequest",
            fields=[
                (
                    "preparation",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="node_request",
                        serialize=False,
                        to="bootstrap.planpreparation",
                    ),
                ),
                ("version", models.CharField(max_length=20)),
                ("identifier", models.CharField(blank=True, max_length=24)),
            ],
            options={
                "default_permissions": (),
            },
        ),
    ]
