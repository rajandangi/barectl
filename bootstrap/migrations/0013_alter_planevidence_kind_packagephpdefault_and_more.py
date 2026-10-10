import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bootstrap", "0012_alter_applyrun_action_alter_configurationplan_action_and_more"),
        ("servers", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="planevidence",
            name="kind",
            field=models.CharField(
                choices=[
                    ("php_source_recheck", "PHP source evidence rechecked before applying"),
                    ("platform", "Platform and boot"),
                    ("privilege", "Privilege"),
                    ("apt_configuration", "Effective APT configuration"),
                    ("apt_hooks", "APT hooks"),
                    ("apt_sources", "APT sources"),
                    ("apt_preferences", "APT preferences"),
                    ("package_indexes", "Package indexes"),
                    ("dpkg_status", "Relevant package states"),
                    ("package_holds", "Package holds"),
                    ("auto_marks", "Automatic installation marks"),
                    ("simulation", "APT simulation"),
                    ("web_configuration", "Web-stack configuration"),
                    ("service_units", "Service units"),
                    ("listeners", "Listeners"),
                    ("administration", "Administrative access"),
                    ("data_paths", "Data directories and option files"),
                    ("apt_revalidation", "APT evidence rechecked before applying"),
                    ("retained_units", "Retained bootstrap units"),
                    (
                        "package_revalidation",
                        "Package and service evidence rechecked before applying",
                    ),
                    ("site_revalidation", "Site evidence rechecked before applying"),
                    ("renewal_revalidation", "Renewal evidence rechecked before applying"),
                    ("node_revalidation", "Node evidence rechecked before applying"),
                    ("wpcli_revalidation", "WP-CLI evidence rechecked before applying"),
                    ("external_reads", "Fresh DNS, addresses, clock and directory reads"),
                    ("lineage_revalidation", "Certificate lineage rechecked before applying"),
                    ("readiness_recheck", "Readiness reads rechecked before applying"),
                    ("nginx_closure", "Nginx configuration"),
                    ("fpm_closure", "PHP-FPM configuration"),
                    ("accounts", "Accounts and groups"),
                    ("allocation", "Account allocation policy"),
                    ("site_paths", "Site paths and ancestors"),
                    ("catalog", "Database catalog"),
                    (
                        "catalog_revalidation",
                        "Database catalog rechecked before and during applying",
                    ),
                    ("catalog_after", "Database catalog after applying"),
                    ("driver", "PHP driver rechecked before applying"),
                    ("wordpress_files", "Application files and capacity rechecked"),
                    ("wordpress_database", "Application database rechecked"),
                    ("wordpress_runtime", "Selected CLI and PHP-FPM capabilities"),
                    ("wordpress_state", "Application configuration, core and extensions"),
                ],
                max_length=20,
            ),
        ),
        migrations.CreateModel(
            name="PackagePhpDefault",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("branch", models.CharField(max_length=3)),
                ("fingerprint", models.CharField(max_length=64)),
                (
                    "plan",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="bootstrap.configurationplan",
                    ),
                ),
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
                ("action", models.CharField(max_length=30)),
                ("branch", models.CharField(max_length=3)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                ("ssh_alias", models.CharField(max_length=253)),
                ("host_key", models.CharField(blank=True, max_length=200)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Changing runtime"),
                            ("succeeded", "Runtime verified"),
                            ("failed", "Runtime change stopped"),
                        ],
                        default="active",
                        max_length=12,
                    ),
                ),
                ("failure", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(null=True)),
                (
                    "requested_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="servers.server"
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
                        to="bootstrap.runtimechange",
                    ),
                ),
                (
                    "preparation",
                    models.OneToOneField(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="bootstrap.planpreparation",
                    ),
                ),
                (
                    "run",
                    models.OneToOneField(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="bootstrap.applyrun",
                    ),
                ),
            ],
            options={
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="RuntimePlan",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("branch", models.CharField(max_length=3)),
                ("before_branch", models.CharField(blank=True, max_length=3)),
                ("before_mode", models.CharField(blank=True, max_length=6)),
                ("default_digest", models.CharField(max_length=64)),
                ("source_digest", models.CharField(blank=True, max_length=64)),
                ("package_action", models.CharField(blank=True, max_length=30)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                ("old_branch", models.CharField(blank=True, max_length=3)),
                ("old_revision", models.PositiveSmallIntegerField(default=4)),
                ("site_digest", models.CharField(blank=True, max_length=64)),
                ("old_site", models.TextField(blank=True)),
                ("new_site", models.TextField(blank=True)),
                ("old_pool", models.TextField(blank=True)),
                ("new_pool", models.TextField(blank=True)),
                ("names", models.TextField(blank=True)),
                ("token", models.CharField(blank=True, max_length=32)),
                ("body_sha256", models.CharField(blank=True, max_length=64)),
                (
                    "plan",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runtime",
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
            name="RuntimeRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("branch", models.CharField(max_length=3)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                (
                    "preparation",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE, to="bootstrap.planpreparation"
                    ),
                ),
            ],
            options={
                "default_permissions": (),
            },
        ),
        migrations.CreateModel(
            name="RuntimeRun",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("branch", models.CharField(max_length=3)),
                ("before_branch", models.CharField(blank=True, max_length=3)),
                ("before_mode", models.CharField(blank=True, max_length=6)),
                ("default_digest", models.CharField(max_length=64)),
                ("source_digest", models.CharField(blank=True, max_length=64)),
                ("package_action", models.CharField(blank=True, max_length=30)),
                ("identifier", models.CharField(blank=True, max_length=24)),
                ("old_branch", models.CharField(blank=True, max_length=3)),
                ("old_revision", models.PositiveSmallIntegerField(default=4)),
                ("site_digest", models.CharField(blank=True, max_length=64)),
                ("old_site", models.TextField(blank=True)),
                ("new_site", models.TextField(blank=True)),
                ("old_pool", models.TextField(blank=True)),
                ("new_pool", models.TextField(blank=True)),
                ("names", models.TextField(blank=True)),
                ("token", models.CharField(blank=True, max_length=32)),
                ("body_sha256", models.CharField(blank=True, max_length=64)),
                (
                    "run",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runtime",
                        to="bootstrap.applyrun",
                    ),
                ),
            ],
            options={
                "abstract": False,
                "default_permissions": (),
            },
        ),
        migrations.AddConstraint(
            model_name="runtimechange",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status", "active")),
                fields=("server",),
                name="one_active_php_runtime_change",
            ),
        ),
        migrations.AddConstraint(
            model_name="runtimechangestep",
            constraint=models.UniqueConstraint(
                fields=("change", "position"), name="one_step_per_runtime_change"
            ),
        ),
    ]
