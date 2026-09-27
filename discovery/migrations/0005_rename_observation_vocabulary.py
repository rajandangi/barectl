# Renames discovery observation models and fields to the vocabulary in CONTEXT.md.
# Rename-only: every row and stored value is kept.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("discovery", "0004_discoverysnapshot_pools_source_and_more"),
    ]

    operations = [
        migrations.RenameModel(old_name="ServiceObservation", new_name="ComponentObservation"),
        migrations.RenameModel(old_name="SiteObservation", new_name="NginxSiteObservation"),
        migrations.RenameModel(old_name="PoolObservation", new_name="PhpFpmPoolObservation"),
        migrations.AlterField(
            model_name="componentobservation",
            name="snapshot",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="components",
                to="discovery.discoverysnapshot",
            ),
        ),
        migrations.AlterField(
            model_name="nginxsiteobservation",
            name="snapshot",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="nginx_site_files",
                to="discovery.discoverysnapshot",
            ),
        ),
        migrations.AlterField(
            model_name="phpfpmpoolobservation",
            name="snapshot",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="php_fpm_pools",
                to="discovery.discoverysnapshot",
            ),
        ),
        migrations.RenameField(
            model_name="discoverysnapshot",
            old_name="sites_status",
            new_name="nginx_site_files_status",
        ),
        migrations.RenameField(
            model_name="discoverysnapshot",
            old_name="sites_source",
            new_name="nginx_site_files_source",
        ),
        migrations.RenameField(
            model_name="discoverysnapshot",
            old_name="sites_warning",
            new_name="nginx_site_files_warning",
        ),
        migrations.RenameField(
            model_name="discoverysnapshot",
            old_name="pools_status",
            new_name="php_fpm_pools_status",
        ),
        migrations.RenameField(
            model_name="discoverysnapshot",
            old_name="pools_source",
            new_name="php_fpm_pools_source",
        ),
        migrations.RenameField(
            model_name="discoverysnapshot",
            old_name="pools_warning",
            new_name="php_fpm_pools_warning",
        ),
        migrations.RemoveConstraint(
            model_name="nginxsiteobservation", name="unique_site_per_snapshot"
        ),
        migrations.AddConstraint(
            model_name="nginxsiteobservation",
            constraint=models.UniqueConstraint(
                fields=("snapshot", "name"), name="unique_nginx_site_file_per_snapshot"
            ),
        ),
        migrations.RemoveConstraint(
            model_name="phpfpmpoolobservation", name="unique_pool_per_snapshot"
        ),
        migrations.AddConstraint(
            model_name="phpfpmpoolobservation",
            constraint=models.UniqueConstraint(
                fields=("snapshot", "version", "name"),
                name="unique_php_fpm_pool_per_snapshot",
            ),
        ),
    ]
