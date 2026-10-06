from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bootstrap", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="planrefusal",
            name="reason",
            field=models.CharField(
                choices=[
                    ("unsupported_platform", "Unsupported platform"),
                    ("privilege", "Privilege unavailable"),
                    ("package_health", "Package database needs attention"),
                    ("held_package", "Held package"),
                    ("apt_hook", "Unknown APT hook"),
                    ("apt_configuration", "Unsupported APT configuration"),
                    ("package_source", "Unqualified package source"),
                    ("package_metadata", "Package indexes unavailable"),
                    ("installed_package_change", "Installed package would change"),
                    ("customized", "Customized configuration"),
                    ("leftover", "Leftover configuration"),
                    ("service_unit", "Service unit needs attention"),
                    ("listener", "Conflicting listener"),
                    ("unsupported_version", "Unsupported release installed"),
                    ("conflict", "Conflicting installation"),
                    ("administration", "Administrative access not established"),
                    ("simulation", "Package simulation refused"),
                    ("incomplete", "Incomplete evidence"),
                    ("collision", "Existing resource"),
                    ("unsupported_layout", "Unsupported configuration layout"),
                    ("not_following", "Not following the convention"),
                    ("prerequisite", "Prerequisite missing"),
                    ("payload_too_large", "Too large to submit"),
                    ("partial_binding", "Incomplete database binding"),
                    ("existing_binding", "Existing database binding"),
                    ("automation", "Other certificate automation"),
                    ("destination", "Uncertain destination"),
                    ("authority", "Certificate authority refused"),
                ],
                max_length=30,
            ),
        ),
    ]
