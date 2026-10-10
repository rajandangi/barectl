import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bootstrap", "0013_alter_planevidence_kind_packagephpdefault_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="PackagePhpDefaultRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
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
    ]
