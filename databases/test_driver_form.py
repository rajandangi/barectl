"""Driver controls remain distinct from bootstrap controls on Setup."""

import re

from bootstrap.models import Action, PlanPreparation
from servers.testing import HTMX_FRAGMENT
from sites.fakes import SiteTestCase


class DriverFormTests(SiteTestCase):
    def test_setup_controls_have_unique_ids_and_matching_labels(self) -> None:
        self.sign_in_with(
            "view_server",
            "view_configurationplan",
            "prepare_configurationplan",
            "view_databaseplan",
            "prepare_databaseplan",
        )
        response = self.client.get(f"/servers/{self.server.pk}/setup/")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        identifiers = re.findall(r'\bid="([^"]+)"', content)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for name in ("php_version", "php_supply"):
            self.assertContains(response, f'id="id_driver_{name}"')
            self.assertContains(response, f'for="id_driver_{name}"')
            self.assertContains(response, f'name="{name}"')

    def test_invalid_choices_render_errors_associated_with_the_driver_controls(self) -> None:
        self.sign_in_with("view_server", "view_databaseplan", "prepare_databaseplan")
        response = self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {
                "action": Action.PHP_MYSQL,
                "family": "drivers",
                "php_version": "9.9",
                "php_supply": "other",
            },
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 422)
        self.assertFalse(PlanPreparation.objects.exists())
        for name in ("php_version", "php_supply"):
            self.assertContains(response, f'id="id_driver_{name}_error"', status_code=422)
            self.assertContains(
                response, f'aria-describedby="id_driver_{name}_error"', status_code=422
            )
            self.assertContains(response, f'for="id_driver_{name}"', status_code=422)
