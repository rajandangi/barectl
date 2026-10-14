from django.test import SimpleTestCase

from .configuration import render, validate


class MasterConfigurationTests(SimpleTestCase):
    def test_missing_shared_cache_protection_is_refused(self) -> None:
        files = render("php84")
        self.assertIn("opcache.validate_permission=1", files.ini)
        with self.assertRaises(ValueError):
            validate(files.ini.replace("opcache.validate_permission=1\n", ""))
        self.assertNotIn("PHP_INI_SCAN_DIR", files.unit)
        self.assertIn("pm = ondemand", files.pool)
        self.assertIn("listen.mode = 0600", files.pool)
        self.assertNotIn("php_admin_value[opcache", files.pool)
