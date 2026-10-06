"""The test runner ``disposable/runner.py`` gives each native ``manage.py test``."""

from typing import override

from django.test.runner import DiscoverRunner

from bootstrap import apply

# Applies finish in seconds on a disposable server; a 2-second poll would wait out each one.
POLL_INTERVAL = 0.2


class NativeRunner(DiscoverRunner):
    @override
    def setup_test_environment(self, **kwargs: object) -> None:
        super().setup_test_environment(**kwargs)
        apply.POLL_INTERVAL = POLL_INTERVAL
