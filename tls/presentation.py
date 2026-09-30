"""What a challenge route plan's review shows beside the common plan facts."""

from dataclasses import dataclass

from bootstrap.models import ConfigurationPlan
from sites.convention import BACKUP_DIRECTORY, CHALLENGE_ROOT, WEB_USER, SitePaths

from .models import PlanChallenge


@dataclass(frozen=True)
class ChallengeReview:
    challenge: PlanChallenge
    paths: SitePaths

    @property
    def names(self) -> tuple[str, ...]:
        return self.challenge.name_list

    @property
    def directories(self) -> list[tuple[str, str, str]]:
        """Each directory the run creates, with its owner and mode."""
        created = []
        if self.challenge.creates_letsencrypt:
            created.append((CHALLENGE_ROOT, "root:root", "0755"))
        created.append((self.paths.webroot, f"root:{WEB_USER}", "0750"))
        if self.challenge.creates_backups:
            created.append((BACKUP_DIRECTORY, "root:root", "0700"))
        return created

    @property
    def backup(self) -> str:
        return f"{BACKUP_DIRECTORY}/{self.paths.identifier}.conf.<unit>"

    @property
    def authority(self) -> str:
        """docs/tls.md#permissions"""
        return (
            "Viewing needs Barectl's permission to view TLS plans, preparing its permission to "
            "prepare them, and applying its permission to apply them; site and bootstrap "
            "permissions grant none of these. On the server, preparation read as root or "
            "through noninteractive sudo; applying needs the same for systemd-run and for the "
            "read that verifies the route afterwards."
        )


def challenge_review(plan: ConfigurationPlan) -> ChallengeReview | None:
    challenge = PlanChallenge.objects.filter(plan=plan).first()
    if challenge is None:
        return None
    return ChallengeReview(challenge, SitePaths(challenge.identifier, challenge.php_version))
