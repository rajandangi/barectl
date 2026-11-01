from dataclasses import replace
from typing import cast

from django.test import SimpleTestCase

from databases.packages import parse_simulation
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import Consent
from security.observation import PendingUpdate, UpdatesState
from security.presentation import UPDATES_DISCLOSURE
from security.updates import (
    CHECK_SLUG,
    INSTALL_SLUG,
    SiteTarget,
    UpdatesEvidence,
    check_body,
    install_body,
    review_check,
    review_install,
)

BOOT_ID = "0123456789abcdef0123456789abcdef"
DIGEST = "a" * 64
UPDATE = """\
Inst tzdata [2026a-3ubuntu1] (2026c-0ubuntu0.26.04.1 Ubuntu:26.04/resolute-security [all])
Conf tzdata (2026c-0ubuntu0.26.04.1 Ubuntu:26.04/resolute-security [all])
Inst libssl3t64 [3.5.5-1ubuntu3] (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
Conf libssl3t64 (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
Inst openssl (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
Conf openssl (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
2 upgraded, 1 newly installed, 0 to remove and 1 not upgraded.
"""


def pending(
    name: str = "tzdata",
    installed: str = "2026a-3ubuntu1",
    candidate: str = "2026c-0ubuntu0.26.04.1",
    archive: str = "resolute-security/main",
    classification: str = "security",
) -> PendingUpdate:
    return PendingUpdate(name, installed, candidate, archive, classification)


def evidence(
    *,
    pending_updates: tuple[PendingUpdate, ...] | None = None,
    simulation: str = UPDATE,
    held: tuple[str, ...] = (),
    conffiles: tuple[tuple[str, str], ...] = (),
    audit: tuple[str, ...] = (),
) -> UpdatesEvidence:
    return UpdatesEvidence(
        standing="Target stack",
        machine="x86_64",
        deb_arch="amd64",
        boot_id=BOOT_ID,
        uptime_centiseconds=500000,
        apt="apt 3.2.0 (amd64)",
        dpkg="Debian 'dpkg' package management program version 1.23.1 (amd64).",
        systemd="systemd 259 (259-1ubuntu1)",
        held=held,
        disk_bytes=10 * 1024**3,
        memory_kib=1024 * 1024,
        state=UpdatesState(
            3600,
            pending_updates
            if pending_updates is not None
            else (
                pending(),
                pending(
                    "libssl3t64",
                    "3.5.5-1ubuntu3",
                    "3.5.5-1ubuntu3.7",
                ),
            ),
        ),
        update_warning="",
        sites=("alpha", "beta"),
        cache_sites=("alpha",),
        targets=(
            SiteTarget("alpha.example.com", "/", True),
            SiteTarget("beta.example.com", "/health", False),
        ),
        services=(
            ("mariadb.service", "active"),
            ("valkey-server.service", "active"),
            ("ssh.service", "active"),
            ("ssh.socket", "active"),
        ),
        conffiles=conffiles,
        audit=audit,
        precondition_digest=DIGEST,
        simulation=parse_simulation(simulation),
    )


class UpdatesReviewTests(SimpleTestCase):
    def test_check_for_updates_is_a_shared_server_change_naming_the_sites(self) -> None:
        draft = review_check(evidence(), PreparationInputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.kind, CHECK_SLUG)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertEqual(draft.current_sites, ("alpha", "beta"))
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(draft.stages, ("preflight", "refresh", "verify"))

    def test_install_security_names_every_upgrade_its_version_and_new_dependency(self) -> None:
        draft = review_install(evidence(), PreparationInputs("security"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.kind, INSTALL_SLUG)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertIn("tzdata 2026c-0ubuntu0.26.04.1", draft.effects[0].text)
        self.assertIn("libssl3t64 3.5.5-1ubuntu3.7", draft.effects[0].text)
        self.assertIn("New dependencies: openssl", draft.effects[0].text)
        self.assertIn(UPDATES_DISCLOSURE, draft.effects[0].text)
        self.assertEqual(
            draft.document["roots"],
            [
                ["libssl3t64", "3.5.5-1ubuntu3.7"],
                ["tzdata", "2026c-0ubuntu0.26.04.1"],
            ],
        )
        details = {
            row["label"]: row["value"]
            for row in cast(list[dict[str, str]], draft.document["details"])
        }
        self.assertIn("openssl", details["New dependencies"])
        self.assertIn("Database (mariadb.service): alpha, beta", details["Restarted services"])
        self.assertIn("Object cache (valkey-server.service): alpha", details["Restarted services"])
        self.assertIn("SSH (ssh.service): no sites", details["Restarted services"])

    def test_install_all_excludes_kept_waiting_updates_and_names_them(self) -> None:
        rows = (
            pending(),
            pending("libssl3t64", "3.5.5-1ubuntu3", "3.5.5-1ubuntu3.7"),
            pending("logrotate", "3.22.0-1build1", "3.22.0-2", "resolute/main", "other"),
            pending("openssl", "1", "kept", "resolute/main", "phased"),
            pending("held-package", "1", "2", "resolute-security/main", "held"),
        )
        simulation = UPDATE.replace(
            "Inst tzdata",
            "Inst logrotate [3.22.0-1build1] (3.22.0-2 Ubuntu:26.04/resolute [amd64])\n"
            "Conf logrotate (3.22.0-2 Ubuntu:26.04/resolute [amd64])\nInst tzdata",
        ).replace(
            "2 upgraded, 1 newly installed",
            "3 upgraded, 1 newly installed",
        )
        draft = review_install(
            evidence(pending_updates=rows, simulation=simulation),
            PreparationInputs("all"),
        )
        details = {
            row["label"]: row["value"]
            for row in cast(list[dict[str, str]], draft.document["details"])
        }
        self.assertIn("logrotate 3.22.0-2", details["Packages"])
        self.assertIn("openssl is waiting for Ubuntu's rollout", details["Kept waiting"])
        self.assertIn("held-package is held by an administrator", details["Kept waiting"])

    def test_no_waiting_updates_is_no_change_with_a_plain_note(self) -> None:
        draft = review_install(evidence(pending_updates=()), PreparationInputs("security"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertEqual(draft.document["note"], "No security updates are waiting.")

    def test_a_hold_in_the_transaction_refuses(self) -> None:
        draft = review_install(evidence(held=("tzdata",)), PreparationInputs("security"))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("held with apt-mark hold" in reason for reason in draft.refusals))

    def test_a_modified_conffile_in_the_transaction_refuses(self) -> None:
        draft = review_install(
            evidence(conffiles=(("libssl3t64", "/etc/ssl/openssl.cnf"),)),
            PreparationInputs("security"),
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("configuration file" in reason for reason in draft.refusals))

    def test_a_modified_conffile_of_another_package_does_not_refuse(self) -> None:
        draft = review_install(
            evidence(conffiles=(("unrelated-package", "/etc/unrelated.conf"),)),
            PreparationInputs("security"),
        )
        self.assertTrue(draft.eligible, draft.refusals)

    def test_a_downgrade_refuses(self) -> None:
        draft = review_install(
            replace(evidence(), downgrades=("tzdata",)),
            PreparationInputs("security"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("downgraded", " ".join(draft.refusals))

    def test_an_unfinished_package_state_refuses(self) -> None:
        draft = review_install(
            evidence(audit=("unpacked but not configured",)), PreparationInputs("security")
        )
        self.assertFalse(draft.eligible)
        self.assertIn("unfinished package state", " ".join(draft.refusals))

    def test_an_update_from_another_archive_refuses(self) -> None:
        draft = review_install(
            evidence(pending_updates=(pending(archive="example/main"),)),
            PreparationInputs("security"),
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("not the Ubuntu 26.04 archive" in reason for reason in draft.refusals))

    def test_an_extra_upgrade_refuses(self) -> None:
        # The simulation upgrades libssl3t64 as well, while only tzdata is a selected
        # pending update.
        draft = review_install(
            evidence(pending_updates=(pending(),)), PreparationInputs("security")
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("would also upgrade libssl3t64" in reason for reason in draft.refusals))

    def test_a_removal_refuses(self) -> None:
        simulation = (
            UPDATE.replace(
                "2 upgraded, 1 newly installed, 0 to remove and 1 not upgraded.",
                "2 upgraded, 1 newly installed, 1 to remove and 1 not upgraded.",
            )
            + "Remv openssl [3.5.5-1ubuntu3]\n"
        )
        draft = review_install(evidence(simulation=simulation), PreparationInputs("security"))
        self.assertFalse(draft.eligible)
        self.assertIn("remove openssl", " ".join(draft.refusals))

    def test_the_body_admits_only_the_reviewed_upgrade_guard(self) -> None:
        draft = review_install(evidence(), PreparationInputs("security"))
        body = install_body(draft.document, BodyContext("", "", 0))
        self.assertIn(b"precondition_digest()", body.source)
        self.assertEqual(body.arguments[0], "security")
        self.assertEqual(body.arguments[1], DIGEST)
        self.assertIn("tzdata=2026c-0ubuntu0.26.04.1", body.arguments[2])
        self.assertIn("U tzdata 2026a-3ubuntu1 all", body.arguments[3])
        self.assertIn("openssl", body.arguments[4])

    def test_a_tampered_install_selection_refuses(self) -> None:
        draft = review_install(evidence(), PreparationInputs("security"))
        document = {**draft.document, "selection": "everything"}
        with self.assertRaisesMessage(ValueError, "not a valid immutable selection"):
            install_body(document, BodyContext("", "", 0))

    def test_a_tampered_check_document_refuses(self) -> None:
        draft = review_check(evidence(), PreparationInputs())
        document = {**draft.document, "body_sha256": "b" * 64}
        with self.assertRaisesMessage(ValueError, "not a valid immutable selection"):
            check_body(document, BodyContext("", "", 0))
