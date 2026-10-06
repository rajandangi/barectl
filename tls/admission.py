"""Challenge route admission: an existing convention site gains its HTTP-01 route.

docs/tls.md#what-a-challenge-route-plan-reviews. The site itself is judged by site
admission, so a route is only proposed for a site that already matches the convention.
"""

from dataclasses import dataclass
from typing import override

from bootstrap import native as bootstrap_native
from bootstrap.models import ADMISSION_CENTISECONDS, Action, PlanEffect, PlanRefusal
from bootstrap.review import Draft
from sites import admission as site_admission
from sites.convention import (
    BACKUP_DIRECTORY,
    CHALLENGE_ROOT,
    CONVENTION_REVISION,
    WEB_USER,
    SitePaths,
    Stage,
    render_site,
)
from sites.inspection import PathState, SiteEvidence

from . import native

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind


@dataclass
class ChallengeDraft(Draft):
    identifier: str = ""
    names: tuple[str, ...] = ()
    paths: SitePaths | None = None
    ipv6: bool = False
    token: str = ""
    preimage: str = ""
    content: str = ""
    creates_letsencrypt: bool = False
    creates_backups: bool = False
    payload_bytes: int | None = None

    @property
    @override
    def revision(self) -> int:
        return CONVENTION_REVISION

    @property
    def proposes(self) -> bool:
        return bool(self.content)


def intent(identifier: str) -> str:
    return f"Serve HTTP-01 challenges for the site {identifier} from its own webroot."


def review(identifier: str, token: str, evidence: SiteEvidence) -> ChallengeDraft:
    draft = ChallengeDraft(
        Action.TLS_CHALLENGE,
        intent(identifier),
        evidence.platform,
        evidence.release,
        identifier=identifier,
        token=token,
    )
    site = site_admission.complete(draft, evidence, identifier, token)
    if site is None or not draft.eligible:
        return draft
    paths = evidence.paths
    if paths is None:
        return draft
    draft.paths = paths
    draft.names, draft.ipv6 = site.names, site.ipv6
    if site.stage.routes_challenges:
        draft.effects.append(
            (
                Effect.NO_CHANGES,
                (
                    f"No changes. The site {identifier} already serves HTTP-01 challenges from "
                    f"{paths.webroot}, as the convention specifies."
                ),
            )
        )
        return draft
    _parents(draft, evidence.states or {})
    if draft.refusals:
        return draft
    draft.preimage = evidence.contents.get(paths.source, "")
    draft.content = render_site(identifier, site.names, ipv6=site.ipv6, stage=Stage.CHALLENGE)
    _payload(draft, evidence.digest)
    if draft.eligible:
        _effects(draft)
    return draft


def _parents(draft: ChallengeDraft, states: dict[str, PathState]) -> None:
    """The webroot's and the backup's parents: absent, or root's with the convention's mode."""
    problems = []
    for path in ("/var/lib", "/var/backups"):
        state = states.get(path)
        if state is None or state.kind != "d" or state.owner != "root" or state.mode & 0o022:
            problems.append(f"{path} must be a directory owned by root that only root can write")
    for path, mode in ((CHALLENGE_ROOT, 0o755), (BACKUP_DIRECTORY, 0o700)):
        state = states.get(path)
        if state is None:
            problems.append(f"Barectl could not read {path}")
        elif state.present and (
            state.kind != "d" or (state.owner, state.group, state.mode) != ("root", "root", mode)
        ):
            problems.append(f"{path} must be a directory owned by root:root with mode {mode:04o}")
    if problems:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"{'; '.join(problems)}. Barectl creates the webroot and the recovery preimage only "
            "below root-controlled directories.",
        )
        return
    draft.creates_letsencrypt = not states[CHALLENGE_ROOT].present
    draft.creates_backups = not states[BACKUP_DIRECTORY].present


def _payload(draft: ChallengeDraft, digest: str) -> None:
    platform, paths = draft.platform, draft.paths
    if platform is None or platform.uptime_centiseconds is None or paths is None or not digest:
        draft.refuse(
            Reason.INCOMPLETE,
            "Barectl could not compute the site evidence digest that applying rechecks.",
        )
        return
    change = native.ChallengeChange(
        paths, draft.names, draft.ipv6, draft.token, digest, draft.preimage, draft.content
    )
    payload = native.challenge_payload(
        bootstrap_native.new_unit_name(),
        platform.boot_id,
        platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
        change,
    )
    draft.payload_bytes = len(payload.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            Reason.PAYLOAD_TOO_LARGE,
            f"Applying this route would need {draft.payload_bytes} bytes, more than the "
            f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run.",
        )


def _effects(draft: ChallengeDraft) -> None:
    paths = draft.paths
    if paths is None:
        return
    families = "IPv4 and IPv6" if draft.ipv6 else "IPv4"
    created = [
        path
        for path, creates in (
            (f"{CHALLENGE_ROOT} (root:root 0755, Certbot's own mode)", draft.creates_letsencrypt),
            (f"{BACKUP_DIRECTORY} (root:root 0700)", draft.creates_backups),
        )
        if creates
    ]
    parents = f" It also creates {' and '.join(created)}, absent now." if created else ""
    probe = paths.challenge_probe(draft.token)
    draft.effects.extend(
        [
            (
                Effect.CHALLENGE_ROUTE,
                (
                    f"Creates the webroot {paths.webroot} (root:{WEB_USER} 0750) and replaces "
                    f"{paths.source} with the site file below, which adds one location: requests "
                    f"under /.well-known/acme-challenge/ for {', '.join(draft.names)} are served "
                    f"as files from {paths.webroot} over {families}, 404 otherwise, never as PHP "
                    "and never as a directory listing. Every other request is served as before."
                    f"{parents}"
                ),
            ),
            (
                Effect.PREIMAGE_BACKUP,
                (
                    f"Before replacing it, copies the current {paths.source} to "
                    f"{BACKUP_DIRECTORY}/{paths.identifier}.conf.<unit> (root:root 0600), named "
                    "after the run's unit, which no Nginx include loads. The candidate is "
                    "staged beside the file and renamed over it only while the file still has "
                    "the reviewed bytes. If nginx -t refuses it, the backup is renamed back and "
                    "nothing is reloaded; the backup is kept either way."
                ),
            ),
            (
                Effect.SERVICE_RELOAD,
                (
                    "After nginx -t accepts the configuration, reloads nginx.service, whose old "
                    "workers finish their requests. A failed check is never followed by a reload."
                ),
            ),
            (
                Effect.ACCEPTANCE_PROBE,
                (
                    f"Writes the temporary file {probe} (root:root 0644) and requests it for each "
                    f"name over {families}; its .php name and the challenge directory must answer "
                    "404, and the site's front page its earlier status. The probe and the "
                    "directories written for it are then removed, if the probe's bytes still "
                    "match. A probe that cannot be removed makes the verification incomplete."
                ),
            ),
            (
                Effect.NO_ROLLBACK,
                (
                    "The webroot, backup, replacement and reload are not one transaction. After "
                    "the first change a failure is partial completion, recorded with its "
                    "boundary; Barectl never removes the webroot or the backup automatically."
                ),
            ),
        ]
    )
    draft.postconditions.extend(
        [
            f"{paths.source} has the reviewed bytes, root:root 0644; its link is unchanged.",
            f"{paths.webroot} is a directory owned by root:{WEB_USER} with mode 0750.",
            "The backup has the preimage's bytes, root:root 0600.",
            "nginx -t accepts the configuration and nginx.service is active.",
            "The temporary probe and its directories no longer exist.",
        ]
    )
