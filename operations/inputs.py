"""Versioned, non-secret preparation selection, validated before opening SSH."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

INVALID_INPUTS = "Barectl refused invalid preparation inputs. Prepare a new review."


class InputShape(StrEnum):
    SELECTION = "selection"
    SITE_CREATE = "site_create"
    WORDPRESS_CREATE = "wordpress_create"
    LARAVEL_CREATE = "laravel_create"
    SITE_RUNTIME = "site_runtime"
    SITE_READINESS = "site_readiness"
    SITE_DATABASE = "site_database"
    LARAVEL_DEPLOY = "laravel_deploy"
    LARAVEL_ROLLBACK = "laravel_rollback"
    DATABASE_ENGINE = "database_engine"


@dataclass(frozen=True)
class PreparationInputs:
    selection: str = ""
    identifier: str = ""
    names: tuple[str, ...] = ()
    # The retained release a Roll back selects; empty for every other kind.
    release: str = ""
    # The site's Deploy switch: pending migrations run only when this is true.
    migrations: bool = True
    # Whether a created site is served over HTTPS. The dashboard passes True; the native
    # scenarios and the change kind's own default keep sites HTTP-only unless asked.
    https: bool = False
    # The site's readiness path, for the one kind that changes it; empty otherwise.
    readiness: str = ""
    # A database engine request that installs Git in the same reviewed transaction.
    git: bool = False
    # A Create Laravel site request: the repository locator, its branch or tag, and the
    # repository host's pasted fingerprint for an SSH locator (Phase B #382).
    repository: str = ""
    branch: str = ""
    fingerprint: str = ""
    # A Create WordPress site request: the site title, administrator username and email.
    # The administrator password travels only through the confidential input channel.
    title: str = ""
    admin_username: str = ""
    admin_email: str = ""

    def _wordpress_document(self) -> dict[str, object]:
        return {
            "version": 1,
            "selection": self.selection,
            "identifier": self.identifier,
            "names": list(self.names),
            "https": self.https,
            "title": self.title,
            "admin_username": self.admin_username,
            "admin_email": self.admin_email,
        }

    def _laravel_document(self) -> dict[str, object]:
        laravel: dict[str, object] = {
            "version": 1,
            "selection": self.selection,
            "identifier": self.identifier,
            "names": list(self.names),
            "https": self.https,
            "repository": self.repository,
            "branch": self.branch,
        }
        if self.fingerprint:
            laravel["fingerprint"] = self.fingerprint
        return laravel

    def document(self) -> dict[str, object]:
        if self.repository:
            return self._laravel_document()
        if self.title:
            return self._wordpress_document()
        return self._other_document()

    def _other_document(self) -> dict[str, object]:
        if self.release:
            return {"version": 1, "identifier": self.identifier, "release": self.release}
        if self.readiness:
            return {
                "version": 1,
                "identifier": self.identifier,
                "readiness": self.readiness,
            }
        if self.identifier and not self.names:
            if not self.selection:
                value: dict[str, object] = {"version": 1, "identifier": self.identifier}
                if not self.migrations:
                    value["migrations"] = False
                return value
            return {"version": 1, "selection": self.selection, "identifier": self.identifier}
        if self.identifier:
            return {
                "version": 1,
                "selection": self.selection,
                "identifier": self.identifier,
                "names": list(self.names),
                "https": self.https,
            }
        if not self.selection:
            return {"version": 1}
        selection: dict[str, object] = {"version": 1, "selection": self.selection}
        if self.git:
            selection["git"] = True
        return selection


EMPTY_INPUTS = PreparationInputs()


def empty_inputs() -> dict[str, object]:
    return {"version": 1}


def decode_inputs(
    value: object, choices: tuple[str, ...], shape: InputShape = InputShape.SELECTION
) -> PreparationInputs:
    if (
        not isinstance(value, dict)
        or type(value.get("version")) is not int
        or value["version"] != 1
    ):
        raise ValueError(INVALID_INPUTS)
    if shape == InputShape.SELECTION:
        return _selection_inputs(value, choices)
    return _DECODERS[shape](value, choices)


def _selection_inputs(value: dict[str, object], choices: tuple[str, ...]) -> PreparationInputs:
    if not choices:
        if set(value) != {"version"}:
            raise ValueError(INVALID_INPUTS)
        return PreparationInputs()
    if set(value) != {"version", "selection"}:
        raise ValueError(INVALID_INPUTS)
    selection = value["selection"]
    if not isinstance(selection, str) or selection not in choices:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(selection)


def _site_inputs(value: dict[str, object], choices: tuple[str, ...]) -> PreparationInputs:
    from sites.names import request

    if set(value) not in (
        {"version", "selection", "identifier", "names"},
        {"version", "selection", "identifier", "names", "https"},
    ):
        raise ValueError(INVALID_INPUTS)
    identifier, names, selection = value["identifier"], value["names"], value["selection"]
    https = value.get("https", False)
    if (
        not isinstance(identifier, str)
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(selection, str)
        or selection not in choices
        or type(https) is not bool
    ):
        raise ValueError(INVALID_INPUTS)
    try:
        identifier, canonical = request(identifier, " ".join(names))
    except ValueError as error:
        raise ValueError(INVALID_INPUTS) from error
    if list(canonical) != names:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(selection, identifier, canonical, https=https)


def _laravel_create_inputs(value: dict[str, object], choices: tuple[str, ...]) -> PreparationInputs:
    from laravel.configuration import repository_locator, repository_ref, valid_fingerprint
    from sites.names import request

    required = {"version", "selection", "identifier", "names", "https", "repository", "branch"}
    if set(value) not in (required, required | {"fingerprint"}):
        raise ValueError(INVALID_INPUTS)
    identifier, names, selection = value["identifier"], value["names"], value["selection"]
    https, repository, branch = value.get("https", False), value["repository"], value["branch"]
    fingerprint = value.get("fingerprint", "")
    if (
        not isinstance(identifier, str)
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(selection, str)
        or selection not in choices
        or type(https) is not bool
        or not isinstance(repository, str)
        or not isinstance(branch, str)
        or not isinstance(fingerprint, str)
    ):
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, canonical_names = request(identifier, " ".join(names))
        locator = repository_locator(repository)
        ref = repository_ref(branch)
    except ValueError as error:
        raise ValueError(INVALID_INPUTS) from error
    if canonical != identifier or list(canonical_names) != names:
        raise ValueError(INVALID_INPUTS)
    ssh = not locator.startswith("https://")
    if fingerprint and not valid_fingerprint(fingerprint):
        raise ValueError(INVALID_INPUTS)
    if ssh and not fingerprint:
        raise ValueError(INVALID_INPUTS)
    if not ssh and fingerprint:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(
        selection,
        identifier,
        canonical_names,
        https=https,
        repository=locator,
        branch=ref,
        fingerprint=fingerprint,
    )


def _wordpress_create_inputs(
    value: dict[str, object], choices: tuple[str, ...]
) -> PreparationInputs:
    from sites.names import request

    required = {
        "version",
        "selection",
        "identifier",
        "names",
        "https",
        "title",
        "admin_username",
        "admin_email",
    }
    if set(value) != required:
        raise ValueError(INVALID_INPUTS)
    identifier, names, selection = value["identifier"], value["names"], value["selection"]
    https = value.get("https", False)
    title, admin_username, admin_email = (
        value["title"],
        value["admin_username"],
        value["admin_email"],
    )
    if (
        not isinstance(identifier, str)
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(selection, str)
        or selection not in choices
        or type(https) is not bool
        or not isinstance(title, str)
        or not isinstance(admin_username, str)
        or not isinstance(admin_email, str)
    ):
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, canonical_names = request(identifier, " ".join(names))
    except ValueError as error:
        raise ValueError(INVALID_INPUTS) from error
    if (
        canonical != identifier
        or list(canonical_names) != names
        or not 1 <= len(title) <= 200
        or "\x00" in title
        or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,60}", admin_username)
        or not re.fullmatch(r"[^@\s]{1,64}@[^@\s.]{1,190}\.[^@\s.]{2,20}", admin_email)
        or len(admin_email) > 100
    ):
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(
        selection,
        identifier,
        canonical_names,
        https=https,
        title=title,
        admin_username=admin_username,
        admin_email=admin_email,
    )


def _runtime_inputs(value: dict[str, object], choices: tuple[str, ...]) -> PreparationInputs:
    from sites.names import request

    if set(value) != {"version", "selection", "identifier"}:
        raise ValueError(INVALID_INPUTS)
    selection, identifier = value["selection"], value["identifier"]
    if (
        not isinstance(selection, str)
        or selection not in choices
        or not isinstance(identifier, str)
    ):
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, _ = request(identifier, "example.com")
    except ValueError:
        raise ValueError(INVALID_INPUTS) from None
    if canonical != identifier:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(selection, identifier)


def _site_readiness_inputs(value: dict[str, object], choices: tuple[str, ...]) -> PreparationInputs:
    from sites.names import readiness_path, request

    if set(value) != {"version", "identifier", "readiness"}:
        raise ValueError(INVALID_INPUTS)
    identifier, readiness = value["identifier"], value["readiness"]
    if not isinstance(identifier, str) or not isinstance(readiness, str):
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, _ = request(identifier, "example.com")
    except ValueError:
        raise ValueError(INVALID_INPUTS) from None
    path, problem = readiness_path(readiness)
    if canonical != identifier or problem or path != readiness:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs("", identifier, readiness=path)


def _database_engine_inputs(
    value: dict[str, object], choices: tuple[str, ...]
) -> PreparationInputs:
    if set(value) not in ({"version", "selection"}, {"version", "selection", "git"}):
        raise ValueError(INVALID_INPUTS)
    selection = value["selection"]
    git = value.get("git", False)
    if not isinstance(selection, str) or selection not in choices or type(git) is not bool:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(selection, git=git)


def _site_database_inputs(value: dict[str, object], choices: tuple[str, ...]) -> PreparationInputs:
    from sites.names import request

    if set(value) != {"version", "identifier"}:
        raise ValueError(INVALID_INPUTS)
    identifier = value["identifier"]
    if not isinstance(identifier, str):
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, _ = request(identifier, "example.com")
    except ValueError:
        raise ValueError(INVALID_INPUTS) from None
    if canonical != identifier:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs("", identifier)


def _laravel_deploy_inputs(value: dict[str, object]) -> PreparationInputs:
    from sites.names import request

    keys = set(value)
    if keys not in ({"version", "identifier"}, {"version", "identifier", "migrations"}):
        raise ValueError(INVALID_INPUTS)
    identifier = value["identifier"]
    migrations = value.get("migrations", True)
    if not isinstance(identifier, str) or type(migrations) is not bool:
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, _ = request(identifier, "example.com")
    except ValueError:
        raise ValueError(INVALID_INPUTS) from None
    if canonical != identifier:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs("", identifier, migrations=migrations)


RELEASE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def valid_release_name(release: str) -> bool:
    """A retained release directory name: no path, no dot entry, no leading dash."""
    return bool(RELEASE_NAME.fullmatch(release)) and release not in {".", ".."}


def _laravel_rollback_inputs(value: dict[str, object]) -> PreparationInputs:
    from sites.names import request

    if set(value) != {"version", "identifier", "release"}:
        raise ValueError(INVALID_INPUTS)
    identifier, release = value["identifier"], value["release"]
    if not isinstance(identifier, str) or not isinstance(release, str):
        raise ValueError(INVALID_INPUTS)
    if not valid_release_name(release):
        raise ValueError(INVALID_INPUTS)
    try:
        canonical, _ = request(identifier, "example.com")
    except ValueError:
        raise ValueError(INVALID_INPUTS) from None
    if canonical != identifier:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs("", identifier, (), release)


_DECODERS: dict[InputShape, Callable[[dict[str, object], tuple[str, ...]], PreparationInputs]] = {
    InputShape.SITE_CREATE: _site_inputs,
    InputShape.WORDPRESS_CREATE: _wordpress_create_inputs,
    InputShape.LARAVEL_CREATE: _laravel_create_inputs,
    InputShape.SITE_RUNTIME: _runtime_inputs,
    InputShape.SITE_READINESS: _site_readiness_inputs,
    InputShape.SITE_DATABASE: _site_database_inputs,
    InputShape.DATABASE_ENGINE: _database_engine_inputs,
    InputShape.LARAVEL_DEPLOY: lambda value, _choices: _laravel_deploy_inputs(value),
    InputShape.LARAVEL_ROLLBACK: lambda value, _choices: _laravel_rollback_inputs(value),
}
