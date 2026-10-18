"""Versioned, non-secret preparation selection, validated before opening SSH."""

import re
from dataclasses import dataclass
from enum import StrEnum

INVALID_INPUTS = "Barectl refused invalid preparation inputs. Prepare a new review."


class InputShape(StrEnum):
    SELECTION = "selection"
    SITE_CREATE = "site_create"
    SITE_RUNTIME = "site_runtime"
    LARAVEL_DEPLOY = "laravel_deploy"
    LARAVEL_ROLLBACK = "laravel_rollback"


@dataclass(frozen=True)
class PreparationInputs:
    selection: str = ""
    identifier: str = ""
    names: tuple[str, ...] = ()
    # The retained release a Roll back selects; empty for every other kind.
    release: str = ""
    # The site's Deploy switch: pending migrations run only when this is true.
    migrations: bool = True

    def document(self) -> dict[str, object]:
        if self.release:
            return {"version": 1, "identifier": self.identifier, "release": self.release}
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
            }
        return {"version": 1, "selection": self.selection} if self.selection else {"version": 1}


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
    if shape == InputShape.SITE_CREATE:
        return _site_inputs(value, choices)
    if shape == InputShape.SITE_RUNTIME:
        return _runtime_inputs(value, choices)
    if shape == InputShape.LARAVEL_DEPLOY:
        return _laravel_deploy_inputs(value)
    if shape == InputShape.LARAVEL_ROLLBACK:
        return _laravel_rollback_inputs(value)
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

    if set(value) != {"version", "selection", "identifier", "names"}:
        raise ValueError(INVALID_INPUTS)
    identifier, names, selection = value["identifier"], value["names"], value["selection"]
    if (
        not isinstance(identifier, str)
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(selection, str)
        or selection not in choices
    ):
        raise ValueError(INVALID_INPUTS)
    try:
        identifier, canonical = request(identifier, " ".join(names))
    except ValueError as error:
        raise ValueError(INVALID_INPUTS) from error
    if list(canonical) != names:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(selection, identifier, canonical)


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
