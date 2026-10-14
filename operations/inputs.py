"""Versioned, non-secret preparation selection, validated before opening SSH."""

from dataclasses import dataclass
from enum import StrEnum

INVALID_INPUTS = "Barectl refused invalid preparation inputs. Prepare a new review."


class InputShape(StrEnum):
    SELECTION = "selection"
    SITE_CREATE = "site_create"


@dataclass(frozen=True)
class PreparationInputs:
    selection: str = ""
    identifier: str = ""
    names: tuple[str, ...] = ()

    def document(self) -> dict[str, object]:
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
        identifier, canonical = request(identifier, " ".join(names), max_name_octets=253)
    except ValueError as error:
        raise ValueError(INVALID_INPUTS) from error
    if list(canonical) != names:
        raise ValueError(INVALID_INPUTS)
    return PreparationInputs(selection, identifier, canonical)
