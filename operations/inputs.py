"""Versioned, non-secret preparation selection, validated before opening SSH."""

from dataclasses import dataclass

INVALID_INPUTS = "Barectl refused invalid preparation inputs. Prepare a new review."


@dataclass(frozen=True)
class PreparationInputs:
    selection: str = ""

    def document(self) -> dict[str, object]:
        return {"version": 1, "selection": self.selection} if self.selection else {"version": 1}


EMPTY_INPUTS = PreparationInputs()


def empty_inputs() -> dict[str, object]:
    return {"version": 1}


def decode_inputs(value: object, choices: tuple[str, ...]) -> PreparationInputs:
    if (
        not isinstance(value, dict)
        or type(value.get("version")) is not int
        or value["version"] != 1
    ):
        raise ValueError(INVALID_INPUTS)
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
