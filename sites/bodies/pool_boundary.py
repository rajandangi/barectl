import configparser
import re
from typing import override


class PoolParser(configparser.ConfigParser):
    @override
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def ini_pool(text: str, identifier: str) -> dict[str, str] | None:
    parser = PoolParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
        if parser.defaults() or parser.sections() != [identifier]:
            return None
        return dict(parser[identifier])
    except configparser.Error:
        return None


def safe_pool_boundary(identifier: str, runtime: str, text: str) -> bool:
    if identifier == "diagnostic" or re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None:
        return False
    values = ini_pool(text, identifier)
    if values is None:
        return False
    fixed = {
        "user": "s" + identifier,
        "group": "s" + identifier,
        "listen": f"/run/php-fpm/{runtime}/{identifier}.sock",
    }
    if any(values.get(key) != value for key, value in fixed.items()):
        return False
    return not any(
        key.split("[", 1)[0].lower() == "include" or "opcache." in key.lower() for key in values
    )
