import json
from functools import lru_cache
from pathlib import Path

_CATALOG_PATH = Path(__file__).parent.parent.parent / "data" / "actions_catalog.json"


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, list[str]]:
    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_actions_for_service(service: str) -> list[str]:
    return _load_catalog().get(service.lower(), [])


def service_exists(service: str) -> bool:
    return service.lower() in _load_catalog()


def get_all_actions() -> list[str]:
    catalog = _load_catalog()
    seen: set[str] = set()
    result: list[str] = []
    for actions in catalog.values():
        for action in actions:
            if action not in seen:
                seen.add(action)
                result.append(action)
    return result
