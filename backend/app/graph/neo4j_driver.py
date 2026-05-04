"""Neo4j driver factory with lazy initialization and session context manager."""
from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from neo4j import Driver, Session

_driver: "Driver | None" = None


def _get_driver() -> "Driver":
    global _driver
    if _driver is None:
        from neo4j import GraphDatabase
        from app.config import Settings
        settings = Settings()
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


def set_driver(driver: "Driver") -> None:
    """Override driver for testing."""
    global _driver
    _driver = driver


@contextmanager
def get_session() -> "Generator[Session, None, None]":
    """Yield a Neo4j session, always closing it afterward."""
    session = _get_driver().session()
    try:
        yield session
    finally:
        session.close()
