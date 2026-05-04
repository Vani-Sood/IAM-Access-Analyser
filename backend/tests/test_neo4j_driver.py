"""Unit tests for Neo4j driver factory."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def test_get_session_yields_session_and_closes():
    """get_session context manager yields a session and closes it on exit."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value = mock_session

    from app.graph import neo4j_driver
    neo4j_driver.set_driver(mock_driver)

    from app.graph.neo4j_driver import get_session
    with get_session() as session:
        assert session is mock_session

    mock_session.close.assert_called_once()


def test_get_session_closes_on_exception():
    """get_session closes session even if body raises."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value = mock_session

    from app.graph import neo4j_driver
    neo4j_driver.set_driver(mock_driver)

    from app.graph.neo4j_driver import get_session
    with pytest.raises(RuntimeError):
        with get_session():
            raise RuntimeError("boom")

    mock_session.close.assert_called_once()


def test_set_driver_overrides_global():
    """set_driver replaces the module-level driver."""
    mock_driver = MagicMock()
    from app.graph import neo4j_driver
    neo4j_driver.set_driver(mock_driver)

    mock_session = MagicMock()
    mock_driver.session.return_value = mock_session

    from app.graph.neo4j_driver import get_session
    with get_session() as s:
        assert s is mock_session


def test_close_driver_resets_global():
    """close_driver calls driver.close() and resets to None."""
    mock_driver = MagicMock()
    from app.graph import neo4j_driver
    neo4j_driver.set_driver(mock_driver)
    neo4j_driver.close_driver()

    mock_driver.close.assert_called_once()
    assert neo4j_driver._driver is None


def test_close_driver_noop_when_none():
    """close_driver is safe when no driver is set."""
    from app.graph import neo4j_driver
    neo4j_driver._driver = None
    neo4j_driver.close_driver()  # should not raise
