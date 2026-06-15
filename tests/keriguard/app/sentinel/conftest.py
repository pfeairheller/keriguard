# -*- encoding: utf-8 -*-
"""Pytest fixtures for Sentinel handler tests."""

import pytest
from unittest.mock import Mock

# Skip all Sentinel tests if dependencies not installed
pytest.importorskip("sentinel")

from sentinel.framework import KELEvent, TELEvent, CredentialEvent
from keriguard.app.sentinel.handler import KeriguardEventHandler
from keriguard.app.sentinel.config import SentinelHandlerConfig


@pytest.fixture
def test_config(tmp_path):
    """Test configuration with temporary directories."""
    # Create mock Habery
    mock_hby = Mock()
    mock_hby.kvy = Mock()

    # Create mock Regery with reger
    mock_rgy = Mock()
    mock_rgy.reger = Mock()
    mock_rgy.tvy = Mock()

    return SentinelHandlerConfig(
        export_dir=str(tmp_path / "export"),
        poll_interval=1.0,
        config_dir=str(tmp_path / "configs"),
        hby=mock_hby,
        rgy=mock_rgy,
        backup_configs=False,  # Disable backups in tests
    )


@pytest.fixture
def handler(test_config):
    """Keriguard event handler instance."""
    return KeriguardEventHandler(test_config)


@pytest.fixture
def mock_kel_event():
    """Mock KEL event for testing."""
    event = Mock(spec=KELEvent)
    event.aid = "EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG"
    event.filepath = "/tmp/export/kel/EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG.cesr"
    event.data = b"test cesr data"
    event.timestamp = 1234567890
    event.hby = None
    return event


@pytest.fixture
def mock_tel_event():
    """Mock TEL event for testing."""
    event = Mock(spec=TELEvent)
    event.aid = "EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG"
    event.filepath = "/tmp/export/tel/EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG.cesr"
    event.data = b"test tel data"
    event.timestamp = 1234567890
    event.hby = None
    return event


@pytest.fixture
def mock_cred_event():
    """Mock credential event for testing."""
    event = Mock(spec=CredentialEvent)
    event.aid = "EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG"
    event.filepath = (
        "/tmp/export/cred/EHzPq4mQWbLQrMgfGH2xQ5Z7KmZAaF7cW9rBmLQrMgfG.cesr"
    )
    event.data = b"test cred data"
    event.timestamp = 1234567890
    event.hby = None
    return event
