# -*- encoding: utf-8 -*-
"""
keriguard.core module

Core functionality for KERI-managed Wireguard.
"""

from .wireguarding import (
    # Main API
    WireguardConfigManager,
    # Data Models
    WireguardConfig,
    WireguardInterface,
    WireguardPeer,
    # KERI Integration
    KERIKeyGenerator,
    # File I/O
    WireguardConfigParser,
    WireguardConfigWriter,
    # Validation
    InterfaceValidator,
    PeerValidator,
    ConfigValidator,
    # Exceptions
    WireguardError,
    KeyGenerationError,
    ValidationError,
    ConfigParseError,
    ConfigWriteError,
)

__all__ = [
    # Main API
    "WireguardConfigManager",
    # Data Models
    "WireguardConfig",
    "WireguardInterface",
    "WireguardPeer",
    # KERI Integration
    "KERIKeyGenerator",
    # File I/O
    "WireguardConfigParser",
    "WireguardConfigWriter",
    # Validation
    "InterfaceValidator",
    "PeerValidator",
    "ConfigValidator",
    # Exceptions
    "WireguardError",
    "KeyGenerationError",
    "ValidationError",
    "ConfigParseError",
    "ConfigWriteError",
]
