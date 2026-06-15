# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.config

Configuration for Keriguard Sentinel handler.
"""

from dataclasses import dataclass

from keri.app.habbing import Habery, Hab
from keri.vdr.credentialing import Regery


@dataclass
class SentinelHandlerConfig:
    """Configuration for Sentinel event handler."""

    # Sentinel framework settings
    export_dir: str  # Directory containing kel/, tel/, cred/
    sentinel_aid: str | None = None
    poll_interval: float = 2.0  # Polling interval in seconds

    # Wireguard configuration
    config_dir: str = "/etc/wireguard"  # Directory for .conf files

    # KERI settings
    hby: Habery = None
    hab: Hab = None
    rgy: Regery = None
    # Handler behavior
    backup_configs: bool = True  # Create .bak files on updates
