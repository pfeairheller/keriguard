# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.services.kel_service

Business logic for KEL event processing.
"""

import base64
from pathlib import Path

import pysodium
from keri import help
from keri.core.coring import Verfer
from keri.core.eventing import Kever

from keriguard.core import (
    WireguardConfigParser,
    WireguardConfigWriter,
    WireguardPeer,
)
from keriguard.core.systeming import WireGuardControlError, restart_wireguard
from keriguard.core.wireguarding import Schema
from ..config import SentinelHandlerConfig

logger = help.ogler.getLogger()


class KELService:
    """Service for managing Wireguard configs based on KEL events."""

    def __init__(self, config: SentinelHandlerConfig):
        self.config = config

    async def update_peer_for_aid(
        self,
        aid: str,
        verfer: Verfer,
        kever: Kever,
    ):
        """
        Update or create Wireguard peer configuration for an AID.

        Converts the KERI verfer to a Wireguard public key and
        updates the peer configuration.
        """
        # Convert KERI verfer to Wireguard public key
        public_key = self._verfer_to_wg_pubkey(verfer)

        logger.info(f"Updating peer for AID {aid}")
        logger.debug(f"  Public key: {public_key}...")

        # Find config file for this AID (or create if auto-create enabled)
        my_saids = [
            saider.qb64
            for saider in self.config.rgy.reger.subjs.get(keys=self.config.hab.pre)
        ]
        interface_saids = [
            saider.qb64
            for saider in self.config.rgy.reger.schms.get(keys=Schema.INTERFACE_SCHEMA)
        ]
        saids = list(set(my_saids) & set(interface_saids))
        if not saids:
            logger.warning(f"No local interface credential saids found for AID {aid}")
            return

        for said in saids:
            interface_creder, *_ = self.config.rgy.reger.cloneCred(said=said)
            payload = interface_creder.attrib
            metadata = payload.get("interfaceMetadata")
            interface_name = metadata.get("interfaceName")

            config_path = Path(self.config.config_dir) / f"{interface_name}.conf"
            if not config_path.exists():
                logger.warning(f"Config not found for {aid}")
                return

            # Load existing config
            config = WireguardConfigParser.parse_file(config_path)

            # Check if peer already exists
            existing_peer = config.get_peer_by_aid(aid)

            if existing_peer:
                # Update existing peer's key if changed
                if existing_peer.public_key != public_key:
                    logger.info(f"Updating public key for peer {aid}")
                    config.remove_peer_by_aid(aid)
                    new_peer = WireguardPeer(
                        public_key=public_key,
                        allowed_ips=existing_peer.allowed_ips,
                        endpoint=existing_peer.endpoint,
                        persistent_keepalive=existing_peer.persistent_keepalive,
                        preshared_key=existing_peer.preshared_key,
                        peer_name=existing_peer.peer_name,
                        keri_aid_qb64=aid,
                    )
                    config.add_peer(new_peer)
                else:
                    logger.debug(f"Public key unchanged for {aid}")
                    return

            else:
                logger.warning(f"Peer not found for {aid} and auto-add disabled")
                return

            # Save updated config
            if self.config.backup_configs:
                backup_path = config_path.with_suffix(config_path.suffix + ".bak")
                backup_path.write_bytes(config_path.read_bytes())

            WireguardConfigWriter.write_file(config, config_path)
            logger.info(f"Updated config file: {config_path}")

            try:
                await restart_wireguard(interface_name)

            except WireGuardControlError as e:
                logger.error(
                    f"Failed to restart WireGuard interface {interface_name}: {e}"
                )
                return

    @staticmethod
    def _verfer_to_wg_pubkey(verfer: Verfer) -> str:
        """Convert KERI verfer to Wireguard public key."""
        # Convert signing key to encryption key
        public_key_bytes = pysodium.crypto_sign_pk_to_box_pk(verfer.raw)
        return base64.b64encode(public_key_bytes).decode("ascii")
