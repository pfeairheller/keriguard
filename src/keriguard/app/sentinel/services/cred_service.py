# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.services.cred_service

Business logic for credential event processing.
"""

from pathlib import Path

from keri import help
from keri.core.serdering import SerderACDC
from keri.kering import MissingEntryError

from keriguard.core import WireguardConfigManager

logger = help.ogler.getLogger()


class CredService:
    """Service for managing credential-based access control."""

    def __init__(self, hby, rgy, config_dir):
        self.hby = hby
        self.rgy = rgy
        self.config_dir = config_dir

    async def process_interface_credential(self, said: str, creder: SerderACDC):
        """
        Process credential event for access control.

        Future implementation:
        - Verify credential validity
        - Check credential type and permissions
        - Add/remove peers based on credential status
        - Implement role-based access control
        """
        payload = creder.attrib
        interface = payload.get("interface")
        metadata = payload.get("interfaceMetadata")

        interface_name = metadata.get("interfaceName")
        interface_description = metadata.get("interfaceDescription", "")

        recipient = payload.get("i")
        if (hab := self.hby.habs.get(recipient)) is None:
            logger.info(f"Recipient {recipient} not found in hby, this is for a peer.")
            return

        manager = WireguardConfigManager(hab=hab)
        config = manager.generate_config(
            address=interface.get("address"),
            listen_port=interface.get("listenPort"),
            dns=interface.get("dns", None),
            mtu=interface.get("mtu"),
            table=interface.get("table", None),
            config_name=interface_name,
            description=interface_description,
        )

        # Add pre/post up/down scripts if provided
        # Handle argument names with underscores (argparse converts dashes to underscores)
        config.interface.pre_up = interface.get("preUp")
        config.interface.post_up = interface.get("postUp")
        config.interface.pre_down = interface.get("preDown")
        config.interface.post_down = interface.get("postDown")

        # Save configuration
        manager.save_config(
            config, Path(self.config_dir) / f"{interface_name}.conf", backup=True
        )

        logger.debug(f"Interface credential service processing complete for {said}")
        pass

    async def process_connection_credential(self, said: str, creder: SerderACDC):
        """
        Process credential event for access control.

        Future implementation:
        - Verify credential validity
        - Check credential type and permissions
        - Add/remove peers based on credential status
        - Implement role-based access control
        """
        try:
            payload = creder.attrib
            peer = payload.get("peer")

            edges = creder.edge

            # Process local interface credential to load the Interface
            local_interface = edges.get("localInterface")
            local_interface_creder, *_ = self.rgy.reger.cloneCred(
                said=local_interface.get("n")
            )

            local_payload = local_interface_creder.attrib
            recipient = local_payload.get("i")
            if (hab := self.hby.habs.get(recipient)) is None:
                logger.debug(f"Recipient {recipient} not found in habby")
                return

            metadata = local_payload.get("interfaceMetadata")

            interface_name = metadata.get("interfaceName")
            config_path = Path(self.config_dir) / f"{interface_name}.conf"
            if not config_path.exists() or not config_path.is_file():
                logger.error(
                    f"Interface configuration file not found for {interface_name}"
                )
                return

            manager = WireguardConfigManager(hab=hab)
            config = manager.load_config(config_path)

            # Process remote credential to generate the Peer
            remote_interface = edges.get("remoteInterface")
            remote_interface_creder, *_ = self.rgy.reger.cloneCred(
                said=remote_interface.get("n")
            )
            remote_payload = remote_interface_creder.attrib
            remote_aid = remote_payload.get("i")

            # Generate peer with auto-generated keys
            logger.info(f"Generating peer keys using KERI identity: {hab.pre}")
            manager.add_peer_to_config(
                config,
                allowed_ips=peer.get("allowedIps"),
                endpoint=peer.get("endpoint"),
                persistent_keepalive=peer.get("persistentKeepalive"),
                preshared_key=peer.get("presharedKey"),
                peer_name=peer.get("peerName"),
                keri_aid=remote_aid,
            )

            # Save updated configuration
            manager.save_config(config, config_path, backup=True)

        except MissingEntryError:
            logger.error(f"Missing entry for interface credential: {said}")
            return

        logger.debug(f"Connection credential service processing complete for {said}")
