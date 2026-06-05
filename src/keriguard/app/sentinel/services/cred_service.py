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
from keriguard.core.systeming import control_wireguard, WireGuardAction

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

        await control_wireguard(WireGuardAction.ENABLE, interface_name)
        await control_wireguard(WireGuardAction.START, interface_name)

        logger.debug(f"Interface credential service processing complete for {said}")

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
            edges = creder.edge

            # Extract peer1 and peer2 from edges
            peer1 = edges.get("peer1")
            peer2 = edges.get("peer2")

            if not peer1 or not peer2:
                logger.error(f"Connection credential {said} missing peer1 or peer2")
                return

            # Clone both interface credentials
            peer1_interface_creder, *_ = self.rgy.reger.cloneCred(said=peer1.get("n"))
            peer2_interface_creder, *_ = self.rgy.reger.cloneCred(said=peer2.get("n"))

            if not peer1_interface_creder or not peer2_interface_creder:
                logger.error(
                    f"Failed to load interface credentials for connection {said}"
                )
                return

            # Determine which peer is local by checking interface credential recipients
            peer1_recipient = peer1_interface_creder.attrib.get("i")
            peer2_recipient = peer2_interface_creder.attrib.get("i")

            # Check if peer1's interface belongs to this host
            if (hab := self.hby.habs.get(peer1_recipient)) is not None:
                # peer1 is local, peer2 is remote
                local_interface_creder = peer1_interface_creder
                remote_interface_creder = peer2_interface_creder
                remote_peer = peer2
                logger.debug(
                    f"Matched peer1 interface to local host: {peer1_recipient}"
                )
            # Check if peer2's interface belongs to this host
            elif (hab := self.hby.habs.get(peer2_recipient)) is not None:
                # peer2 is local, peer1 is remote
                local_interface_creder = peer2_interface_creder
                remote_interface_creder = peer1_interface_creder
                remote_peer = peer1
                logger.debug(
                    f"Matched peer2 interface to local host: {peer2_recipient}"
                )
            else:
                # Neither peer is local, ignore this credential
                logger.debug(
                    f"Neither peer interface belongs to this host, ignoring credential {said}"
                )
                return

            # Extract interface name from local interface credential
            local_payload = local_interface_creder.attrib
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

            # Extract peer configuration from remote peer object
            allowed_ips = remote_peer.get("allowedIps", [])
            endpoint = remote_peer.get("endpoint")
            persistent_keepalive = remote_peer.get("persistentKeepalive")
            preshared_key = remote_peer.get("presharedKey")

            # Extract peer name from connection metadata
            connection_metadata = remote_peer.get("connectionMetadata", {})
            peer_name = connection_metadata.get("connectionName")

            # Get remote AID from remote interface credential
            remote_aid = remote_interface_creder.attrib.get("i")

            # Generate peer with auto-generated keys
            logger.info(f"Generating peer keys using KERI identity: {hab.pre}")
            manager.add_peer_to_config(
                config,
                allowed_ips=allowed_ips,
                endpoint=endpoint,
                persistent_keepalive=persistent_keepalive,
                preshared_key=preshared_key,
                peer_name=peer_name,
                keri_aid=remote_aid,
            )

            # Save updated configuration
            manager.save_config(config, config_path, backup=True)

            await control_wireguard(WireGuardAction.RESTART, interface_name)

        except MissingEntryError:
            logger.error(f"Missing entry for interface credential: {said}")
            return

        logger.info(f"Connection credential service processing complete for {said}")
