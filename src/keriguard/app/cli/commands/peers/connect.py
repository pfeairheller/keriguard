# -*- encoding: utf-8 -*-
"""
keriguard.app.cli.commands.peers.connect module

Issue a KERI credential for Wireguard peer connection configuration.
"""

import argparse
import asyncio
import sys

import httpx
from keri import help
from keri.app.httping import CESR_CONTENT_TYPE
from keri import kering
from keri.app.cli.common import existing
from keri.help import helping
from keri.vdr import credentialing

from keriguard.core.kering import Issuer

parser = argparse.ArgumentParser(
    description="Issue a KERI credential for Wireguard peer connection configuration."
)
parser.set_defaults(handler=lambda args: asyncio.run(issue_credential(args)))

# KERI identity arguments
parser.add_argument(
    "--name",
    "-n",
    help="keystore name and file location of KERI keystore",
    required=False,
    default="keriguard",
)
parser.add_argument("--alias", action="store", required=False, default="keriguard")
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="21 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)

# Peer configurations
parser.add_argument(
    "--peer",
    action="append",
    required=True,
    help='Peer configuration in format: "name=CONN_NAME,endpoint=HOST:PORT,allowed-ips=CIDR[,keepalive=SECS][,psk=KEY][,peer-name=NAME][,purpose=TEXT][,environment=ENV][,bandwidth-class=CLASS]"',
)

parser.add_argument(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Output file for credential",
)
parser.add_argument(
    "--registrar-url",
    type=str,
    default=None,
    help="URL to send grant data via PUT request (mutually exclusive with --output)",
)
parser.add_argument(
    "--authenticate",
    "-z",
    help="Prompt the controller for authentication codes for each witness",
    action="store_true",
)

logger = help.ogler.getLogger()


def parse_peer_config(peer_string):
    """
    Parse peer configuration string into a dict.

    Format: "name=CONN_NAME,endpoint=HOST:PORT,allowed-ips=CIDR,..."

    Returns:
        tuple: (peer_config, connection_metadata)
    """
    peer_config = {}
    connection_metadata = {}

    # Split on commas, but be careful with values that might contain commas
    parts = peer_string.split(",")

    for part in parts:
        if "=" not in part:
            raise kering.ConfigurationError(
                f"Invalid peer configuration format: '{part}'. Expected key=value"
            )

        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Connection metadata fields
        if key == "name":
            connection_metadata["connectionName"] = value
        elif key == "purpose":
            connection_metadata["purpose"] = value
        elif key == "environment":
            connection_metadata["environment"] = value
        elif key == "bandwidth-class":
            connection_metadata["bandwidthClass"] = value

        # Peer configuration fields
        elif key == "allowed-ips":
            # Split by | or ; to support multiple IPs in one string
            peer_config["allowedIps"] = [
                ip.strip() for ip in value.replace(";", "|").split("|")
            ]
        elif key == "endpoint":
            peer_config["endpoint"] = value
        elif key == "keepalive":
            peer_config["persistentKeepalive"] = int(value)
        elif key == "psk":
            peer_config["presharedKey"] = value
        elif key == "peer-name":
            peer_config["peerName"] = value
        else:
            raise kering.ConfigurationError(f"Unknown peer configuration key: '{key}'")

    # Validate required fields
    if "connectionName" not in connection_metadata:
        raise kering.ConfigurationError(
            "Peer configuration must include 'name=<connection_name>'"
        )

    if "allowedIps" not in peer_config:
        raise kering.ConfigurationError(
            "Peer configuration must include 'allowed-ips=<cidr>'"
        )

    return peer_config, connection_metadata


async def issue_credential(args):
    """Issue a KERI credential for Wireguard peer connection configuration."""
    name = args.name
    alias = args.alias
    bran = args.bran

    # Validate mutual exclusivity of --output and --registrar-url
    if args.output and args.registrar_url:
        print(
            "Error: --output and --registrar-url are mutually exclusive. Please specify only one.",
            file=sys.stderr,
        )
        return 1

    # Validate input counts
    if not args.peer or len(args.peer) != 2:
        print(
            "Error: Exactly 2 --peer arguments required",
            file=sys.stderr,
        )
        return 1

    # Load existing Hab
    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        # Create Regery
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

        issuer = Issuer(hby=hby, hab=hab, rgy=rgy)

        print(
            f"Issuing connection credential using KERI identity: {hab.pre}",
            file=sys.stderr,
        )

        # Parse peer configurations
        try:
            peers = []
            for i, peer_string in enumerate(args.peer):
                peer_config, connection_metadata = parse_peer_config(peer_string)

                # Validate keepalive range if provided
                if "persistentKeepalive" in peer_config:
                    keepalive = peer_config["persistentKeepalive"]
                    if keepalive < 0 or keepalive > 65535:
                        raise kering.ConfigurationError(
                            f"Keepalive must be between 0 and 65535 seconds, got {keepalive}"
                        )

                # Validate connection name format (schema requirement)
                conn_name = connection_metadata["connectionName"]
                if not conn_name or len(conn_name) < 1 or len(conn_name) > 64:
                    raise kering.ConfigurationError(
                        f"Connection name must be between 1 and 64 characters, got {len(conn_name)}"
                    )

                # Validate purpose length if provided (schema requirement)
                if (
                    "purpose" in connection_metadata
                    and len(connection_metadata["purpose"]) > 256
                ):
                    raise kering.ConfigurationError(
                        f"Purpose must be 256 characters or less, got {len(connection_metadata['purpose'])}"
                    )

                peers.append(
                    {
                        "peer_config": peer_config,
                        "connection_metadata": connection_metadata,
                    }
                )

                print(
                    f"  Peer {i+1}: {conn_name} -> Interface {peers[i]['peer_config']['endpoint']}...",  # type: ignore
                    file=sys.stderr,
                )

        except kering.ConfigurationError as e:
            print(f"Configuration error: {e}", file=sys.stderr)
            return 1

        auths = {}
        if args.authenticate:
            for wit in hab.kever.wits:
                if wit in auths:
                    continue
                code = input(f"Enter code for {wit}: ")
                auths[wit] = f"{code}#{helping.nowIso8601()}"

        try:
            creder = await issuer.issue_connection_credential(
                peers=peers,
                auths=auths,
            )

            # Output credential grant
            if args.output or args.registrar_url:
                grant = issuer.grant(creder.said, creder.attrib.get("i"))

                if args.output:
                    with open(args.output, "wb") as f:
                        f.write(grant)

                if args.registrar_url:
                    try:
                        # Send grant data to registrar via PUT request
                        response = httpx.put(
                            args.registrar_url,
                            content=bytes(grant),
                            headers={"Content-Type": CESR_CONTENT_TYPE},
                            timeout=30.0,
                        )
                        response.raise_for_status()

                        print(
                            f"  Registrar: Grant sent to {args.registrar_url} (HTTP {response.status_code})",
                            file=sys.stderr,
                        )

                    except httpx.HTTPError as e:
                        print(
                            f"Failed to send grant to registrar: {e}", file=sys.stderr
                        )
                        return 1

            # Success message
            print("\n✓ Connection credential issued successfully", file=sys.stderr)
            print(f"  Credential SAID: {creder.said}", file=sys.stderr)
            print(f"  Recipient: {creder.attrib.get('i')}", file=sys.stderr)
            print(
                f"  Peer 1: {peers[0]['connection_metadata']['connectionName']}",
                file=sys.stderr,
            )
            print(f"    Interface SAID: {peers[0]['interface_said']}", file=sys.stderr)
            print(
                f"  Peer 2: {peers[1]['connection_metadata']['connectionName']}",
                file=sys.stderr,
            )
            print(f"    Interface SAID: {peers[1]['interface_said']}", file=sys.stderr)
            print(f"  Registry: {creder.sad.get('ri')}", file=sys.stderr)
            if args.output:
                print(f"  Output: {args.output}", file=sys.stderr)
            if args.registrar_url:
                print(f"  Registrar URL: {args.registrar_url}", file=sys.stderr)

            return 0

        except kering.ValidationError as e:
            print(f"Credential validation failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"Failed to issue credential: {e}", file=sys.stderr)
            return 1
