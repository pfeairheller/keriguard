# -*- encoding: utf-8 -*-
"""
keriguard.app.cli.commands.interface.list module

List Wireguard interface credentials from KERI registry.
"""

import argparse
import asyncio

from keri import help
from keri.app import connecting
from keri.app.cli.common import existing
from keri.vdr import credentialing

from keriguard.core.wireguarding import Schema

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(
    description="List Wireguard peer connection credentials from the KERI registry"
)
parser.set_defaults(handler=lambda args: asyncio.run(list_peer_connections(args)))
parser.add_argument(
    "--name",
    "-n",
    help="keystore name and file location of KERI keystore",
    required=False,
    default="keriguard",
)
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
parser.add_argument(
    "--verbose",
    "-v",
    help="Show all credential fields",
    action="store_true",
)


def get_recipient_name(hby, recipient):
    if recipient is None:
        return "Unknown"

    if recipient in hby.habs:
        hab = hby.habs[recipient]
        return hab.name
    else:
        org = connecting.Organizer(hby=hby)
        contact = org.get(pre=recipient)
        return contact.get("alias") if contact else None


async def list_peer_connections(args):
    """List Wireguard interface credentials from the KERI registry."""
    name = args.name
    bran = args.bran

    try:
        # Load KERI Habery
        with existing.existingHby(name=name, base=args.base, bran=bran) as hby:
            # Create registry for credential access
            rgy = credentialing.Regery(
                hby=hby, name=hby.name, base=hby.base, temp=hby.temp
            )

            # Iterate all credentials and filter by schema
            connections = []

            try:
                for saider in rgy.reger.schms.get(keys=Schema.CONNECTION_SCHEMA):
                    try:
                        said = saider.qb64
                        creder, *_ = rgy.reger.cloneCred(said=said)

                        # Extract credential data
                        edges = creder.edge
                        peer1 = edges.get("peer1")
                        peer2 = edges.get("peer2")

                        peer1_name = peer1.get("connectionMetadata", {}).get(
                            "connectionName", "N/A"
                        )
                        peer2_name = peer2.get("connectionMetadata", {}).get(
                            "connectionName", "N/A"
                        )

                        peer1_ip = peer1.get("endpoint")
                        peer2_ip = peer2.get("endpoint")

                        peer1_allowed_ips = peer1.get("allowedIps")
                        peer2_allowed_ips = peer2.get("allowedIps")

                        peer1_interface_said = peer1.get("n")
                        peer2_interface_said = peer2.get("n")

                        peer1_env = peer1.get("connectionMetadata", {}).get(
                            "environment"
                        )
                        peer2_env = peer2.get("connectionMetadata", {}).get(
                            "environment"
                        )

                        conneciton_info = {
                            "said": creder.said,
                            "peer1_name": peer1_name,
                            "peer2_name": peer2_name,
                            "peer1_ip": peer1_ip,
                            "peer2_ip": peer2_ip,
                            "peer1_allowed_ips": peer1_allowed_ips,
                            "peer2_allowed_ips": peer2_allowed_ips,
                            "peer1_env": peer1_env,
                            "peer2_env": peer2_env,
                            "peer1_interface_said": peer1_interface_said,
                            "peer2_interface_said": peer2_interface_said,
                        }
                        connections.append(conneciton_info)

                    except Exception as e:
                        # Log warning and skip credential if parse fails
                        logger.warning(f"Failed to parse credential {said}: {e}")
                        continue

            except Exception as e:
                print(f"Error querying credentials: {e}")
                return 1

            # Display results
            if not connections:
                print("No peer connection credentials found.")
                return 0

            output_table(connections, hby, rgy, verbose=args.verbose)
            return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def output_table(connections, hby, rgy, verbose=False):
    """Output interfaces with all fields."""
    print(f"\nFound {len(connections)} peer connection credential(s):\n")

    for i, conn in enumerate(connections, 1):
        print(f"Peer Connection {i} ({conn['said']}):")
        print(f"  Hosts: {conn["peer1_name"]} <--> {conn["peer2_name"]}")
        print(
            f"  Allowed IPs: {conn["peer1_allowed_ips"]} <--> {conn["peer2_allowed_ips"]}"
        )
        print(f"  Endpoints: {conn["peer1_ip"]} <--> {conn["peer2_ip"]}")

        if verbose:
            creder1, *_ = rgy.reger.cloneCred(said=conn["peer1_interface_said"])
            creder2, *_ = rgy.reger.cloneCred(said=conn["peer2_interface_said"])

            payload = creder1.attrib
            recipient1 = payload.get("i")
            recipient1_name = get_recipient_name(hby, recipient1)
            payload2 = creder2.attrib
            recipient2 = payload2.get("i")
            recipient2_name = get_recipient_name(hby, recipient2)

            print(f"  Recipients: {recipient1_name} <--> {recipient2_name}")
            print(f"  Recipient AIDs: {recipient1}\n {' ' * 18} <--> {recipient2}")
            print(
                f"  Interface: {conn['peer1_interface_said']}\n {' ' * 13} <--> {conn['peer2_interface_said']}"
            )
            print(f"  Environment: {conn['peer1_env']} <--> {conn['peer2_env']}")

        print()
