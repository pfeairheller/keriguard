# -*- encoding: utf-8 -*-
"""
keriguard.app.cli module

Issue KERI credentials for Wireguard interface configuration.
"""

import argparse
import asyncio
import re
import sys

from keri import help
from keri import kering
from keri.app import connecting
from keri.app.cli.common import existing
from keri.help import helping
from keri.vdr import credentialing

from keriguard.core.kering import Issuer

parser = argparse.ArgumentParser(
    description="Issue a KERI credential for Wireguard interface configuration."
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
parser.add_argument("--alias", action="store", required=False, default="owl")
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

# Credential issuance arguments
parser.add_argument(
    "--recipient",
    "-r",
    required=True,
    help="AID of the credential recipient (issuee)",
)
parser.add_argument(
    "--registry-name",
    help="Registry name to use for credential issuance (defaults to hab name)",
    default=None,
)

# Interface metadata arguments
parser.add_argument(
    "--interface-name",
    required=True,
    help="Interface name (e.g., wg0) - used for config filename",
)
parser.add_argument(
    "--interface-description",
    help="Human-readable description of this interface",
    default=None,
)
parser.add_argument(
    "--environment",
    help="Deployment environment tag",
    choices=["production", "staging", "development", "test"],
    default=None,
)

# Required Wireguard interface arguments
parser.add_argument(
    "--address",
    "-a",
    required=True,
    action="append",
    help="Interface address in CIDR notation (can be specified multiple times for IPv4+IPv6)",
)
parser.add_argument(
    "--listen-port",
    "-l",
    type=int,
    required=True,
    help="UDP port to listen on (1-65535, required per schema)",
)

# Optional Wireguard interface arguments
parser.add_argument(
    "--dns",
    action="append",
    default=None,
    help="DNS server (can be specified multiple times)",
)
parser.add_argument(
    "--mtu",
    type=int,
    default=None,
    help="MTU for the interface (576-65535)",
)
parser.add_argument(
    "--table",
    type=str,
    default=None,
    help="Routing table to use (auto, off, or table number)",
)

# Hook scripts
parser.add_argument(
    "--pre-up",
    type=str,
    default=None,
    help="Command to run before interface goes up",
)
parser.add_argument(
    "--post-up",
    type=str,
    default=None,
    help="Command to run after interface goes up",
)
parser.add_argument(
    "--pre-down",
    type=str,
    default=None,
    help="Command to run before interface goes down",
)
parser.add_argument(
    "--post-down",
    type=str,
    default=None,
    help="Command to run after interface goes down",
)

parser.add_argument(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Output file for credential",
)
parser.add_argument(
    "--authenticate",
    "-z",
    help="Prompt the controller for authentication codes for each witness",
    action="store_true",
)

logger = help.ogler.getLogger()


async def issue_credential(args):
    """Issue a KERI credential for Wireguard interface configuration."""
    name = args.name
    alias = args.alias
    bran = args.bran

    # Load existing Hab
    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        # Validate recipient exists in kevers
        recipient = ""
        if args.recipient not in hby.kevers:
            if (recipient_hab := hby.habByName(args.recipient)) is not None:
                recipient = recipient_hab.pre
            else:
                org = connecting.Organizer(hby=hby)
                results = org.find("alias", args.recipient)
                if not results:
                    raise kering.ConfigurationError(
                        f"Recipient '{args.recipient}' not found. "
                        f"Resolve recipient OOBI first with: kli oobi resolve --name {name} --oobi-alias <alias> --oobi <url>"
                    )
                recipient = results[0].get("id")

        else:
            recipient = args.recipient

        # Create Regery
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)
        # Get registry
        registry_name = args.registry_name or hab.name

        issuer = Issuer(hby=hby, hab=hab, rgy=rgy)
        # Validate listen port range (schema requirement)
        if args.listen_port < 1 or args.listen_port > 65535:
            raise kering.ConfigurationError(
                f"Listen port must be between 1 and 65535, got {args.listen_port}"
            )

        # Validate MTU range if provided (schema requirement)
        if args.mtu is not None and (args.mtu < 576 or args.mtu > 65535):
            raise kering.ConfigurationError(
                f"MTU must be between 576 and 65535, got {args.mtu}"
            )

        # Validate interface name pattern (schema requirement)
        if not re.match(r"^[a-zA-Z0-9_-]+$", args.interface_name):
            raise kering.ConfigurationError(
                f"Interface name must contain only alphanumeric characters, underscores, and hyphens: {args.interface_name}"
            )

        if len(args.interface_name) < 1 or len(args.interface_name) > 64:
            raise kering.ConfigurationError(
                f"Interface name must be between 1 and 64 characters, got {len(args.interface_name)}"
            )

        # Validate interface description length if provided (schema requirement)
        if args.interface_description and len(args.interface_description) > 256:
            raise kering.ConfigurationError(
                f"Interface description must be 256 characters or less, got {len(args.interface_description)}"
            )

        # Build credential data
        print(
            f"Issuing interface credential using KERI identity: {hab.pre}",
            file=sys.stderr,
        )
        print(f"Recipient: {recipient}", file=sys.stderr)
        print(f"Registry: {registry_name}", file=sys.stderr)

        # Build interface configuration
        interface_config = {
            "listenPort": args.listen_port,
        }

        # Add optional interface fields
        if args.address:
            interface_config["address"] = args.address
        if args.dns:
            interface_config["dns"] = args.dns
        if args.mtu is not None:
            interface_config["mtu"] = args.mtu
        if args.table is not None:
            interface_config["table"] = args.table
        if args.pre_up:
            interface_config["preUp"] = args.pre_up
        if args.post_up:
            interface_config["postUp"] = args.post_up
        if args.pre_down:
            interface_config["preDown"] = args.pre_down
        if args.post_down:
            interface_config["postDown"] = args.post_down

        # Build interface metadata
        interface_metadata = {
            "interfaceName": args.interface_name,
        }

        if args.interface_description:
            interface_metadata["interfaceDescription"] = args.interface_description
        if args.environment:
            interface_metadata["environment"] = args.environment

        auths = {}
        if args.authenticate:
            for wit in hab.kever.wits:
                if wit in auths:
                    continue
                code = input(f"Enter code for {wit}: ")
                auths[wit] = f"{code}#{helping.nowIso8601()}"

        try:
            creder = await issuer.issue_interface_credential(
                recipient=recipient,
                registry_name=registry_name,
                interface=interface_config,
                interface_metadata=interface_metadata,
                auths=auths,
            )

            # Output credential grant
            if args.output:
                grant = issuer.grant(creder.said, recipient)
                with open(args.output, "wb") as f:
                    f.write(grant)

            # Success message
            print("\n✓ Interface credential issued successfully", file=sys.stderr)
            print(f"  Credential SAID: {creder.said}", file=sys.stderr)
            print(f"  Recipient: {recipient}", file=sys.stderr)
            print(f"  Interface: {args.interface_name}", file=sys.stderr)
            print(f"  Registry: {registry_name}", file=sys.stderr)
            if args.output:
                print(f"  Output: {args.output}", file=sys.stderr)

            return 0

        except kering.ValidationError as e:
            print(f"Credential validation failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"Failed to issue credential: {e}", file=sys.stderr)
            return 1
