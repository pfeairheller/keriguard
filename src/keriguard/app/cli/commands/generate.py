# -*- encoding: utf-8 -*-
"""
heki.app.cli module

"""

import argparse
import asyncio
import sys
from pathlib import Path

from keri import help
from keri import kering
from keri.app.cli.common import existing


from keriguard.core.wireguarding import WireguardConfigManager

parser = argparse.ArgumentParser(
    description="Generate Wireguard configuration file based on KERI Hab keys."
)
parser.set_defaults(handler=lambda args: asyncio.run(generate(args)))
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
)  # passcode => bran

# Required arguments for Wireguard configuration
parser.add_argument(
    "--address",
    "-a",
    required=True,
    action="append",
    help="Interface address in CIDR notation (can be specified multiple times for IPv4+IPv6)",
)

parser.add_argument(
    "--output",
    "-o",
    required=True,
    type=str,
    help="Output path for the Wireguard configuration file (e.g., /etc/wireguard/wg0.conf)",
)

# Optional Wireguard interface arguments
parser.add_argument(
    "--listen-port",
    "-l",
    type=int,
    default=None,
    help="UDP port to listen on (1-65535, default: auto-assigned)",
)

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
    help="MTU for the interface (1280-9000, default: auto)",
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

# Metadata
parser.add_argument(
    "--config-name",
    type=str,
    default=None,
    help="Name for this configuration (defaults to filename)",
)

parser.add_argument(
    "--description",
    type=str,
    default=None,
    help="Human-readable description of this configuration",
)

# Output options
parser.add_argument(
    "--force",
    "-f",
    action="store_true",
    help="Overwrite existing file without creating backup",
)


logger = help.ogler.getLogger()


async def generate(args):
    """Generate a Wireguard interface configuration with KERI-tracked keys."""
    name = args.name
    alias = args.alias
    bran = args.bran

    # Load existing Hab
    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        if not hab:
            raise kering.ConfigurationError(
                f"Identifier '{alias}' must already exist. "
                f"Create one first using KERI's 'kli init' command."
            )

        # Create config manager with the Hab
        manager = WireguardConfigManager(hab=hab)

        # Determine config name from output path if not provided
        output_path = Path(args.output)
        config_name = args.config_name or output_path.stem

        # Generate configuration
        print(f"Generating Wireguard configuration using KERI identity: {hab.pre}")

        try:
            config = manager.generate_config(
                address=args.address,
                listen_port=args.listen_port,
                dns=args.dns if args.dns else None,
                mtu=args.mtu,
                table=args.table,
                config_name=config_name,
                description=args.description,
            )

            # Add pre/post up/down scripts if provided
            # Handle argument names with underscores (argparse converts dashes to underscores)
            if hasattr(args, "pre_up") and args.pre_up:
                config.interface.pre_up = args.pre_up
            if hasattr(args, "post_up") and args.post_up:
                config.interface.post_up = args.post_up
            if hasattr(args, "pre_down") and args.pre_down:
                config.interface.pre_down = args.pre_down
            if hasattr(args, "post_down") and args.post_down:
                config.interface.post_down = args.post_down

            # Save configuration
            backup = not args.force
            manager.save_config(config, output_path, backup=backup)

            # Get public key for display
            _, public_key, _ = manager.key_generator.generate_keypair()

            # Success message with details
            print(f"\nConfiguration saved to: {output_path}")
            print(f"Interface addresses: {', '.join(config.interface.address)}")
            if config.interface.listen_port:
                print(f"Listen port: {config.interface.listen_port}")
            print(f"Public key: {public_key[:32]}...")
            print(f"KERI AID: {config.interface.keri_aid_qb64}")

            if backup and output_path.exists():
                backup_path = Path(str(output_path) + ".bak")
                if backup_path.exists():
                    print(f"\nBackup created: {backup_path}")

            print("\nTo activate this configuration:")
            print(f"  sudo wg-quick up {output_path}")

        except kering.ValidationError as e:
            print(f"Configuration validation failed: {e}", file=sys.stderr)
            return 1
        except PermissionError:
            print(f"Permission denied: {output_path}", file=sys.stderr)
            print(
                "Try running with sudo or choose a different output location.",
                file=sys.stderr,
            )
            return 1
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"Failed to generate configuration: {e}", file=sys.stderr)
            return 1
