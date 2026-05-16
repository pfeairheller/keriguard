# -*- encoding: utf-8 -*-
"""
keriguard.app.cli.commands.peer.add module

CLI command to add a peer to an existing Wireguard configuration file.
"""

import argparse
import asyncio
import shutil
import sys
from pathlib import Path

from keri import help
from keri import kering
from keri.app.cli.common import existing

from keriguard.core.wireguarding import (
    WireguardConfigManager,
    WireguardConfigParser,
    WireguardConfigWriter,
    WireguardPeer,
    ValidationError as WireguardValidationError,
    ConfigParseError,
    ConfigWriteError,
)

parser = argparse.ArgumentParser(
    description="Add a peer to an existing Wireguard configuration file."
)
parser.set_defaults(handler=lambda args: asyncio.run(add_peer(args)))

# Required arguments
parser.add_argument(
    "--config",
    "-c",
    required=True,
    type=str,
    help="Path to existing Wireguard configuration file",
)

parser.add_argument(
    "--public-key",
    "-k",
    type=str,
    help="Peer's public key (base64-encoded, 32 bytes). Required unless --keri-aid is used.",
)

parser.add_argument(
    "--allowed-ips",
    "-i",
    required=True,
    action="append",
    help="IP address or CIDR block the peer can route (can be specified multiple times)",
)

# Optional peer parameters
parser.add_argument(
    "--endpoint",
    "-e",
    type=str,
    default=None,
    help="Peer endpoint in format host:port or [IPv6]:port",
)

parser.add_argument(
    "--keepalive",
    type=int,
    default=None,
    help="Persistent keepalive interval in seconds (1-300)",
)

parser.add_argument(
    "--preshared-key",
    "--psk",
    type=str,
    default=None,
    help="Base64-encoded preshared key (32 bytes)",
)

parser.add_argument(
    "--name",
    "-n",
    type=str,
    default=None,
    help="Human-readable name for this peer",
)

# Key generation options (KERI integration)
parser.add_argument(
    "--keri-aid",
    type=str,
    default=None,
    help="Auto-generate keypair from KERI AID current signing key (alternative to --public-key)",
)

parser.add_argument(
    "--keystore-name",
    type=str,
    default="keriguard",
    help="KERI keystore name (for key generation, default: keriguard)",
)

parser.add_argument(
    "--keystore-alias",
    type=str,
    default="keriguard",
    help="KERI Hab alias (for key generation, default: owl)",
)

parser.add_argument(
    "--keystore-base",
    type=str,
    default="",
    help="Additional prefix to KERI keystore location (for key generation)",
)

parser.add_argument(
    "--passcode",
    "-p",
    type=str,
    dest="bran",
    default=None,
    help="21 character encryption passcode for KERI keystore (for key generation)",
)

# Output options
parser.add_argument(
    "--force",
    "-f",
    action="store_true",
    help="Overwrite config file without creating backup",
)

logger = help.ogler.getLogger()


async def add_peer(args):
    """Add a peer to an existing Wireguard configuration."""
    config_path = Path(args.config)

    # Validate config file exists
    if not config_path.exists():
        print(f"Error: Configuration file not found: {config_path}", file=sys.stderr)
        return 1

    if not config_path.is_file():
        print(f"Error: Path is not a file: {config_path}", file=sys.stderr)
        return 1

    # Validate public key requirements
    if not args.public_key and not args.keri_aid:
        print(
            "Error: Either --public-key or --keri-aid must be specified",
            file=sys.stderr,
        )
        return 1

    if args.public_key and args.keri_aid:
        print(
            "Error: Cannot specify both --public-key and --keri-aid",
            file=sys.stderr,
        )
        return 1

    try:
        # Determine backup path
        backup = not args.force
        backup_path = config_path.with_suffix(config_path.suffix + ".bak")

        # Load existing configuration
        # For key generation, we need a Hab; for manual keys, we don't
        if args.keri_aid:
            # Load KERI Hab for key generation
            with existing.existingHab(
                name=args.keystore_name,
                alias=args.keystore_alias,
                base=args.keystore_base,
                bran=args.bran,
            ) as (hby, hab):
                if not hab:
                    raise kering.ConfigurationError(
                        f"Identifier '{args.keystore_alias}' must already exist. "
                        f"Create one first using KERI's 'kli init' command."
                    )

                manager = WireguardConfigManager(hab=hab)
                config = manager.load_config(config_path)

                # Generate peer with auto-generated keys
                print(f"Generating peer keys using KERI identity: {hab.pre}")
                peer = manager.add_peer_to_config(
                    config,
                    allowed_ips=args.allowed_ips,
                    endpoint=args.endpoint,
                    persistent_keepalive=args.keepalive,
                    preshared_key=args.preshared_key,
                    peer_name=args.name,
                    keri_aid=args.keri_aid,
                    # public_key not provided - will auto-generate
                )

                # Save updated configuration
                manager.save_config(config, config_path, backup=backup)

                # Display success message
                print(f"\nPeer added to: {config_path}")
                if args.name:
                    print(f"Peer name: {args.name}")
                print(f"Public key: {peer.public_key}")
                print(f"Allowed IPs: {', '.join(peer.allowed_ips)}")
                if peer.endpoint:
                    print(f"Endpoint: {peer.endpoint}")
                if peer.persistent_keepalive:
                    print(f"Keepalive: {peer.persistent_keepalive}s")
                if peer.keri_aid_qb64:
                    print(f"KERI AID: {peer.keri_aid_qb64}")

        else:
            # Manual public key - no Hab needed
            # Use Parser/Writer directly since WireguardConfigManager requires Hab
            config = WireguardConfigParser.parse_file(config_path)

            # Create peer manually
            print("Adding peer with provided public key")
            peer = WireguardPeer(
                public_key=args.public_key,
                allowed_ips=args.allowed_ips,
                endpoint=args.endpoint,
                persistent_keepalive=args.keepalive,
                preshared_key=args.preshared_key,
                peer_name=args.name,
                keri_aid_qb64=None,
            )

            config.add_peer(peer)

            # Save updated configuration with backup
            if backup and config_path.exists():
                shutil.copy2(config_path, backup_path)

            WireguardConfigWriter.write_file(config, config_path)

            # Display success message
            print(f"\nPeer added to: {config_path}")
            if args.name:
                print(f"Peer name: {args.name}")
            print(f"Public key: {peer.public_key}")
            print(f"Allowed IPs: {', '.join(peer.allowed_ips)}")
            if peer.endpoint:
                print(f"Endpoint: {peer.endpoint}")
            if peer.persistent_keepalive:
                print(f"Keepalive: {peer.persistent_keepalive}s")

        # Display backup message if created
        if backup and backup_path.exists():
            print(f"\nBackup created: {backup_path}")

        print(f"\nTotal peers in configuration: {len(config.peers)}")

    except WireguardValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return 1
    except ConfigParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1
    except ConfigWriteError as e:
        print(f"Write error: {e}", file=sys.stderr)
        return 1
    except kering.ConfigurationError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Permission denied: {config_path}", file=sys.stderr)
        print(
            "Try running with sudo or ensure you have write permissions.",
            file=sys.stderr,
        )
        return 1
    except Exception as e:
        print(f"Failed to add peer: {e}", file=sys.stderr)
        return 1

    return 0
