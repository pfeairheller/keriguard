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
from keri import kering
from keri.app.cli.common import existing
from keri.app.httping import CESR_CONTENT_TYPE
from keri.vdr import credentialing

from keriguard.core.kering import Issuer

parser = argparse.ArgumentParser(
    description="Publish a KERI credential for Wireguard peer connection configuration."
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
    "--said",
    action="store",
    required=True,
    help="The qb64 said of the peer credential to publish",
)

parser.add_argument(
    "--registrar-url",
    type=str,
    required=True,
    default=None,
    help="URL to send grant data via PUT request (mutually exclusive with --output)",
)


logger = help.ogler.getLogger()


async def issue_credential(args):
    """Issue a KERI credential for Wireguard peer connection configuration."""
    name = args.name
    alias = args.alias
    bran = args.bran

    # Load existing Hab
    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        # Create Regery
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

        issuer = Issuer(hby=hby, hab=hab, rgy=rgy)

        print(
            f"Publishing peer connection credential using KERI identity: {hab.pre}",
            file=sys.stderr,
        )

        try:
            creder, *_ = rgy.reger.cloneCred(said=args.said)
            if not creder:
                print("Credential not found", file=sys.stderr)
                return 1

            # Output credential grant
            grant = issuer.grant(creder.said, creder.attrib.get("i"))

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
                print(f"Failed to send grant to registrar: {e}", file=sys.stderr)
                return 1

            # Success message
            print("\n✓ Connection credential published successfully")
            print(f"  Credential SAID: {creder.said}")
            print(f"  Recipient: {creder.attrib.get('i')}")
            print(f"  Registrar URL: {args.registrar_url}")

            return 0

        except kering.ValidationError as e:
            print(f"Credential validation failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"Failed to issue credential: {e}", file=sys.stderr)
            return 1
