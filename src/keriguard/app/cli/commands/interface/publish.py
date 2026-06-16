# -*- encoding: utf-8 -*-
"""
keriguard.app.cli module

Issue KERI credentials for Wireguard interface configuration.
"""

import argparse
import asyncio
import sys

import httpx
from keri import help
from keri.app.httping import CESR_CONTENT_TYPE
from keri import kering
from keri.app import connecting
from keri.app.cli.common import existing
from keri.help import helping
from keri.peer import exchanging
from keri.vdr import credentialing

from keriguard.core.kering import Issuer
from keriguard.core.wireguarding import Schema

parser = argparse.ArgumentParser(
    description="Publish a previously issued KERI credential for Wireguard interface configuration."
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

# Credential issuance arguments
parser.add_argument(
    "--recipient",
    "-r",
    required=True,
    help="AID of the credential recipient (issuee)",
)
parser.add_argument(
    "--registrar-url",
    type=str,
    required=True,
    default=None,
    help="URL to send grant data via PUT request",
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
        recipient_name = ""
        if args.recipient not in hby.kevers:
            if (recipient_hab := hby.habByName(args.recipient)) is not None:
                recipient = recipient_hab.pre
                recipient_name = recipient_hab.alias
            else:
                org = connecting.Organizer(hby=hby)
                results = org.find("alias", args.recipient)
                if not results:
                    raise kering.ConfigurationError(
                        f"Recipient '{args.recipient}' not found. "
                        f"Resolve recipient OOBI first with: kli oobi resolve --name {name} --oobi-alias <alias> --oobi <url>"
                    )
                recipient = results[0].get("id")
                recipient_name = args.recipient

        else:
            recipient = args.recipient

        org = connecting.Organizer(hby=hby)
        result = org.get(recipient)
        if not result:
            raise kering.ConfigurationError(
                f"Recipient '{args.recipient}' not a contact. "
                f"Resolve recipient OOBI first with: kli oobi resolve --name {name} --oobi-alias <alias> --oobi <url>"
            )

        oobi = result.get("oobi")

        # Create Regery
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

        issuer = Issuer(hby=hby, hab=hab, rgy=rgy)
        # Validate listen port range (schema requirement)

        try:
            creders = []
            for saider in rgy.reger.subjs.get(keys=recipient):
                said = saider.qb64
                creder, *_ = rgy.reger.cloneCred(said=said)
                if creder.sad.get("s") == Schema.INTERFACE_SCHEMA:
                    creders.append(creder)

            if len(creders) == 0:
                print(f"No interface credentials found for recipient {args.recipient}")
                return -1

            elif len(creders) > 1:
                print(
                    f"Multiple interface credentials found for recipient {args.recipient}, please enter the number of the one to publish:"
                )
                output_choices(creders)

                while True:
                    print(
                        f"\n\nMultiple interface credentials found for recipient {args.recipient}"
                    )
                    output_choices(creders)
                    num = input(
                        "Please enter the number of the credential to publish: "
                    )
                    try:
                        num = int(num)
                        if num < 1 or num > len(creders):
                            print("Invalid number, please try again.")
                            continue
                        creder = creders[num - 1]
                        break
                    except ValueError:
                        print("\vInvalid input, please enter a number.")
                        continue
            else:
                creder = creders[0]

            grant = issuer.grant(creder.said, recipient)

            if args.registrar_url:
                data = dict(aid=recipient, alias=recipient_name, oobi=oobi)
                exn, end = exchanging.exchange(
                    route="/introduction",
                    payload=data,
                    sender=hab.pre,
                    date=helping.nowIso8601(),
                )
                introduction = hab.endorse(serder=exn, last=False, pipelined=False)

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

                    # Send introduction data to registrar via PUT request
                    response = httpx.put(
                        args.registrar_url,
                        content=bytes(introduction),
                        headers={"Content-Type": CESR_CONTENT_TYPE},
                        timeout=30.0,
                    )
                    response.raise_for_status()

                except httpx.HTTPError as e:
                    print(f"Failed to send grant to registrar: {e}", file=sys.stderr)
                    return 1

            # Success message
            print("\n✓ Interface credential published successfully")
            print(f"  Credential SAID: {creder.said}")
            print(f"  Recipient: {recipient}")
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


def output_choices(creders):
    print(f"{'Number':<10} {'Name':<20}  {'Address':<20}  Port")
    print("-" * 95)

    # Print rows
    for idx, creder in enumerate(creders):
        payload = creder.attrib
        interface_data = payload.get("interface", {})
        metadata = payload.get("interfaceMetadata", {})

        name = metadata["interfaceName"][:19]

        addr = ", ".join(interface_data.get("address", "N/A"))
        port = str(interface_data.get("listenPort", "auto"))

        print(f"{str(idx+1)+".":<10} {name:<20}  {addr:<20}  {port}")

    print()
