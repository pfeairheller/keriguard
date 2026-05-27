# -*- encoding: utf-8 -*-
"""
keriguard.app.cli module

"""

import argparse
import asyncio
import sys

from keri import help
from keri.app.cli.common import existing
from keri.core import serdering, parsing, coring
from keri.peer import exchanging
from keri.vdr import credentialing, verifying

from keriguard.app.sentinel.services import CredService
from keriguard.core.wireguarding import Schema

parser = argparse.ArgumentParser(
    description="Process a KERIGuard credential and generate Wireguard configuration"
)
parser.set_defaults(handler=lambda args: asyncio.run(process(args)))
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
)  # passcode => bran

# Required arguments for Wireguard configuration
parser.add_argument(
    "--file",
    "-f",
    required=True,
    help="Credential file to load",
)

# Required arguments for Wireguard configuration
parser.add_argument(
    "--export-dir",
    required=False,
    default=".",
    help="Directory to export Wireguard configuration files",
)


logger = help.ogler.getLogger()


async def process(args):
    """Generate a Wireguard interface configuration with KERI-tracked keys."""
    name = args.name
    bran = args.bran

    if not name:
        print("Interface name is required.")
        sys.exit(1)

    data = None
    with open(args.file, "br") as file:
        data = file.read()

    if not data:
        print("KERIGuard credential file is empty or does not exist.")
        return 1

    with existing.existingHby(name=name, base=args.base, bran=bran) as (hby):
        grant = serdering.SerderKERI(raw=bytes(data))

        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        verifier = verifying.Verifier(hby=hby, reger=rgy.reger)
        psr = parsing.Parser(kvy=hby.kvy, tvy=rgy.tvy, vry=verifier, exc=exc)

        psr.parse(data)
        psr.kvy.processEscrows()
        rgy.tvy.processEscrows()
        verifier.processEscrows()

        pserder, pathed = exchanging.cloneMessage(hby, said=grant.said)
        embeds = grant.ked["e"]
        acdc = embeds["acdc"]
        # issr = acdc['i']

        for label in ("anc", "reg", "iss", "acdc"):
            ked = embeds[label]
            sadder = coring.Sadder(ked=ked)
            ims = bytearray(sadder.raw) + pathed[label]
            psr.parseOne(ims=ims)

        creder = serdering.SerderACDC(sad=acdc)

        if rgy.reger.saved.get(keys=(creder.said,)):

            service = CredService(hby, rgy, args.export_dir)
            match creder.schema:
                case Schema.INTERFACE_SCHEMA:
                    await service.process_interface_credential(creder.said, creder)
                case Schema.CONNECTION_SCHEMA:
                    await service.process_connection_credential(creder.said, creder)
                case _:
                    print(f"Unknown credential schema: {creder.schema}")
                    return -1

            return 0

        print("Credential did not parse correctly")
        return 1
