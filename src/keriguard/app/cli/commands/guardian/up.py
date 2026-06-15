# -*- encoding: utf-8 -*-
"""
KERI
kerugard.app.cli.commands module

Initialize the KERIGuard server
"""

import argparse
import asyncio

import requests
from keri import help, kering
from keri.app import habbing, connecting
from keri.app.keeping import Algos
from keri.core import parsing, serdering
from keri.help import helping
from keri.kering import ConfigurationError
from sentinel.core.initializing import SentinelConfig

from keriguard.core import querying
from keriguard.core.initializing import (
    load_schema,
    load_oobi,
    authenticate_witness,
    KeriguardConfig,
)
from keriguard.core.wireguarding import SCHEMA_OOBIS, Schema
from keriguard.db.basing import KERIGuardBaser

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description="Initialize a new KERIGuard instance.")
parser.set_defaults(handler=lambda args: asyncio.run(up(args)))
parser.add_argument(
    "--config",
    "-c",
    help="Path to the configuration file",
    required=True,
    default=None,
)
parser.add_argument(
    "--name",
    "-n",
    help="Name of the database environment",
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
    "--alias",
    "-a",
    help="human readable alias for the new identifier prefix",
    required=False,
    default="keriguard",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="21 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)  # passcode => bran
parser.add_argument(
    "--salt",
    "-s",
    help="qualified base64 salt for creating key pairs",
    required=False,
    default=None,
)
parser.add_argument(
    "--log-level",
    default="INFO",
    help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
)
parser.add_argument(
    "--authenticate",
    "-z",
    help="Prompt the controller for authentication codes for each witness",
    action="store_true",
)
parser.add_argument(
    "--sentinel-config-path",
    default=None,
    required=False,
    help="Path to sentinel config file",
)


async def up(args):
    config = KeriguardConfig.load(args.config)
    keriguard_name = args.name
    keriguard_alias = args.alias

    sentinel_name = f"{keriguard_name}-sentinel"
    sentinel_alias = f"{keriguard_alias}-sentinel"

    kwa = dict()
    kwa["salt"] = args.salt
    kwa["bran"] = args.bran
    if args.salt is None:
        kwa["algo"] = Algos.randy

    # Create environment and identifier for the ACDC Auth Server
    keriguard_hby = habbing.Habery(
        name=keriguard_name, base=args.base, temp=False, **kwa
    )
    if not (keriguard_hab := keriguard_hby.habByName(keriguard_alias)):
        keriguard_hab = keriguard_hby.makeHab(
            name=keriguard_alias,
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            toad=0,
        )

    # Create the environment and identifier for the sentinel
    sentinel_hby = habbing.Habery(name=sentinel_name, base=args.base, temp=False, **kwa)
    if not (sentinel_hab := sentinel_hby.habByName(sentinel_alias)):
        sentinel_hab = sentinel_hby.makeHab(
            name=sentinel_alias,
            transferable=False,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            toad=0,
        )

    # Load KERIGuard schema in both databases
    for hby in (sentinel_hby, keriguard_hby):
        load_schema(
            hby=hby,
            schema_oobi=SCHEMA_OOBIS[Schema.INTERFACE_SCHEMA],
            schema_said=Schema.INTERFACE_SCHEMA,
        )
        load_schema(
            hby=hby,
            schema_oobi=SCHEMA_OOBIS[Schema.CONNECTION_SCHEMA],
            schema_said=Schema.CONNECTION_SCHEMA,
        )

    keriguard_org = connecting.Organizer(hby=keriguard_hby)

    icp = sentinel_hab.makeOwnEvent(sn=0)
    parsing.Parser().parse(ims=bytearray(icp), kvy=keriguard_hab.kvy)

    keriguard_org.update(pre=sentinel_hab.pre, data=dict(alias=sentinel_alias))

    print(f"KERIGuard AID generate: {keriguard_hab.pre}")

    while True:
        oobi = input("Enter a witness OOBI (You can add more witness later): ")
        try:
            witness_aid = load_oobi(hby=keriguard_hby, oobi=oobi, alias="witness0")
            break

        except ValueError as err:
            print(err)

    auths = dict()
    if args.authenticate:
        print("Performing witness authentication...")
        authenticate_witness(hab=sentinel_hab, witness=witness_aid)
        code = input(f"Enter code for {witness_aid}: ")
        auths[witness_aid] = f"{code}#{helping.nowIso8601()}"

    print("Now rotating in new witness...")

    raw = keriguard_hab.rotate(
        isith="1", nsith="1", ncount=1, toad=1, adds=[witness_aid]
    )
    serder = serdering.SerderKERI(raw=raw)

    receiptor = querying.Receiptor(hby=keriguard_hby)
    await receiptor.receipt(serder.pre, serder.sn, auths=auths)

    urls = keriguard_hab.fetchUrls(
        eid=witness_aid, scheme=kering.Schemes.http
    ) or keriguard_hab.fetchUrls(eid=witness_aid, scheme=kering.Schemes.https)
    if not urls:
        raise kering.ConfigurationError(
            f"unable to query witness {witness_aid}, no http endpoint"
        )

    url = (
        urls[kering.Schemes.https]
        if kering.Schemes.https in urls
        else urls[kering.Schemes.http]
    )
    keriguard_oobi = f"{url.rstrip("/")}/oobi/{keriguard_hab.pre}/witness"
    print("keriguard OOBI:")
    print(keriguard_oobi)

    # Get keriguard KEL into Sentinel so he can respond to requests.
    load_oobi(hby=sentinel_hby, oobi=keriguard_oobi, alias="keriguard")

    response = requests.get(config.registrar.oobi)
    keriguard_hby.psr.parse(ims=response.content)
    sentinel_hab.psr.parse(ims=response.content)

    response = requests.get(config.issuer.oobi)
    keriguard_hby.psr.parse(ims=response.content)
    sentinel_hab.psr.parse(ims=response.content)

    keriguard_hby.kvy.processEscrows()
    sentinel_hab.kvy.processEscrows()

    if (
        config.registrar.aid not in keriguard_hby.kevers
        or config.issuer.aid not in keriguard_hby.kevers
    ):
        raise ConfigurationError(
            "Unable to resolve configuration root identifiers. Please check your configuration"
        )

    sentinel_config = SentinelConfig()
    sentinel_config.name = sentinel_name
    sentinel_config.alias = sentinel_alias
    sentinel_config.bran = args.bran
    sentinel_config.base = args.base
    sentinel_config.uxd = True
    sentinel_config.local = True
    sentinel_config.export_dir = f"/usr/local/var/sentinel/{args.name}"

    sentinel_config.registrar.aid = config.registrar.aid
    sentinel_config.registrar.oobi = config.registrar.oobi
    sentinel_config.registrar.url = config.registrar.url
    sentinel_config.issuer.aid = config.issuer.aid
    sentinel_config.issuer.oobi = config.issuer.oobi

    if args.sentinel_config_path:
        sentinel_config.save(args.sentinel_config_path)
    else:
        sentinel_config.save(f"/etc/sentinel/{args.name}.yaml")

    kgb = KERIGuardBaser(name=args.name, base=args.base)
    kgb.set_registrar(
        aid=config.registrar.aid,
        oobi=config.registrar.oobi,
        url=config.registrar.url,
        ipaddress=config.registrar.ipaddress,
        endpoint=config.registrar.endpoint,
    )

    kgb.set_issuer(aid=config.issuer.aid, oobi=config.issuer.oobi)
