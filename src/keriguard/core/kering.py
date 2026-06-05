# -*- encoding: utf-8 -*-
"""
keriguard.core.ipexing module

Methods for creating IPEX messages

"""

import asyncio
from datetime import datetime, UTC

from keri import kering
from keri.app import signing, connecting
from keri.core import serdering, parsing, coring
from keri.db import dbing
from keri.help import helping
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing, verifying

from keriguard.core import querying
from keriguard.core.wireguarding import Schema


class Issuer:

    def __init__(self, hby, hab, rgy):
        self.hby = hby
        self.hab = hab
        self.rgy = rgy
        self.exc = exchanging.Exchanger(hby=hby, handlers=[])
        self.org = connecting.Organizer(hby=hby)
        self.registrar = credentialing.Registrar(
            hby=self.hby, rgy=self.rgy, counselor=None
        )
        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.credentialer = credentialing.Credentialer(
            hby=self.hby, rgy=self.rgy, registrar=self.registrar, verifier=self.verifier
        )
        self.receiptor = querying.Receiptor(hby=self.hby)

    async def issue_interface_credential(
        self,
        recipient,
        registry_name,
        interface: dict,
        interface_metadata: dict,
        auths: dict,
    ):
        dt = datetime.now(UTC).isoformat()
        credential_data = {
            "interface": interface,
            "interfaceMetadata": interface_metadata,
            "dt": dt,
        }

        try:
            registry = self.rgy.registryByName(registry_name)
            if registry is None:
                raise kering.ConfigurationError(
                    f"Registry '{registry_name}' not found. "
                    f"Create with: kli vc registry incept --name {self.hby.name} --alias {self.hab.name} "
                    f"--registry-name "
                    f"{registry_name}"
                )

            # Create credential
            creder = self.credentialer.create(
                regname=registry_name,
                recp=recipient,
                schema=Schema.INTERFACE_SCHEMA,
                data=credential_data,
                source=None,
                rules=None,
                private=True,
            )

            iserder = registry.issue(said=creder.said, dt=dt)

            # Anchor to KEL
            rseal = dict(i=creder.said, s=iserder.ked["s"], d=iserder.said)
            anc = self.hab.interact(data=[rseal])

            aserder = serdering.SerderKERI(raw=anc)

            await self.receiptor.receipt(aserder.pre, aserder.sn, auths=auths)

            # Issue to TEL
            prefixer = coring.Prefixer(qb64=iserder.pre)
            seqner = coring.Seqner(sn=iserder.sn)

            try:
                self.verifier.processCredential(
                    creder=creder,
                    prefixer=prefixer,
                    seqner=seqner,
                    saider=coring.Saider(qb64=iserder.said),
                )
            except kering.MissingRegistryError:
                pass

            self.registrar.issue(creder, iserder, aserder, auths=auths)

            snkey = dbing.snKey(creder.said, 0)
            while not self.rgy.reger.getTel(key=snkey):
                self.hab.kvy.processEscrows()
                self.rgy.processEscrows()
                self.credentialer.processEscrows()
                self.verifier.processEscrows()
                await asyncio.sleep(0.1)

            return creder

        except kering.ValidationError as e:
            raise ValueError(f"Credential validation failed: {e}")

        except Exception as e:
            import traceback

            traceback.print_exc()
            raise ValueError(f"Failed to issue credential: {e}")

    async def issue_connection_credential(
        self,
        peers: list,
        auths: dict,
    ):
        """
        Issue a connection credential linking two interface credentials.

        Args:
            peers: List of 2 peer dicts, each containing:
                - interface_said: SAID of the interface credential
                - peer_config: Peer configuration dict with allowedIps, endpoint, and optional persistentKeepalive,
                presharedKey, peerName
                - connection_metadata: Metadata dict with connectionName and optional purpose, environment,
                bandwidthClass
            auths: Authorization dict for the registrar

        Returns:
            The created credential (Creder object)
        """
        if len(peers) != 2:
            raise kering.ConfigurationError(
                f"Exactly 2 peers required, got {len(peers)}"
            )

        # Validate first interface credential and get registry info
        peer1_name = peers[0]["connection_metadata"]["connectionName"]
        peer1_aid = ""
        if (recipient_hab := self.hby.habByName(peer1_name)) is not None:
            peer1_aid = recipient_hab.pre
        else:
            results = self.org.find("alias", peer1_name)
            if results:
                peer1_aid = results[0].get("id")

        if not peer1_aid:
            raise kering.ConfigurationError(
                f"Recipient '{peer1_name}' not found. "
                f"If not local, resolve recipient OOBI first with: kli oobi resolve --name {peer1_name} --oobi-alias <alias> --oobi "
                f"<url>"
            )

        saiders = self.rgy.reger.subjs.get(peer1_aid)
        creder = None
        for saider in saiders:
            (
                c,
                *_,
            ) = self.rgy.reger.cloneCred(said=saider.qb64)
            if c.schema == Schema.INTERFACE_SCHEMA:
                creder = c
                break

        if not creder:
            raise kering.ConfigurationError(
                f"Interface credential for {peer1_name} not found. "
            )

        peers[0]["interface_said"] = creder.said
        recipient = creder.attrib.get("i")
        registry_said = creder.sad.get("ri")
        registry = self.rgy.regs.get(registry_said)

        if registry is None:
            raise kering.ConfigurationError(
                f"Registry '{registry_said}' not found. "
                f"Create with: kli vc registry incept --name {self.hby.name} --alias {self.hab.name} --registry-name "
                f"<REGISTRY_NAME>"
            )

        # Validate second interface credential
        peer2_name = peers[1]["connection_metadata"]["connectionName"]
        peer2_aid = ""
        if (recipient_hab := self.hby.habByName(peer2_name)) is not None:
            peer2_aid = recipient_hab.pre
        else:
            results = self.org.find("alias", peer2_name)
            if results:
                peer2_aid = results[0].get("id")

        if not peer2_aid:
            raise kering.ConfigurationError(
                f"Recipient '{peer2_name}' not found. "
                f"If not local, resolve recipient OOBI first with: kli oobi resolve --name {peer2_name} --oobi-alias <alias> --oobi "
                f"<url>"
            )

        saiders = self.rgy.reger.subjs.get(peer2_aid)
        creder2 = None
        for saider in saiders:
            (
                c,
                *_,
            ) = self.rgy.reger.cloneCred(said=saider.qb64)
            if c.schema == Schema.INTERFACE_SCHEMA:
                creder2 = c
                break

        if not creder2:
            raise kering.ConfigurationError(
                f"Interface credential for {peer1_name} not found. "
            )

        peers[1]["interface_said"] = creder2.said
        dt = datetime.now(UTC).isoformat()
        credential_data = {
            "dt": dt,
        }

        # Build edges array with 2 peer configurations
        edges = {
            "d": "",
            "peer1": {
                "n": creder.said,
                "s": Schema.INTERFACE_SCHEMA,
                "o": "NI2I",
                **peers[0]["peer_config"],
                "connectionMetadata": peers[0]["connection_metadata"],
            },
            "peer2": {
                "n": creder2.said,
                "s": Schema.INTERFACE_SCHEMA,
                "o": "NI2I",
                **peers[1]["peer_config"],
                "connectionMetadata": peers[1]["connection_metadata"],
            },
        }

        _, edges = coring.Saider.saidify(sad=edges)

        try:
            # Create credential with edges
            creder = self.credentialer.create(
                regname=registry.name,
                recp=recipient,
                schema=Schema.CONNECTION_SCHEMA,
                data=credential_data,
                source=edges,
                rules=None,
                private=True,
            )

            iserder = registry.issue(said=creder.said, dt=dt)

            # Anchor to KEL
            rseal = dict(i=creder.said, s=iserder.ked["s"], d=iserder.said)
            anc = self.hab.interact(data=[rseal])

            aserder = serdering.SerderKERI(raw=anc)

            await self.receiptor.receipt(aserder.pre, aserder.sn, auths=auths)

            # Issue to TEL
            prefixer = coring.Prefixer(qb64=iserder.pre)
            seqner = coring.Seqner(sn=iserder.sn)

            try:
                self.verifier.processCredential(
                    creder=creder,
                    prefixer=prefixer,
                    seqner=seqner,
                    saider=coring.Saider(qb64=iserder.said),
                )
            except kering.MissingRegistryError:
                pass

            self.registrar.issue(creder, iserder, aserder, auths=auths)

            snkey = dbing.snKey(creder.said, 0)
            while not self.rgy.reger.getTel(key=snkey):
                self.hab.kvy.processEscrows()
                self.rgy.processEscrows()
                self.credentialer.processEscrows()
                self.verifier.processEscrows()
                await asyncio.sleep(0.1)

            return creder

        except kering.ValidationError as e:
            raise ValueError(f"Credential validation failed: {e}")

        except Exception as e:
            import traceback

            traceback.print_exc()
            raise ValueError(f"Failed to issue connection credential: {e}")

    def grant(self, credential_said, recipient):
        creder, prefixer, seqner, saider = self.rgy.reger.cloneCred(
            said=credential_said
        )
        if creder is None:
            raise ValueError(f"invalid credential SAID to grant={credential_said}")

        acdc = signing.serialize(creder, prefixer, seqner, saider)

        reg = self.rgy.reger.cloneTvtAt(creder.regi)
        iss = self.rgy.reger.cloneTvtAt(creder.said)

        iserder = serdering.SerderKERI(raw=bytes(iss))
        seqner = coring.Seqner(sn=iserder.sn)

        serder = self.hab.db.fetchLastSealingEventByEventSeal(
            creder.sad["i"], seal=dict(i=iserder.pre, s=seqner.snh, d=iserder.said)
        )
        anc = self.hab.db.cloneEvtMsg(pre=serder.pre, fn=0, dig=serder.said)

        timestamp = helping.nowIso8601()
        exn, atc = protocoling.ipexGrantExn(
            hab=self.hab,
            recp=recipient,
            message="",
            acdc=acdc,
            reg=reg,
            iss=iss,
            anc=anc,
            dt=timestamp,
        )
        msg = bytearray(exn.raw)
        msg.extend(atc)

        parsing.Parser().parseOne(ims=bytes(msg), exc=self.exc)

        return msg
