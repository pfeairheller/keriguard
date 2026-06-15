# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.healthKERI.db.basing module

Sentinel-specific  database (SentinelBaser).

"""

from dataclasses import dataclass
from typing import Optional

from keri.db import dbing, koming


@dataclass
class Registrar:
    """
    Registrar record
    """

    aid: str
    oobi: str
    url: Optional[str] = None
    ipaddress: Optional[str] = None
    endpoint: Optional[str] = None


@dataclass
class Issuer:
    """
    Issuer record
    """

    aid: str
    oobi: str


class KERIGuardBaser(dbing.LMDBer):
    """Plugin-owned database for healthKERI state.

    Manages healthKERI accounts, teams, and witness provisioning state
    in a separate LMDB from the core LocksmithBaser.
    """

    TailDirPath = "keri/hk"
    AltTailDirPath = ".keri/hk"
    TempPrefix = "hk"

    def __init__(self, name="keriguard", headDirPath=None, reopen=True, **kwa):
        self.registrar = None
        self.issuer = None

        super(KERIGuardBaser, self).__init__(
            name=name, headDirPath=headDirPath, reopen=reopen, **kwa
        )

    def reopen(self, **kwa):
        super(KERIGuardBaser, self).reopen(**kwa)

        # Most recent witness query records
        self.registrar = koming.Komer(db=self, subkey="rar.", schema=Registrar)

        # Most recent witness query records
        self.issuer = koming.Komer(db=self, subkey="iss.", schema=Issuer)

        return self.env

    def set_registrar(
        self,
        aid: str,
        oobi: str,
        url: Optional[str] = None,
        ipaddress: Optional[str] = None,
        endpoint: Optional[str] = None,
    ):
        self.registrar.pin(
            keys=("registrar",),
            val=Registrar(
                aid=aid, oobi=oobi, url=url, ipaddress=ipaddress, endpoint=endpoint
            ),
        )

    def get_registrar(self):
        return self.registrar.get(keys=("registrar",))

    def set_issuer(self, aid: str, oobi: str):
        self.issuer.pin(keys=("issuer",), val=Issuer(aid=aid, oobi=oobi))

    def get_issuer(self):
        return self.issuer.get(keys=("issuer",))
