# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.handlers.kel_handler

KEL (Key Event Log) event handler.
"""

from sentinel.framework import KELEvent
from keri import help

from ..config import SentinelHandlerConfig
from ..services.kel_service import KELService

logger = help.ogler.getLogger()


class KELHandler:
    """Handler for KEL events - manages peer configs based on key state changes."""

    def __init__(self, config: SentinelHandlerConfig):
        self.config = config
        self.service = KELService(config)

    async def process(self, event: KELEvent):
        """
        Process KEL event and update Wireguard configuration.

        When a KERI identifier's keys are rotated, we need to update
        the peer's public key in the Wireguard configuration.
        """
        logger.info(f"Processing KEL event for AID: {event.aid}")

        # Get the AID's current key state
        if event.hby is None:
            logger.warning(f"No KERI Habery available for {event.aid}")
            return

        # Check if this AID has a kever (key event registry)
        kever = event.hby.kevers.get(event.aid)
        if kever is None:
            logger.info(f"AID {event.aid} not found locally - may need to sync")
            return

        # Get current verification key
        current_verfer = kever.verfers[0]
        logger.debug(f"Current verfer for {event.aid}: {current_verfer.qb64}")

        # Update or create Wireguard peer configuration
        await self.service.update_peer_for_aid(
            aid=event.aid,
            verfer=current_verfer,
            kever=kever,
        )

        logger.info(f"KEL event processed for {event.aid}")
