# -*- encoding: utf-8 -*-
"""
keriguard.core.systeming module

Methods for creating IPEX messages

"""

import os
import platform
import re
from enum import StrEnum

from dbus_fast import BusType
from dbus_fast.aio import MessageBus

SYSTEMD_SERVICE = "org.freedesktop.systemd1"
SYSTEMD_OBJECT = "/org/freedesktop/systemd1"
SYSTEMD_MANAGER = "org.freedesktop.systemd1.Manager"

WG_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class WireGuardAction(StrEnum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    RELOAD = "reload"
    RELOAD_OR_RESTART = "reload-or-restart"
    ENABLE = "enable"
    DISABLE = "disable"


class WireGuardControlError(RuntimeError):
    pass


def supports_dbus_systemd() -> bool:
    if platform.system() != "Linux":
        return False

    if not os.path.exists("/run/dbus/system_bus_socket"):
        return False

    if not os.path.exists("/run/systemd/system"):
        return False

    return True


def wg_quick_unit(interface: str) -> str:
    if not WG_IFACE_RE.fullmatch(interface):
        raise ValueError(f"Invalid WireGuard interface name: {interface!r}")

    return f"wg-quick@{interface}.service"


async def call_systemd(action: WireGuardAction, interface: str) -> object:
    unit = wg_quick_unit(interface)

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    introspection = await bus.introspect(SYSTEMD_SERVICE, SYSTEMD_OBJECT)

    proxy = bus.get_proxy_object(
        SYSTEMD_SERVICE,
        SYSTEMD_OBJECT,
        introspection,
    )

    manager = proxy.get_interface(SYSTEMD_MANAGER)

    match action:
        case WireGuardAction.START:
            return await manager.call_start_unit(unit, "replace")

        case WireGuardAction.STOP:
            return await manager.call_stop_unit(unit, "replace")

        case WireGuardAction.RESTART:
            return await manager.call_restart_unit(unit, "replace")

        case WireGuardAction.RELOAD:
            return await manager.call_reload_unit(unit, "replace")

        case WireGuardAction.RELOAD_OR_RESTART:
            return await manager.call_reload_or_restart_unit(unit, "replace")

        case WireGuardAction.ENABLE:
            # runtime=False, force=False
            return await manager.call_enable_unit_files([unit], False, False)

        case WireGuardAction.DISABLE:
            # runtime=False
            return await manager.call_disable_unit_files([unit], False)

        case _:
            raise ValueError(f"Unsupported WireGuard action: {action}")


async def control_wireguard(
    action: WireGuardAction,
    interface: str,
) -> object:
    if supports_dbus_systemd():
        return await call_systemd(action, interface)

    system = platform.system()

    if system == "Darwin":
        raise WireGuardControlError(
            "macOS placeholder: implement launchd or NetworkExtension control here."
        )

    if system == "Windows":
        raise WireGuardControlError(
            "Windows placeholder: implement WireGuardNT service control here."
        )

    if system in {"FreeBSD", "OpenBSD", "NetBSD"}:
        raise WireGuardControlError(
            "BSD placeholder: implement rc.d/service or native wg control here."
        )

    raise WireGuardControlError(
        f"Unsupported platform or missing system D-Bus/systemd: {system}"
    )


async def start_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.START, interface)


async def stop_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.STOP, interface)


async def restart_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.RESTART, interface)


async def reload_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.RELOAD, interface)


async def reload_or_restart_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.RELOAD_OR_RESTART, interface)


async def enable_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.ENABLE, interface)


async def disable_wireguard(interface: str) -> object:
    return await control_wireguard(WireGuardAction.DISABLE, interface)
