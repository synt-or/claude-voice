"""Let only known addresses reach the bridge from the internet.

Behind a tunnel every connection comes from 127.0.0.1, so the caller's address
is read from a header the tunnel appends. Only its last value is trusted: the
tunnel adds it, while anything before it came from the caller.
"""

from __future__ import annotations

import ipaddress
import logging

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger("claude_voice.gate")
OPEN_PATHS = frozenset({"/healthz"})


class AddressGate:
    def __init__(self, app: ASGIApp, allowed: list[str], header: str | None = None) -> None:
        self.app = app
        self.allowed = [ipaddress.ip_network(a.strip(), strict=False) for a in allowed if a.strip()]
        self.header = header.lower().encode() if header else None

    def caller(self, scope: Scope) -> str:
        if self.header:
            values = [v for k, v in scope.get("headers", []) if k == self.header]
            if values:
                return values[-1].decode("latin-1").split(",")[-1].strip()
        client = scope.get("client")
        return client[0] if client else ""

    def admits(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return ip.is_loopback or any(ip in net for net in self.allowed)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.allowed or scope["path"] in OPEN_PATHS:
            await self.app(scope, receive, send)
            return
        address = self.caller(scope)
        # RULE: from the internet, only allowed addresses get past the gate
        if not self.admits(address):
            log.warning("gate: refused %s %s", address or "?", scope["path"])
            await PlainTextResponse("forbidden", 403)(scope, receive, send)
            return
        await self.app(scope, receive, send)
