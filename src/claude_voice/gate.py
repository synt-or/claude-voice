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
# The owner's own browser opens these, not the assistant's servers.
SIGN_IN_PATHS = frozenset({"/authorize", "/oauth/consent"})


def _networks(values: list[str]) -> list:
    return [ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip()]


class AddressGate:
    def __init__(
        self, app: ASGIApp, allowed: list[str], header: str | None = None, sign_in: list[str] | None = None
    ) -> None:
        self.app = app
        self.allowed = _networks(allowed)
        # Empty: the sign-in pages are open to every address, and the login secret guards them.
        self.sign_in = _networks(sign_in or [])
        self.header = header.lower().encode() if header else None

    def caller(self, scope: Scope) -> str:
        if self.header:
            values = [v for k, v in scope.get("headers", []) if k == self.header]
            if values:
                return values[-1].decode("latin-1").split(",")[-1].strip()
        client = scope.get("client")
        return client[0] if client else ""

    def admits(self, address: str, path: str = "") -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if path in SIGN_IN_PATHS:
            # RULE: the sign-in pages open only to the owner's own networks, when they are named
            return not self.sign_in or any(ip in net for net in self.sign_in)
        # Behind a tunnel every connection is local, so loopback proves nothing there.
        # RULE: behind a tunnel, a request without the tunnel's header is a stranger
        return (ip.is_loopback and not self.header) or any(ip in net for net in self.allowed)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.allowed or scope["path"] in OPEN_PATHS:
            await self.app(scope, receive, send)
            return
        address = self.caller(scope)
        # RULE: from the internet, only allowed addresses get past the gate
        if not self.admits(address, scope["path"]):
            log.warning("gate: refused %s %s", address or "?", scope["path"])
            await PlainTextResponse("forbidden", 403)(scope, receive, send)
            return
        await self.app(scope, receive, send)
