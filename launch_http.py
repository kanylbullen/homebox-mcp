#!/usr/bin/env python3
"""Run the homebox MCP server over Streamable HTTP instead of stdio.

Upstream ships stdio only (``main()`` calls ``mcp.run()`` with no transport),
which means one server process per MCP client session. This launcher runs a
single shared instance, so one process can serve every client.

Kept as a separate module so a rebase onto upstream never conflicts: nothing in
``homebox_mcp.py`` is modified.

Two things make this safe to expose beyond loopback:

``HOMEBOX_MCP_BEARER``
    Enables in-process bearer authentication. The check happens here, in the
    server, rather than in a reverse proxy — so the server does not depend on a
    proxy rule staying correct. Without it the server binds loopback only.

``HOMEBOX_MCP_EXCLUDE_TOOLS``
    Comma-separated tool names to unregister before serving. Excluded tools do
    not appear in ``tools/list`` and cannot be called: they are removed at
    startup, not filtered at call time. Use it to keep destructive tools off an
    instance that is reachable from the internet.

DNS-rebinding protection stays **on**. FastMCP enables it automatically for a
loopback bind and then only accepts ``Host: 127.0.0.1``/``localhost``, so every
request arriving through a proxy is rejected with ``421 Invalid Host header``.
``HOMEBOX_MCP_PUBLIC_HOST`` allowlists the public name rather than turning the
check off.

Environment:
    HOMEBOX_MCP_HOST            bind address (default 127.0.0.1)
    HOMEBOX_MCP_PORT            bind port (default 3003)
    HOMEBOX_MCP_PUBLIC_HOST     public Host header(s) the proxy forwards, comma-separated
    HOMEBOX_MCP_BEARER          static bearer token; required for a non-loopback bind
    HOMEBOX_MCP_EXCLUDE_TOOLS   comma-separated tool names to unregister
    HOMEBOX_MCP_RATE_LIMIT      requests per window per client (0 = off, the default)
    HOMEBOX_MCP_RATE_WINDOW     window in seconds (default 60)
    plus everything homebox_mcp.py itself reads (HOMEBOX_URL, HOMEBOX_TOKEN)
"""

from __future__ import annotations

import hmac
import os
import sys
import time
from collections import OrderedDict, deque

from mcp.server.transport_security import TransportSecuritySettings

from homebox_mcp import mcp

LOOPBACK = ("127.0.0.1", "::1", "localhost")

# Cap on distinct clients tracked by the rate limiter. Without it, an attacker
# rotating source addresses grows the table without bound — turning the defence
# into the memory-exhaustion vector.
RATE_MAX_TRACKED = 4096


class RateLimit:
    """Sliding-window per-client rate limit.

    Keys on the client address, read from ``CF-Connecting-IP`` when present and
    otherwise from the socket peer.

    That header choice matters. Behind a tunnel or reverse proxy every request
    arrives from the connector's own address, so keying on the socket peer puts
    every client in **one shared bucket** — legitimate users then throttle each
    other while an attacker still gets the full allowance. The header is only
    trustworthy because nothing but the connector can reach this port; if that
    stops being true, this becomes spoofable and the limit becomes worthless.
    """

    def __init__(self, app, limit: int, window: float) -> None:
        self.app = app
        self.limit = limit
        self.window = window
        self.hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _client(self, scope) -> str:
        headers = dict(scope.get("headers") or [])
        fwd = headers.get(b"cf-connecting-ip") or headers.get(b"x-forwarded-for")
        if fwd:
            return fwd.decode("latin-1").split(",")[0].strip()
        peer = scope.get("client")
        return peer[0] if peer else "unknown"

    def _allow(self, key: str, now: float) -> bool:
        bucket = self.hits.get(key)
        if bucket is None:
            if len(self.hits) >= RATE_MAX_TRACKED:
                self.hits.popitem(last=False)
            bucket = self.hits[key] = deque()
        else:
            self.hits.move_to_end(key)
        cutoff = now - self.window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if not self._allow(self._client(scope), time.monotonic()):
            retry = str(int(self.window)).encode()
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"retry-after", retry),
                ],
            })
            await send({"type": "http.response.body", "body": b'{"error":"rate limited"}'})
            return

        await self.app(scope, receive, send)


class BearerGate:
    """ASGI middleware enforcing a static bearer token.

    Compares in constant time and answers with a spec-shaped
    ``WWW-Authenticate`` header. Non-HTTP scopes (``lifespan``) pass straight
    through, so the session manager still starts and stops normally.
    """

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}"

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        presented = headers.get(b"authorization", b"").decode("latin-1")

        if not hmac.compare_digest(presented, self.expected):
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Bearer realm="homebox-mcp"'),
                ],
            })
            await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
            return

        await self.app(scope, receive, send)


def main() -> None:
    host = os.environ.get("HOMEBOX_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("HOMEBOX_MCP_PORT", "3003"))
    bearer = os.environ.get("HOMEBOX_MCP_BEARER", "").strip()

    if host not in LOOPBACK and not bearer:
        sys.stderr.write(
            f"launch_http: refusing to bind {host} without HOMEBOX_MCP_BEARER — "
            "an unauthenticated bind exposes every registered tool.\n"
        )
        raise SystemExit(2)
    if bearer and len(bearer) < 32:
        sys.stderr.write("launch_http: HOMEBOX_MCP_BEARER is shorter than 32 characters.\n")
        raise SystemExit(2)

    excluded = [t.strip() for t in os.environ.get("HOMEBOX_MCP_EXCLUDE_TOOLS", "").split(",")]
    excluded = [t for t in excluded if t]
    known = {t.name for t in mcp._tool_manager.list_tools()}
    unknown = [t for t in excluded if t not in known]
    if unknown:
        # A typo here would silently leave a destructive tool registered, which
        # is the opposite of what the caller asked for. Fail loudly instead.
        sys.stderr.write(f"launch_http: unknown tool(s) in EXCLUDE_TOOLS: {unknown}\n")
        raise SystemExit(2)
    for name in excluded:
        mcp.remove_tool(name)

    allowed_hosts = [
        f"{h}{suffix}" for h in ("127.0.0.1", "localhost") for suffix in ("", f":{port}")
    ]
    allowed_origins: list[str] = []
    for name in os.environ.get("HOMEBOX_MCP_PUBLIC_HOST", "").split(","):
        name = name.strip()
        if not name:
            continue
        allowed_hosts += [name, f"{name}:*"]
        allowed_origins += [f"https://{name}", f"https://{name}:*"]

    mcp.settings.host = host
    mcp.settings.port = port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

    remaining = len(mcp._tool_manager.list_tools())
    sys.stderr.write(
        f"launch_http: {remaining} tool(s) registered"
        f"{f', {len(excluded)} excluded' if excluded else ''}"
        f", auth={'on' if bearer else 'off'}, bind={host}:{port}\n"
    )

    if not bearer:
        mcp.run(transport="streamable-http")
        return

    import uvicorn

    app = BearerGate(mcp.streamable_http_app(), bearer)

    limit = int(os.environ.get("HOMEBOX_MCP_RATE_LIMIT", "0"))
    if limit > 0:
        window = float(os.environ.get("HOMEBOX_MCP_RATE_WINDOW", "60"))
        # Outside the bearer gate on purpose: unauthenticated hammering is
        # exactly what needs throttling, and it must not be free.
        app = RateLimit(app, limit, window)
        sys.stderr.write(f"launch_http: rate limit {limit} req / {window:g}s per client\n")

    uvicorn.run(app, host=host, port=port, log_level=mcp.settings.log_level.lower())


if __name__ == "__main__":
    main()
