#!/usr/bin/env python3
"""Run the homebox MCP server over Streamable HTTP instead of stdio.

Upstream ships stdio only (``main()`` calls ``mcp.run()`` with no transport),
which means one server process per MCP client session. This launcher runs a
single shared instance bound to loopback, so a reverse proxy in front of it can
serve every client from one process.

Kept as a separate module so a rebase onto upstream never conflicts: nothing in
``homebox_mcp.py`` is modified.

The server has **no authentication of its own** — FastMCP from the reference
SDK does not provide any. The bind address must stay on loopback and the proxy
in front of it must enforce a bearer token. Do not set HOMEBOX_MCP_HOST to
0.0.0.0.

Environment:
    HOMEBOX_MCP_HOST           bind address (default 127.0.0.1)
    HOMEBOX_MCP_PORT           bind port (default 3003)
    HOMEBOX_MCP_PUBLIC_HOST    public Host header the proxy forwards, e.g.
                               ``mcp.example.com``. Comma-separated for several.
                               Required when a proxy fronts the server — see below.
    plus everything homebox_mcp.py itself reads (HOMEBOX_URL, HOMEBOX_TOKEN)

DNS-rebinding protection stays **on**. FastMCP enables it automatically for a
loopback bind and then only accepts ``Host: 127.0.0.1``/``localhost``, so every
request arriving through a proxy is rejected with ``421 Invalid Host header``.
The fix is to allowlist the public name rather than to disable the check.
"""

from __future__ import annotations

import os
import sys

from mcp.server.transport_security import TransportSecuritySettings

from homebox_mcp import mcp


def main() -> None:
    host = os.environ.get("HOMEBOX_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("HOMEBOX_MCP_PORT", "3003"))

    if host not in ("127.0.0.1", "::1", "localhost"):
        sys.stderr.write(
            f"launch_http: refusing to bind {host} — this server has no auth of "
            "its own; keep it on loopback behind an authenticating proxy.\n"
        )
        raise SystemExit(2)

    allowed_hosts = ["127.0.0.1", f"127.0.0.1:{port}", "localhost", f"localhost:{port}"]
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
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
