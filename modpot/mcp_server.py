"""MODPOT MCP server — exposes analyze_capture() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-modpot[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-modpot[mcp]'")
        return 1

    from modpot.core import analyze_capture

    app = FastMCP("modpot")

    @app.tool()
    def modpot_analyze(hexlog: str) -> str:
        """Decode and classify Modbus TCP frames from a newline-separated hex
        capture log. Returns JSON findings as a string."""
        if not hexlog or not hexlog.strip():
            return json.dumps([])
        lines = hexlog.splitlines()
        events = analyze_capture(lines)
        return json.dumps(events)

    app.run()
    return 0
