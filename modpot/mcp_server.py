"""MODPOT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from modpot.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-modpot[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-modpot[mcp]'")
        return 1
    app = FastMCP("modpot")

    @app.tool()
    def modpot_scan(target: str) -> str:
        """Spin up a high-interaction Modbus/DNP3 ICS honeypot that logs attacker register reads/writes as structured JSON.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
