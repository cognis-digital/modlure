"""MODLURE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from modlure.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "modlure[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'modlure[mcp]'")
        return 1
    app = FastMCP("modlure")

    @app.tool()
    def modlure_scan(target: str) -> str:
        """Spin up a high-interaction Modbus/DNP3 ICS honeypot that logs attacker register reads/writes as structured JSON.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
