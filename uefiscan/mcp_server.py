"""UEFISCAN MCP server -- exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from uefiscan.core import audit_image


def serve() -> int:
    """Start an MCP stdio server. Requires the optional mcp extra:
        pip install "cognis-uefiscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-uefiscan[mcp]'")
        return 1
    app = FastMCP("uefiscan")

    @app.tool()
    def uefiscan_scan(target: str) -> str:
        """Audit a UEFI firmware dump for Secure Boot and module signing issues.

        Returns JSON findings including verdict, firmware volumes, Secure Boot
        key variables, and per-module signing status.
        """
        try:
            result = audit_image(target)
        except FileNotFoundError:
            return json.dumps({"error": "file not found", "target": target})
        except OSError as exc:
            return json.dumps({"error": str(exc), "target": target})
        return json.dumps(result.to_dict())

    app.run()
    return 0
