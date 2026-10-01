"""MCP server exposing the sonic-rca tool surface over stdio.

Requires the `mcp` package (pip install mcp). Any MCP-capable client/model
can drive these tools — the LLM is a replaceable component by construction.
"""
from __future__ import annotations

from . import mcp_tools as T


def build_server():
    try:  # mcp >= 2.0 renamed FastMCP to MCPServer
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer
    srv = MCPServer("sonic-rca")
    for name in ("load_dump", "source_info", "get_db", "trace_object",
                 "diff_pipeline", "search_logs", "service_health",
                 "get_report", "get_evidence", "explain_check"):
        srv.tool()(getattr(T, name))
    return srv


def main() -> None:
    try:
        srv = build_server()
    except ImportError as e:
        raise SystemExit(f"MCP server requires the 'mcp' package: {e}")
    srv.run()  # stdio transport


if __name__ == "__main__":
    main()
