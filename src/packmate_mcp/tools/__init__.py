"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared PackmateClient. `register_all` (added in
Task 22, once all submodules exist) glues them together.
"""
