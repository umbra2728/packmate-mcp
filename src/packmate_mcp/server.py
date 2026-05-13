"""FastMCP server wiring.

Builds the FastMCP instance, the PackmateClient, registers all tools, and runs
over stdio.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.config import PackmateSettings
from packmate_mcp.tools import register_all

log = logging.getLogger(__name__)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def build_server() -> FastMCP:
    """Construct a FastMCP server with all tools registered.

    Settings are loaded from env at call time. The PackmateClient is opened in a
    lifespan context manager so it shares the FastMCP lifecycle.
    """
    # pydantic-settings reads fields from env at runtime; mypy cannot see them statically.
    settings = PackmateSettings()  # type: ignore[call-arg]
    _configure_logging(settings.log_level)
    log.info("Connecting to Packmate at %s", settings.base_url)

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[None]:
        async with PackmateClient(settings) as client:
            register_all(mcp, client)
            yield

    mcp = FastMCP("packmate", lifespan=lifespan)
    return mcp


def run() -> None:
    """Entrypoint: build the server and run it over stdio."""
    server = build_server()
    server.run(transport="stdio")
