"""Async HTTP client for Packmate's REST API."""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Any, Optional

import httpx

from packmate_mcp.config import PackmateSettings
from packmate_mcp.models import (
    Packet,
    PacketPagination,
    Pattern,
    PatternCreate,
    PatternUpdate,
    Service,
    ServiceCreate,
    ServiceUpdate,
    Stream,
    StreamPagination,
)

log = logging.getLogger(__name__)


# ---------- exceptions ----------


class PackmateError(Exception):
    """Base for all errors raised by PackmateClient."""


class PackmateConnectionError(PackmateError):
    """Network failure: cannot reach Packmate, or request timed out."""


class PackmateAuthError(PackmateError):
    """HTTP 401/403 — bad credentials."""


class PackmateNotFoundError(PackmateError):
    """HTTP 404 — resource does not exist."""


class PackmateValidationError(PackmateError):
    """HTTP 4xx (other than 401/403/404) — Packmate rejected the request."""


class PackmateServerError(PackmateError):
    """HTTP 5xx — Packmate internal error."""


# ---------- client ----------


class PackmateClient:
    """Thin async client over Packmate's REST API.

    Use as an async context manager:
        async with PackmateClient(settings) as client:
            services = await client.list_services()
    """

    def __init__(self, settings: PackmateSettings) -> None:
        self._settings = settings
        self._http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "PackmateClient":
        self._http = httpx.AsyncClient(
            base_url=str(self._settings.base_url).rstrip("/"),
            auth=(self._settings.login, self._settings.password),
            timeout=self._settings.timeout_seconds,
        )
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, Any]] = None,
    ) -> httpx.Response:
        assert self._http is not None, "PackmateClient must be used as async context manager"
        try:
            response = await self._http.request(method, path, json=json, params=params)
        except httpx.TimeoutException as e:
            raise PackmateConnectionError(
                f"Request to {method} {path} timed out after {self._settings.timeout_seconds}s."
            ) from e
        except httpx.ConnectError as e:
            raise PackmateConnectionError(
                f"Cannot reach Packmate at {self._settings.base_url}. Is the server running?"
            ) from e
        except httpx.HTTPError as e:
            raise PackmateConnectionError(f"HTTP error: {e}") from e

        if response.status_code in (401, 403):
            raise PackmateAuthError(
                "Authentication failed. Check PACKMATE_MCP_LOGIN and PACKMATE_MCP_PASSWORD env vars."
            )
        if response.status_code == 404:
            raise PackmateNotFoundError(f"Resource not found: {method} {path}")
        if 400 <= response.status_code < 500:
            raise PackmateValidationError(
                f"Packmate rejected request ({response.status_code}): {response.text}"
            )
        if response.status_code >= 500:
            raise PackmateServerError(
                f"Packmate server error ({response.status_code}). "
                f"Check Packmate logs. Body: {response.text}"
            )
        return response

    # ---------- services ----------

    async def list_services(self) -> list[Service]:
        r = await self._request("GET", "/api/service/")
        return [Service.model_validate(item) for item in r.json()]

    async def create_service(self, payload: ServiceCreate) -> Service:
        r = await self._request(
            "POST",
            "/api/service/",
            json=payload.model_dump(by_alias=True),
        )
        return Service.model_validate(r.json())

    async def update_service(self, port: int, payload: ServiceUpdate) -> Service:
        r = await self._request(
            "POST",
            f"/api/service/{port}",
            json=payload.model_dump(by_alias=True, exclude_unset=True),
        )
        return Service.model_validate(r.json())

    async def delete_service(self, port: int) -> None:
        await self._request("DELETE", f"/api/service/{port}")

    # ---------- patterns ----------

    async def list_patterns(self) -> list[Pattern]:
        r = await self._request("GET", "/api/pattern/")
        return [Pattern.model_validate(item) for item in r.json()]

    async def create_pattern(self, payload: PatternCreate) -> Pattern:
        r = await self._request(
            "POST",
            "/api/pattern/",
            json=payload.model_dump(by_alias=True, exclude_none=True, mode="json"),
        )
        return Pattern.model_validate(r.json())

    async def update_pattern(self, pattern_id: int, payload: PatternUpdate) -> Pattern:
        r = await self._request(
            "POST",
            f"/api/pattern/{pattern_id}",
            json=payload.model_dump(by_alias=True, exclude_unset=True, mode="json"),
        )
        return Pattern.model_validate(r.json())

    async def delete_pattern(self, pattern_id: int) -> None:
        await self._request("DELETE", f"/api/pattern/{pattern_id}")

    async def set_pattern_enabled(self, pattern_id: int, enabled: bool) -> None:
        await self._request(
            "POST",
            f"/api/pattern/{pattern_id}/enable",
            params={"enabled": "true" if enabled else "false"},
        )

    async def pattern_lookback(self, pattern_id: int, minutes: int) -> None:
        # Packmate's controller deserializes the body as raw int (not JSON object).
        # httpx encodes `json=N` as the bare digits, which Spring accepts.
        await self._request(
            "POST",
            f"/api/pattern/{pattern_id}/lookback",
            json=minutes,
        )

    # ---------- streams ----------

    async def list_streams(
        self,
        pagination: StreamPagination,
        *,
        port: Optional[int] = None,
    ) -> list[Stream]:
        path = "/api/stream/all" if port is None else f"/api/stream/{port}"
        r = await self._request(
            "POST",
            path,
            json=pagination.model_dump(by_alias=True),
        )
        return [Stream.model_validate(item) for item in r.json()]

    async def set_stream_favorite(self, stream_id: int, favorite: bool) -> None:
        suffix = "favorite" if favorite else "unfavorite"
        await self._request("POST", f"/api/stream/{stream_id}/{suffix}")

    # ---------- packets ----------

    async def get_packets(
        self, stream_id: int, pagination: PacketPagination
    ) -> list[Packet]:
        r = await self._request(
            "POST",
            f"/api/packet/{stream_id}",
            json=pagination.model_dump(by_alias=True),
        )
        return [Packet.model_validate(item) for item in r.json()]

    # ---------- pcap ----------

    async def pcap_status(self) -> bool:
        r = await self._request("GET", "/api/pcap/started")
        return bool(r.json())

    async def pcap_start(self) -> None:
        await self._request("POST", "/api/pcap/start")
