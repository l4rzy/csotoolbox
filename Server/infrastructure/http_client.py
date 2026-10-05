import asyncio
import logging
from typing import Dict, List, Optional, Tuple

import aiohttp

from infrastructure.constants import USER_AGENT


logger = logging.getLogger()

_sessions: Dict[int, aiohttp.ClientSession] = {}


async def close_session():
    try:
        loop_key = id(asyncio.get_running_loop())
    except RuntimeError:
        return
    session = _sessions.pop(loop_key, None)
    if session is not None and not session.closed:
        await session.close()


async def get_session() -> aiohttp.ClientSession:
    loop_key = id(asyncio.get_running_loop())
    session = _sessions.get(loop_key)
    if session is not None and not session.closed:
        return session
    connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
    session = aiohttp.ClientSession(
        headers={"User-Agent": USER_AGENT},
        connector=connector,
    )
    _sessions[loop_key] = session
    return session


async def aiohttp_fetch(
    url: str, headers: Optional[List[str]] = None, timeout: Optional[int] = None
) -> Tuple[int, bytes]:
    """Returns (status_code, body_bytes)."""
    session = await get_session()
    req_headers = {"Accept": "application/json"}
    if headers:
        for h in headers:
            try:
                colon = h.index(":")
                if colon > 0:
                    name = h[:colon].strip()
                    val = h[colon + 1 :].strip()
                    req_headers[name] = val
                else:
                    logger.warning(f"Skipping malformed header (empty name): {h!r}")
            except ValueError:
                logger.warning(f"Skipping malformed header (missing colon): {h!r}")

    async with session.get(
        url, headers=req_headers, timeout=aiohttp.ClientTimeout(total=timeout or 30)
    ) as resp:
        body = await resp.read()
        return resp.status, body


async def aiohttp_post_form(
    url: str,
    data: dict,
    headers: Optional[List[str]] = None,
    timeout: Optional[int] = None,
) -> Tuple[int, bytes]:
    """POST form-urlencoded data. Returns (status_code, body_bytes)."""
    session = await get_session()
    req_headers = {"Accept": "application/json"}
    if headers:
        for h in headers:
            try:
                colon = h.index(":")
                if colon > 0:
                    name = h[:colon].strip()
                    val = h[colon + 1 :].strip()
                    req_headers[name] = val
            except ValueError:
                logger.warning(f"Skipping malformed header: {h!r}")

    async with session.post(
        url,
        headers=req_headers,
        data=data,
        timeout=aiohttp.ClientTimeout(total=timeout or 30),
    ) as resp:
        body = await resp.read()
        return resp.status, body


async def aiohttp_post_json(
    url: str,
    json_data: dict,
    headers: Optional[List[str]] = None,
    timeout: Optional[int] = None,
) -> Tuple[int, bytes]:
    """POST JSON data. Returns (status_code, body_bytes)."""
    session = await get_session()
    req_headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if headers:
        for h in headers:
            try:
                colon = h.index(":")
                if colon > 0:
                    name = h[:colon].strip()
                    val = h[colon + 1 :].strip()
                    req_headers[name] = val
            except ValueError:
                logger.warning(f"Skipping malformed header: {h!r}")

    async with session.post(
        url,
        headers=req_headers,
        json=json_data,
        timeout=aiohttp.ClientTimeout(total=timeout or 30),
    ) as resp:
        body = await resp.read()
        return resp.status, body
