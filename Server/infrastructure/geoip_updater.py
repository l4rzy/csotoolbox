import asyncio
import logging
import os
import shutil
import tempfile
from datetime import datetime, timedelta

import aiohttp
import maxminddb

from infrastructure.http_client import get_session

logger = logging.getLogger()

P3TERX_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/download/{date}/GeoLite2-City.mmdb"
FALLBACK_DAYS = 7


class GeoIPUpdater:
    def __init__(self, db_path: str, reader=None):
        self._db_path = db_path
        self._reader = reader
        self._task: asyncio.Task | None = None

    def set_reader(self, reader):
        self._reader = reader

    async def start(self, interval_hours: int = 24):
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run_loop(interval_hours))
        logger.info(f"GeoIP updater started (interval={interval_hours}h)")

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run_loop(self, interval_hours: int):
        while True:
            try:
                await self._check_and_update()
            except Exception as e:
                logger.error(f"GeoIP update check failed: {e}")
            await asyncio.sleep(interval_hours * 3600)

    async def _check_and_update(self):
        today = datetime.utcnow()
        for offset in range(FALLBACK_DAYS):
            d = today - timedelta(days=offset)
            date_str = d.strftime("%Y.%m.%d")
            url = P3TERX_URL.format(date=date_str)
            logger.info(f"Checking GeoIP database: {url}")
            try:
                session = await get_session()
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status == 200:
                        logger.info(f"Found GeoIP database for {date_str}, downloading...")
                        data = await resp.read()
                        self._save_and_reload(data)
                        return
                    else:
                        logger.info(f"No database for {date_str} (status={resp.status})")
            except Exception as e:
                logger.warning(f"Failed to check {url}: {e}")

    def _save_and_reload(self, data: bytes):
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mmdb") as f:
                f.write(data)
                tmp = f.name

            maxminddb.open_database(tmp).close()

            shutil.move(tmp, self._db_path)
            logger.info(f"GeoIP database updated: {self._db_path}")

            if self._reader is not None:
                self._reader.reload()
                logger.info("GeoIP reader reloaded")
        except Exception as e:
            logger.error(f"Failed to save/reload GeoIP database: {e}")
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
