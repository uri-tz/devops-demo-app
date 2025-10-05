from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from .config import Settings
from .keys_store import KeyStore

logger = logging.getLogger(__name__)


class ExpiryScheduler:
    def __init__(self, settings: Settings, key_store: KeyStore):
        self.settings = settings
        self.key_store = key_store
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            await self._task

    async def _run(self) -> None:
        interval = timedelta(hours=1)
        logger.info("Starting key expiration scheduler with interval %s", interval)
        try:
            while not self._stop_event.is_set():
                removed = self.key_store.expire_stale_keys()
                if removed:
                    logger.info("Expired %s stale keys", removed)
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=interval.total_seconds())
                except asyncio.TimeoutError:
                    continue
        except Exception:  # noqa: BLE001
            logger.exception("Key expiration scheduler failed")
        finally:
            logger.info("Key expiration scheduler stopped")
