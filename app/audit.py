from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import Settings

logger = logging.getLogger(__name__)


def append_audit_event(
    settings: Settings,
    *,
    actor: str,
    action: str,
    subject: str,
    ip: Optional[str] = None,
) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor": actor,
        "action": action,
        "subject": subject,
        "ip": ip,
    }
    path: Path = settings.audit_log_path
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:  # noqa: BLE001
        logger.exception("Failed to append audit log entry")
