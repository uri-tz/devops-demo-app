from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, Tuple

import fcntl

from .audit import append_audit_event
from .config import Settings
from .models import KeyEntry, KeysDocument

TOKEN_LENGTH_BYTES = 48


class KeyStoreError(Exception):
    """Raised when the JSON document cannot be processed."""


class KeyStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.path: Path = settings.keys_json_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_document(KeysDocument())

    def generate_token(self) -> str:
        return secrets.token_urlsafe(TOKEN_LENGTH_BYTES)

    def get_personal_key(self, identifier: str) -> Tuple[str, KeyEntry] | None:
        subject = self._personal_subject(identifier)
        doc = self._read_document()
        entry = doc.gpt.get(subject)
        if entry:
            return subject, entry
        return None

    def upsert_personal_key(self, *, identifier: str, ttl_days: int, actor: str, ip: str | None) -> KeyEntry:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=ttl_days)
        entry = KeyEntry(key=self.generate_token(), created_at=now, expires_at=expires)
        subject = self._personal_subject(identifier)

        def modifier(data: Dict[str, KeyEntry]) -> str:
            action = "create" if subject not in data else "rotate"
            data[subject] = entry
            return action

        action = self._update_document(
            modifier=modifier,
            actor=actor,
            default_action="create",
            subject=subject,
            ip=ip,
        )
        if action not in {"create", "rotate"}:
            raise KeyStoreError("Unexpected action while upserting personal key")
        return entry

    def delete_personal_key(self, *, identifier: str, actor: str, ip: str | None) -> None:
        subject = self._personal_subject(identifier)

        def modifier(data: Dict[str, KeyEntry]) -> str:
            if subject in data:
                data.pop(subject, None)
                return "delete"
            return "noop"

        self._update_document(
            modifier=modifier,
            actor=actor,
            default_action="noop",
            subject=subject,
            ip=ip,
        )

    def set_app_key(self, *, name: str, key: str | None, actor: str, ip: str | None) -> KeyEntry:
        now = datetime.now(timezone.utc)
        entry = KeyEntry(key=key or self.generate_token(), created_at=now, expires_at=None)
        subject = self._app_subject(name)

        def modifier(data: Dict[str, KeyEntry]) -> str:
            action = "create" if subject not in data else "rotate"
            data[subject] = entry
            return action

        action = self._update_document(
            modifier=modifier,
            actor=actor,
            default_action="create",
            subject=subject,
            ip=ip,
        )
        if action not in {"create", "rotate"}:
            raise KeyStoreError("Unexpected action while setting app key")
        return entry

    def delete_app_key(self, *, name: str, actor: str, ip: str | None) -> None:
        subject = self._app_subject(name)

        def modifier(data: Dict[str, KeyEntry]) -> str:
            if subject in data:
                data.pop(subject, None)
                return "delete"
            return "noop"

        self._update_document(
            modifier=modifier,
            actor=actor,
            default_action="noop",
            subject=subject,
            ip=ip,
        )

    def list_entries(self) -> Iterable[Tuple[str, KeyEntry]]:
        return tuple(self._read_document().gpt.items())

    def has_subject(self, subject: str) -> bool:
        doc = self._read_document()
        return subject in doc.gpt

    def has_app_key(self, name: str) -> bool:
        return self.has_subject(self._app_subject(name))

    def expire_stale_keys(self) -> int:
        now = datetime.now(timezone.utc)
        removed: Dict[str, KeyEntry] = {}

        def modifier(data: Dict[str, KeyEntry]) -> str:
            for subject, entry in list(data.items()):
                if subject.startswith("user:") and entry.expires_at and entry.expires_at <= now:
                    removed[subject] = data.pop(subject)
            return "expire" if removed else "noop"

        action = self._update_document(
            modifier=modifier,
            actor="system",
            default_action="noop",
            subject="user:*",
            ip=None,
            audit_each_removed=removed,
        )
        if action not in {"expire", "noop"}:
            raise KeyStoreError("Unexpected action during expiration")
        return len(removed)

    def _personal_subject(self, identifier: str) -> str:
        return f"user:{identifier.lower()}"

    def _app_subject(self, name: str) -> str:
        return f"app:{name.lower()}"

    def _read_document(self) -> KeysDocument:
        with self._locked_file(shared=True) as file:
            file.seek(0)
            content = file.read().strip()
            if not content:
                return KeysDocument()
            data = json.loads(content)
            return KeysDocument(**data)

    def _write_document(self, document: KeysDocument) -> None:
        tmp_path = self.path.with_suffix(".tmp")
        json_data = document.json(indent=2, sort_keys=True)
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(json_data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, self.path)
        os.chmod(self.path, 0o640)

    def _update_document(
        self,
        *,
        modifier,
        actor: str,
        default_action: str,
        subject: str,
        ip: str | None,
        audit_each_removed: Dict[str, KeyEntry] | None = None,
    ) -> str:
        with self._locked_file(shared=False) as file:
            file.seek(0)
            content = file.read().strip()
            document = KeysDocument(**json.loads(content)) if content else KeysDocument()
            original_data = dict(document.gpt)
            data = dict(document.gpt)
            try:
                action = modifier(data) or default_action
            except Exception as exc:  # noqa: BLE001
                raise KeyStoreError("Failed to modify keys document") from exc
            if data != original_data:
                document = KeysDocument(gpt=data)
                self._write_document(document)
            else:
                action = "noop"
        if audit_each_removed:
            for removed_subject in audit_each_removed:
                append_audit_event(self.settings, actor=actor, action="expire", subject=removed_subject, ip=ip)
        elif action != "noop":
            append_audit_event(self.settings, actor=actor, action=action, subject=subject, ip=ip)
        return action

    @contextmanager
    def _locked_file(self, *, shared: bool) -> Iterator[object]:
        with self.path.open("a+", encoding="utf-8") as file:
            file.seek(0)
            lock_type = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            fcntl.flock(file.fileno(), lock_type)
            try:
                yield file
            finally:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
