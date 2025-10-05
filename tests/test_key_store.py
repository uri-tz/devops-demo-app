import threading
from datetime import datetime, timedelta, timezone

from app.keys_store import KeyStore
from app.models import KeyEntry, KeysDocument


def test_concurrent_updates(settings):
    store = KeyStore(settings)
    errors = []

    def worker(user_id: str):
        try:
            store.upsert_personal_key(identifier=user_id, ttl_days=30, actor=user_id, ip=None)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"user{i}@example.com",)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    entries = dict(store.list_entries())
    assert len(entries) == 10


def test_expire_stale_keys(settings, tmp_path):
    store = KeyStore(settings)
    now = datetime.now(timezone.utc)
    document = KeysDocument(
        gpt={
            "user:old@example.com": KeyEntry(key="old", created_at=now - timedelta(days=31), expires_at=now - timedelta(days=1)),
            "user:current@example.com": KeyEntry(key="cur", created_at=now, expires_at=now + timedelta(days=10)),
        }
    )
    store._write_document(document)
    removed = store.expire_stale_keys()
    assert removed == 1
    remaining = dict(store.list_entries())
    assert "user:old@example.com" not in remaining
    assert "user:current@example.com" in remaining
