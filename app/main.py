from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Union

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import (
    authenticate_and_create_session,
    get_current_user,
    require_admin,
    get_session_manager,
)
from .config import Settings, get_settings
from .keys_store import KeyStore
from .models import AppKeyRequest, AppKeyResponse, AuthenticatedUser, LoginRequest, PersonalKeyResponse
from .scheduler import ExpiryScheduler

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(title="vLLM Key Portal", version="1.0.0")

    if settings.https_only:
        app.add_middleware(HTTPSRedirectMiddleware)

    static_dir = Path(__file__).parent.parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse(url="/static/index.html")

    key_store = KeyStore(settings)
    scheduler = ExpiryScheduler(settings, key_store)

    @app.on_event("startup")
    async def startup_event() -> None:
        scheduler.start()

    @app.on_event("shutdown")
    async def shutdown_event() -> None:
        await scheduler.stop()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    def get_key_store_dep() -> KeyStore:
        return key_store

    def mask_key(value: str) -> str:
        if len(value) <= 4:
            return "****"
        return "*" * (len(value) - 4) + value[-4:]

    @app.post("/auth/login", response_model=AuthenticatedUser)
    async def login(user: AuthenticatedUser = Depends(authenticate_and_create_session)) -> AuthenticatedUser:
        return user

    @app.post("/auth/logout")
    async def logout(response: Response, session_manager=Depends(get_session_manager)) -> Dict[str, str]:
        session_manager.clear(response)
        return {"detail": "logged out"}

    @app.get("/me", response_model=AuthenticatedUser)
    async def get_me(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        return user

    @app.get("/me/key", response_model=Union[PersonalKeyResponse, Dict[str, str]])
    async def get_my_key(
        user: AuthenticatedUser = Depends(get_current_user),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> Union[PersonalKeyResponse, Dict[str, str]]:
        result = key_store.get_personal_key(user.identifier)
        if not result:
            return {}
        subject, entry = result
        return PersonalKeyResponse(
            subject=subject,
            key=entry.key,
            created_at=entry.created_at,
            expires_at=entry.expires_at,
        )

    @app.post("/me/key:regenerate", response_model=PersonalKeyResponse)
    async def regenerate_my_key(
        request: Request,
        user: AuthenticatedUser = Depends(get_current_user),
        key_store: KeyStore = Depends(get_key_store_dep),
        settings: Settings = Depends(get_settings),
    ) -> PersonalKeyResponse:
        entry = key_store.upsert_personal_key(
            identifier=user.identifier,
            ttl_days=settings.key_default_ttl_days,
            actor=user.identifier,
            ip=request.client.host if request.client else None,
        )
        return PersonalKeyResponse(
            subject=f"user:{user.identifier}",
            key=entry.key,
            created_at=entry.created_at,
            expires_at=entry.expires_at,
        )

    @app.delete("/me/key")
    async def delete_my_key(
        request: Request,
        user: AuthenticatedUser = Depends(get_current_user),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> Dict[str, str]:
        key_store.delete_personal_key(
            identifier=user.identifier,
            actor=user.identifier,
            ip=request.client.host if request.client else None,
        )
        return {"detail": "deleted"}

    @app.get("/admin/keys")
    async def list_keys(
        skip: int = 0,
        limit: int = 100,
        subject_filter: str | None = None,
        _: AuthenticatedUser = Depends(require_admin),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> Dict[str, Iterable[Dict[str, str]]]:
        entries = list(key_store.list_entries())
        if subject_filter:
            entries = [item for item in entries if subject_filter in item[0]]
        total = len(entries)
        sliced = entries[skip : skip + limit]
        return {
            "items": [
                {
                    "subject": subject,
                    "key": mask_key(entry.key),
                    "created_at": entry.created_at,
                    "expires_at": entry.expires_at,
                }
                for subject, entry in sliced
            ],
            "total": total,
        }

    @app.post("/admin/app-keys", response_model=AppKeyResponse)
    async def create_app_key(
        request: Request,
        payload: AppKeyRequest,
        user: AuthenticatedUser = Depends(require_admin),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> AppKeyResponse:
        if key_store.has_app_key(payload.name):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="App key already exists")
        entry = key_store.set_app_key(
            name=payload.name,
            key=payload.key,
            actor=user.identifier,
            ip=request.client.host if request.client else None,
        )
        subject = f"app:{payload.name}"
        return AppKeyResponse(name=subject, key=entry.key, created_at=entry.created_at, expires_at=entry.expires_at)

    @app.put("/admin/app-keys/{name}", response_model=AppKeyResponse)
    async def rotate_app_key(
        name: str,
        request: Request,
        user: AuthenticatedUser = Depends(require_admin),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> AppKeyResponse:
        normalized = name.lower()
        if not key_store.has_app_key(normalized):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="App key not found")
        entry = key_store.set_app_key(
            name=normalized,
            key=None,
            actor=user.identifier,
            ip=request.client.host if request.client else None,
        )
        subject = f"app:{normalized}"
        return AppKeyResponse(name=subject, key=entry.key, created_at=entry.created_at, expires_at=entry.expires_at)

    @app.delete("/admin/app-keys/{name}")
    async def delete_app_key(
        name: str,
        request: Request,
        user: AuthenticatedUser = Depends(require_admin),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> Dict[str, str]:
        normalized = name.lower()
        if not key_store.has_app_key(normalized):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="App key not found")
        key_store.delete_app_key(
            name=normalized,
            actor=user.identifier,
            ip=request.client.host if request.client else None,
        )
        return {"detail": "deleted"}

    @app.get("/admin/export.csv")
    async def export_csv(
        _: AuthenticatedUser = Depends(require_admin),
        key_store: KeyStore = Depends(get_key_store_dep),
    ) -> Response:
        entries = key_store.list_entries()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["subject", "key", "created_at", "expires_at"])
        for subject, entry in entries:
            writer.writerow([
                subject,
                mask_key(entry.key),
                entry.created_at.isoformat(),
                entry.expires_at.isoformat() if entry.expires_at else "",
            ])
        response = Response(content=buffer.getvalue(), media_type="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=keys.csv"
        return response

    return app


def configure_logging(settings: Settings) -> None:
    log_path = settings.audit_log_path.parent / "application.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_path, encoding="utf-8"),
        ],
    )


app = create_app()
