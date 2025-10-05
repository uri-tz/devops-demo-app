from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, Response, status
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import Settings, get_settings
from .ldap_client import LDAPClient
from .models import AuthenticatedUser, LoginRequest

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "vllm_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24


class SessionManager:
    def __init__(self, settings: Settings):
        self.serializer = URLSafeTimedSerializer(settings.session_secret, salt="vllm-keyportal")

    def create(self, response: Response, user: AuthenticatedUser) -> None:
        payload = {
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "is_admin": user.is_admin,
            "iat": datetime.now(timezone.utc).timestamp(),
        }
        token = self.serializer.dumps(payload)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            max_age=SESSION_MAX_AGE_SECONDS,
            secure=True,
            httponly=True,
            samesite="strict",
        )

    def clear(self, response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE_NAME)

    def load(self, request: Request) -> Optional[AuthenticatedUser]:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return None
        try:
            data = self.serializer.loads(token, max_age=SESSION_MAX_AGE_SECONDS)
            return AuthenticatedUser(**{k: data.get(k) for k in ("username", "email", "display_name", "is_admin")})
        except BadSignature:
            logger.warning("Invalid session token")
            return None


def get_session_manager(settings: Settings = Depends(get_settings)) -> SessionManager:
    return SessionManager(settings)


def get_ldap_client(settings: Settings = Depends(get_settings)) -> LDAPClient:
    return LDAPClient(settings)


def get_current_user(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
) -> AuthenticatedUser:
    user = session_manager.load(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def require_admin(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return user


def authenticate_and_create_session(
    payload: LoginRequest,
    request: Request,
    response: Response,
    ldap_client: LDAPClient = Depends(get_ldap_client),
    session_manager: SessionManager = Depends(get_session_manager),
) -> AuthenticatedUser:
    info = ldap_client.authenticate(payload.username, payload.password)
    if not info:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    is_admin = ldap_client.is_admin(info)
    user = AuthenticatedUser(
        username=info.username,
        email=info.email,
        display_name=info.display_name,
        is_admin=is_admin,
    )
    session_manager.create(response, user)
    request.state.user = user
    return user
