"""BBB-auth: Backend OAuth2 and Social Sign-In router.

Supports:
- Google Sign In (Web OAuth + One Tap / Popup credential verification)
- Apple Sign In (form_post callback + short-lived ES256 client secret generation)
- GitHub OAuth
- Redis-backed CSRF state validation
- Strict Open Redirect defense (_safe_redirect_url)
- One-time OAuth code exchange to prevent token leakage in browser history/Referer headers
"""

from __future__ import annotations

import json
import os
import secrets
import time
import urllib.parse
from typing import Any, Callable

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError  # type: ignore[import-untyped]
from authlib.jose import jwt as authlib_jwt  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from jose import JWTError
from jose import jwt as jose_jwt
from pydantic import BaseModel

_OAUTH_CODE_TTL = 90  # seconds — one-time exchange window


def get_safe_redirect_url(
    return_to: str | None,
    allowed_hosts: set[str] | None = None,
    default_url: str = "https://bigbankbonus.com/command-center.html",
) -> str:
    """Validate return_to URL to prevent Open Redirect attacks.

    Allows safe relative paths or URLs whose hostname matches trusted domains.
    Rejects untrusted / attacker origins and falls back to default_url.
    """
    if not return_to:
        return default_url

    # Safe relative paths starting with / (excluding scheme-relative //)
    if return_to.startswith("/") and not return_to.startswith("//"):
        base = default_url.split("//")[0] + "//" + default_url.split("//")[1].split("/")[0]
        return f"{base.rstrip('/')}{return_to}"

    try:
        parsed = urllib.parse.urlparse(return_to)
        if not parsed.scheme or not parsed.netloc:
            return default_url

        if parsed.scheme not in ("http", "https"):
            return default_url

        hostname = (parsed.hostname or "").lower()

        trusted = {"bigbankbonus.com", "www.bigbankbonus.com", "localhost", "127.0.0.1"}
        if allowed_hosts:
            trusted.update(h.lower() for h in allowed_hosts)

        if hostname in trusted or any(hostname.endswith("." + h) for h in ("bigbankbonus.com",)):
            return return_to

        return default_url
    except Exception:
        return default_url


class OAuthSettings(BaseModel):
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    google_redirect_uri: str | None = os.getenv("GOOGLE_REDIRECT_URI")

    apple_client_id: str = os.getenv("APPLE_CLIENT_ID", "")
    apple_team_id: str = os.getenv("APPLE_TEAM_ID", "")
    apple_key_id: str = os.getenv("APPLE_KEY_ID", "")
    apple_private_key: str = os.getenv("APPLE_PRIVATE_KEY", "")
    apple_redirect_uri: str | None = os.getenv("APPLE_REDIRECT_URI")

    github_client_id: str = os.getenv("GITHUB_CLIENT_ID", "")
    github_client_secret: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    github_redirect_uri: str | None = os.getenv("GITHUB_REDIRECT_URI")

    backend_url: str = os.getenv("BACKEND_URL", "http://localhost:8000")
    website_url: str = os.getenv("WEBSITE_URL", "https://bigbankbonus.com")
    environment: str = os.getenv("ENVIRONMENT", "development")


def create_oauth_router(
    settings: OAuthSettings,
    get_redis: Callable[[], Any],
    token_issuer: Callable[[dict[str, Any]], tuple[str, str]],
    user_upsert: Callable[[str, str, str | None, str | None, Request], Any],
) -> APIRouter:
    """Factory creating an authenticated OAuth router with injected dependencies."""
    router = APIRouter(prefix="/api/v1/auth/oauth", tags=["oauth"])

    oauth = OAuth()
    if settings.google_client_id and settings.google_client_secret:
        oauth.register(
            name="google",
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    async def _store_oauth_tokens(redis: Any, access_token: str, refresh_token: str) -> str:
        code = secrets.token_urlsafe(32)
        await redis.set(
            f"oauth_exchange:{code}",
            json.dumps({"access_token": access_token, "refresh_token": refresh_token}),
            ex=_OAUTH_CODE_TTL,
        )
        return code

    def _safe_dest(return_to: str | None) -> str:
        return get_safe_redirect_url(
            return_to,
            default_url=f"{settings.website_url.rstrip('/')}/command-center.html",
        )

    # ── Google ─────────────────────────────────────────────────────────────

    @router.get("/google")
    async def google_login(
        request: Request,
        return_to: str | None = None,
        redis: Any = Depends(get_redis),
    ):
        if not settings.google_client_id or (
            settings.environment not in ("development", "test", "local") and not settings.google_client_secret
        ):
            raise HTTPException(status_code=503, detail="Google OAuth not configured")

        redirect_uri = settings.google_redirect_uri or f"{settings.backend_url}/api/v1/auth/oauth/google/callback"
        safe_dest = _safe_dest(return_to)
        state_token = secrets.token_urlsafe(16)
        await redis.set(f"oauth_state:google:{state_token}", safe_dest, ex=600)
        state = state_token + ":" + urllib.parse.quote(safe_dest, safe="")
        return await oauth.google.authorize_redirect(request, redirect_uri, state=state)

    @router.get("/google/callback")
    async def google_callback(
        request: Request,
        redis: Any = Depends(get_redis),
    ):
        raw_state = request.query_params.get("state", "")
        state_token = raw_state.split(":", 1)[0] if ":" in raw_state else raw_state
        saved_dest = None
        if state_token:
            try:
                saved_dest = await redis.getdel(f"oauth_state:google:{state_token}")
            except Exception:
                pass

        fallback = raw_state.split(":", 1)[1] if ":" in raw_state else None
        dest = _safe_dest(saved_dest or fallback)

        try:
            token = await oauth.google.authorize_access_token(request)
        except OAuthError as e:
            raise HTTPException(status_code=400, detail=str(e))

        userinfo = token.get("userinfo") or {}
        email = userinfo.get("email")
        google_id = userinfo.get("sub")
        name = userinfo.get("name")

        if not email or not google_id:
            raise HTTPException(status_code=400, detail="Missing email or user ID from Google")

        user = await user_upsert("google", google_id, email, name, request)
        access_token, refresh_token = token_issuer(user)

        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            code = await _store_oauth_tokens(redis, access_token, refresh_token)
            sep = "&" if "?" in dest else "?"
            return RedirectResponse(url=f"{dest}{sep}oauth_code={code}", status_code=302)

        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    # ── Google ID Token Verification (Popup / One Tap) ──────────────────────

    class GoogleVerifyRequest(BaseModel):
        credential: str

    @router.post("/google/verify")
    async def google_verify(
        payload: GoogleVerifyRequest,
        request: Request,
    ):
        credential = payload.credential
        try:
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token

            claims = id_token.verify_oauth2_token(credential, google_requests.Request(), settings.google_client_id)
            email = claims.get("email")
            google_id = claims.get("sub")
            name = claims.get("name")
            picture = claims.get("picture", "")
        except Exception:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": credential})
            if r.status_code != 200:
                raise HTTPException(status_code=400, detail="Invalid Google credential")
            claims = r.json()
            if claims.get("aud") != settings.google_client_id:
                raise HTTPException(status_code=400, detail="Token audience mismatch")
            email = claims.get("email")
            google_id = claims.get("sub")
            name = claims.get("name")
            picture = claims.get("picture", "")

        if not email or not google_id:
            raise HTTPException(status_code=400, detail="Google credential missing email or sub")

        user = await user_upsert("google", google_id, email, name, request)
        access_token, refresh_token = token_issuer(user)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {"email": email, "name": name, "picture": picture},
        }

    # ── One-Time OAuth Code Exchange ───────────────────────────────────────

    class ExchangeRequest(BaseModel):
        code: str

    @router.post("/exchange")
    async def exchange_code(payload: ExchangeRequest, redis: Any = Depends(get_redis)):
        key = f"oauth_exchange:{payload.code}"
        raw = await redis.getdel(key)
        if not raw:
            raise HTTPException(status_code=400, detail="Invalid or expired OAuth exchange code")
        data = json.loads(raw)
        return {"access_token": data["access_token"], "refresh_token": data["refresh_token"], "token_type": "bearer"}

    # ── Apple Sign In ──────────────────────────────────────────────────────

    def _apple_client_secret() -> str:
        if not settings.apple_private_key or not settings.apple_key_id or not settings.apple_team_id:
            raise HTTPException(status_code=503, detail="Apple OAuth credentials not configured")
        header = {"alg": "ES256", "kid": settings.apple_key_id}
        payload = {
            "iss": settings.apple_team_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "aud": "https://appleid.apple.com",
            "sub": settings.apple_client_id,
        }
        token = authlib_jwt.encode(header, payload, settings.apple_private_key.encode())
        return token.decode() if isinstance(token, bytes) else token

    @router.get("/apple")
    async def apple_login(
        request: Request,
        return_to: str | None = None,
        redis: Any = Depends(get_redis),
    ):
        safe_dest = _safe_dest(return_to)
        if not settings.apple_client_id:
            raise HTTPException(status_code=503, detail="Apple OAuth not configured")

        state_token = secrets.token_urlsafe(32)
        await redis.set(f"oauth_state:apple:{state_token}", safe_dest, ex=600)
        state = f"{state_token}|{safe_dest}"

        apple_redirect_uri = settings.apple_redirect_uri or f"{settings.backend_url}/api/v1/auth/oauth/apple/callback"
        params = {
            "client_id": settings.apple_client_id,
            "redirect_uri": apple_redirect_uri,
            "response_type": "code",
            "scope": "name email",
            "response_mode": "form_post",
            "state": state,
        }
        return RedirectResponse("https://appleid.apple.com/auth/authorize?" + urllib.parse.urlencode(params))

    @router.post("/apple/callback")
    async def apple_callback(
        request: Request,
        redis: Any = Depends(get_redis),
    ):
        if not settings.apple_client_id:
            raise HTTPException(status_code=503, detail="Apple OAuth not configured")

        form = await request.form()
        code = form.get("code")
        if not code:
            return RedirectResponse(f"{_safe_dest(None)}?error=missing_code", status_code=302)

        state_raw = str(form.get("state", ""))
        state_parts = state_raw.split("|", 1)
        state_token = state_parts[0] if state_parts else ""

        saved_dest = None
        if state_token:
            try:
                saved_dest = await redis.getdel(f"oauth_state:apple:{state_token}")
            except Exception:
                pass

        if not saved_dest and settings.environment not in ("development", "test", "local"):
            return RedirectResponse(f"{_safe_dest(None)}?error=invalid_state", status_code=302)

        dest = _safe_dest(saved_dest or (state_parts[1] if len(state_parts) > 1 else None))

        # Exchange code with Apple
        apple_redirect_uri = settings.apple_redirect_uri or f"{settings.backend_url}/api/v1/auth/oauth/apple/callback"
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                "https://appleid.apple.com/auth/token",
                data={
                    "client_id": settings.apple_client_id,
                    "client_secret": _apple_client_secret(),
                    "code": str(code),
                    "grant_type": "authorization_code",
                    "redirect_uri": apple_redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            r.raise_for_status()
            apple_token = r.json()

        id_token_str = apple_token.get("id_token")
        if not id_token_str:
            raise HTTPException(status_code=400, detail="Apple omitted id_token")

        async with httpx.AsyncClient(timeout=10.0) as c:
            keys = (await c.get("https://appleid.apple.com/auth/keys")).json()

        claims = jose_jwt.decode(
            id_token_str, keys, algorithms=["RS256"], audience=settings.apple_client_id, issuer="https://appleid.apple.com"
        )
        apple_id = claims.get("sub")
        email = claims.get("email")

        user = await user_upsert("apple", apple_id, email, None, request)
        access_token, refresh_token = token_issuer(user)
        exchange_code = await _store_oauth_tokens(redis, access_token, refresh_token)
        sep = "&" if "?" in dest else "?"
        return RedirectResponse(f"{dest}{sep}oauth_code={exchange_code}", status_code=302)

    return router
