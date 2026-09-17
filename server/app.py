from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from redis.asyncio import Redis

from oauth import OAuthSettings, create_oauth_router


def _env_csv(name: str, default: str = "") -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _require(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _parse_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as e:
        raise RuntimeError(f"Invalid {name}: expected integer, got {raw!r}") from e
    if value <= 0:
        raise RuntimeError(f"Invalid {name}: expected integer > 0, got {raw!r}")
    return value


class ServiceSettings:
    def __init__(self) -> None:
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.allowed_origins = _env_csv(
            "ALLOWED_ORIGINS",
            os.getenv("WEBSITE_URL", "http://localhost:3000"),
        )
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.uses_generated_dev_secret = False
        self.jwt_secret = os.getenv("JWT_SECRET", "").strip()
        if not self.jwt_secret and self.environment in ("development", "local", "test"):
            self.jwt_secret = secrets.token_urlsafe(48)
            self.uses_generated_dev_secret = True
        self.jwt_issuer = os.getenv("JWT_ISSUER", os.getenv("BACKEND_URL", "http://localhost:8000"))
        self.jwt_audience = os.getenv("JWT_AUDIENCE", "bbb-api")
        self.access_token_minutes = _parse_positive_int("ACCESS_TOKEN_MINUTES", 15)
        self.refresh_token_days = _parse_positive_int("REFRESH_TOKEN_DAYS", 30)


service_settings = ServiceSettings()
oauth_settings = OAuthSettings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if service_settings.environment not in ("development", "local", "test"):
        _require("JWT_SECRET")

    _app.state.redis = Redis.from_url(service_settings.redis_url, encoding="utf-8", decode_responses=True)
    try:
        await _app.state.redis.ping()
        yield
    finally:
        redis_client: Redis | None = getattr(_app.state, "redis", None)
        if redis_client is not None:
            await redis_client.close()


app = FastAPI(title="BBB-auth OAuth Layer", version="1.0.0", lifespan=lifespan)

if service_settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=service_settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    )

async def get_redis() -> Redis:
    redis_client: Redis | None = getattr(app.state, "redis", None)
    if redis_client is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    return redis_client


def _issue(provider_user: dict[str, Any]) -> tuple[str, str]:
    if not service_settings.jwt_secret:
        raise HTTPException(status_code=503, detail="JWT signing secret not configured")

    now = datetime.now(UTC)
    provider = str(provider_user.get("provider") or "unknown")
    identity = str(provider_user.get("id") or provider_user.get("email") or "unknown")
    base_claims = {
        "iss": service_settings.jwt_issuer,
        "aud": service_settings.jwt_audience,
        "sub": f"{provider}:{identity}",
        "email": provider_user.get("email"),
        "name": provider_user.get("name"),
        "provider": provider,
        "iat": int(now.timestamp()),
    }
    access_token = jwt.encode(
        {
            **base_claims,
            "typ": "access",
            "jti": secrets.token_urlsafe(12),
            "exp": int((now + timedelta(minutes=service_settings.access_token_minutes)).timestamp()),
        },
        service_settings.jwt_secret,
        algorithm="HS256",
    )
    refresh_token = jwt.encode(
        {
            **base_claims,
            "typ": "refresh",
            "jti": secrets.token_urlsafe(12),
            "exp": int((now + timedelta(days=service_settings.refresh_token_days)).timestamp()),
        },
        service_settings.jwt_secret,
        algorithm="HS256",
    )
    return access_token, refresh_token


async def _upsert_user(
    provider: str,
    provider_user_id: str,
    email: str | None,
    name: str | None,
    _request: Any,
) -> dict[str, Any]:
    return {"id": provider_user_id, "provider": provider, "email": email, "name": name}


app.include_router(
    create_oauth_router(
        settings=oauth_settings,
        get_redis=get_redis,
        token_issuer=_issue,
        user_upsert=_upsert_user,
    )
)


@app.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
async def ready() -> dict[str, str]:
    redis_client = await get_redis()
    try:
        await redis_client.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail="Redis not ready") from e
    return {"status": "ready"}
