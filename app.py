#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pro Shop Enterprise API
Production-ready FastAPI + SQLite + Render
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

import aiosqlite
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware.base import BaseHTTPMiddleware


# ============================================================================
# PATHS
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
EXPORT_DIR = BASE_DIR / "exports"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# SETTINGS
# ============================================================================

class AppEnvironment(str, Enum):
    development = "development"
    staging = "staging"
    production = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    APP_NAME: str = "Pro Shop Enterprise API"
    APP_VERSION: str = "24.0.0"

    ENVIRONMENT: AppEnvironment = AppEnvironment.production

    HOST: str = "0.0.0.0"
    PORT: int = Field(default=8000, ge=1, le=65535)

    DB_FILE: str = "proshop.db"

    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(48)
    )

    ADMIN_TOKEN: str = Field(
        default_factory=lambda: secrets.token_urlsafe(48)
    )

    CORS_ORIGINS: str = "*"

    RATE_LIMIT_REQUESTS: int = Field(default=60, ge=1)
    RATE_LIMIT_WINDOW: int = Field(default=60, ge=1)

    MAX_USERS_PER_REQUEST: int = Field(default=100, ge=1, le=1000)

    LOG_LEVEL: str = "INFO"

    @property
    def db_path(self) -> Path:
        return DATA_DIR / self.DB_FILE

    @property
    def cors_origins(self) -> list[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]

        return [
            origin.strip()
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]


settings = Settings()


# ============================================================================
# LOGGING
# ============================================================================

class UTCFormatter(logging.Formatter):
    converter = time.gmtime

    def formatTime(
        self,
        record: logging.LogRecord,
        datefmt: Optional[str] = None,
    ) -> str:
        return datetime.fromtimestamp(
            record.created,
            tz=timezone.utc,
        ).isoformat()


def create_logger() -> logging.Logger:
    logger = logging.getLogger("pro_shop")
    logger.setLevel(
        getattr(
            logging,
            settings.LOG_LEVEL.upper(),
            logging.INFO,
        )
    )

    if logger.handlers:
        return logger

    formatter = UTCFormatter(
        "%(asctime)s | %(levelname)s | %(name)s | "
        "%(funcName)s:%(lineno)d | %(message)s"
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)

    file_handler = RotatingFileHandler(
        LOG_DIR / "proshop.log",
        maxBytes=20 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    logger.addHandler(console)
    logger.addHandler(file_handler)

    return logger


log = create_logger()


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

class Security:
    @staticmethod
    def hash_value(value: str) -> str:
        return hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def constant_time_compare(
        first: str,
        second: str,
    ) -> bool:
        return secrets.compare_digest(first, second)

    @staticmethod
    def request_id() -> str:
        return uuid.uuid4().hex

    @staticmethod
    def sanitize_text(
        value: Optional[str],
        max_length: int = 500,
    ) -> Optional[str]:
        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        return value[:max_length]


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    def __init__(
        self,
        requests: int,
        window: int,
    ) -> None:
        self.limit = requests
        self.window = window
        self._requests: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> bool:
        now = time.monotonic()

        async with self._lock:
            timestamps = self._requests.get(key, [])

            timestamps = [
                timestamp
                for timestamp in timestamps
                if now - timestamp < self.window
            ]

            if len(timestamps) >= self.limit:
                self._requests[key] = timestamps
                return False

            timestamps.append(now)
            self._requests[key] = timestamps

            if len(self._requests) > 10000:
                self._cleanup_locked(now)

            return True

    def _cleanup_locked(self, now: float) -> None:
        expired_keys = []

        for key, timestamps in self._requests.items():
            valid = [
                timestamp
                for timestamp in timestamps
                if now - timestamp < self.window
            ]

            if valid:
                self._requests[key] = valid
            else:
                expired_keys.append(key)

        for key in expired_keys:
            self._requests.pop(key, None)


rate_limiter = RateLimiter(
    settings.RATE_LIMIT_REQUESTS,
    settings.RATE_LIMIT_WINDOW,
)


# ============================================================================
# DATABASE
# ============================================================================

class Database:
    def __init__(self, path: Path):
        self.path = path
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def connect(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(
            self.path,
            timeout=30,
        )

        db.row_factory = aiosqlite.Row

        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("PRAGMA busy_timeout=30000")

        return db

    async def initialize(self) -> None:
        async with self._init_lock:
            if self._initialized:
                return

            async with await self.connect() as db:
                await db.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        external_id TEXT UNIQUE,
                        first_name TEXT,
                        last_name TEXT,
                        username TEXT,
                        phone TEXT UNIQUE,
                        source TEXT,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_seen TEXT
                    );

                    CREATE TABLE IF NOT EXISTS admin_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        details TEXT,
                        ip TEXT,
                        request_id TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS system_config (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        updated_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS
                        idx_users_phone
                        ON users(phone);

                    CREATE INDEX IF NOT EXISTS
                        idx_users_external_id
                        ON users(external_id);

                    CREATE INDEX IF NOT EXISTS
                        idx_users_username
                        ON users(username);

                    CREATE INDEX IF NOT EXISTS
                        idx_users_active
                        ON users(is_active);

                    CREATE INDEX IF NOT EXISTS
                        idx_admin_logs_created
                        ON admin_logs(created_at);
                    """
                )

                await db.commit()

            self._initialized = True

            log.info(
                "Database initialized: %s",
                self.path,
            )

    async def count_users(self) -> int:
        async with await self.connect() as db:
            cursor = await db.execute(
                "SELECT COUNT(*) AS total FROM users"
            )

            row = await cursor.fetchone()

            return int(row["total"])

    async def get_user(
        self,
        user_id: int,
    ) -> Optional[dict[str, Any]]:
        async with await self.connect() as db:
            cursor = await db.execute(
                """
                SELECT
                    id,
                    external_id,
                    first_name,
                    last_name,
                    username,
                    phone,
                    source,
                    is_active,
                    created_at,
                    updated_at,
                    last_seen
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            )

            row = await cursor.fetchone()

            return dict(row) if row else None

    async def get_users(
        self,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        async with await self.connect() as db:
            cursor = await db.execute(
                """
                SELECT
                    id,
                    external_id,
                    first_name,
                    last_name,
                    username,
                    phone,
                    source,
                    is_active,
                    created_at,
                    updated_at,
                    last_seen
                FROM users
                ORDER BY id DESC
                LIMIT ?
                OFFSET ?
                """,
                (limit, offset),
            )

            rows = await cursor.fetchall()

            return [dict(row) for row in rows]

    async def create_user(
        self,
        external_id: Optional[str],
        first_name: Optional[str],
        last_name: Optional[str],
        username: Optional[str],
        phone: Optional[str],
        source: Optional[str],
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()

        async with await self.connect() as db:
            try:
                cursor = await db.execute(
                    """
                    INSERT INTO users (
                        external_id,
                        first_name,
                        last_name,
                        username,
                        phone,
                        source,
                        is_active,
                        created_at,
                        updated_at,
                        last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (
                        external_id,
                        first_name,
                        last_name,
                        username,
                        phone,
                        source,
                        now,
                        now,
                        now,
                    ),
                )

                await db.commit()

            except aiosqlite.IntegrityError as exc:
                raise ValueError(
                    "A user with the same external_id or phone already exists."
                ) from exc

            user_id = cursor.lastrowid

        result = await self.get_user(int(user_id))

        if result is None:
            raise RuntimeError("User creation failed.")

        return result

    async def update_user(
        self,
        user_id: int,
        first_name: Optional[str],
        last_name: Optional[str],
        username: Optional[str],
        phone: Optional[str],
        is_active: Optional[bool],
    ) -> Optional[dict[str, Any]]:
        current = await self.get_user(user_id)

        if current is None:
            return None

        now = datetime.now(timezone.utc).isoformat()

        first_name = (
            current["first_name"]
            if first_name is None
            else first_name
        )

        last_name = (
            current["last_name"]
            if last_name is None
            else last_name
        )

        username = (
            current["username"]
            if username is None
            else username
        )

        phone = (
            current["phone"]
            if phone is None
            else phone
        )

        active = (
            current["is_active"]
            if is_active is None
            else int(is_active)
        )

        async with await self.connect() as db:
            try:
                await db.execute(
                    """
                    UPDATE users
                    SET
                        first_name = ?,
                        last_name = ?,
                        username = ?,
                        phone = ?,
                        is_active = ?,
                        updated_at = ?,
                        last_seen = ?
                    WHERE id = ?
                    """,
                    (
                        first_name,
                        last_name,
                        username,
                        phone,
                        active,
                        now,
                        now,
                        user_id,
                    ),
                )

                await db.commit()

            except aiosqlite.IntegrityError as exc:
                raise ValueError(
                    "Phone or username conflicts with another record."
                ) from exc

        return await self.get_user(user_id)

    async def deactivate_user(
        self,
        user_id: int,
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()

        async with await self.connect() as db:
            cursor = await db.execute(
                """
                UPDATE users
                SET
                    is_active = 0,
                    updated_at = ?
                WHERE id = ?
                """,
                (now, user_id),
            )

            await db.commit()

            return cursor.rowcount > 0

    async def write_admin_log(
        self,
        action: str,
        details: str,
        ip: str,
        request_id: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()

        async with await self.connect() as db:
            await db.execute(
                """
                INSERT INTO admin_logs (
                    action,
                    details,
                    ip,
                    request_id,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    action,
                    details,
                    ip,
                    request_id,
                    now,
                ),
            )

            await db.commit()

    async def get_admin_logs(
        self,
        limit: int,
    ) -> list[dict[str, Any]]:
        async with await self.connect() as db:
            cursor = await db.execute(
                """
                SELECT
                    id,
                    action,
                    details,
                    ip,
                    request_id,
                    created_at
                FROM admin_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )

            rows = await cursor.fetchall()

            return [dict(row) for row in rows]


db = Database(settings.db_path)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_id: Optional[str] = Field(
        default=None,
        max_length=255,
    )

    first_name: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    last_name: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    username: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    phone: Optional[str] = Field(
        default=None,
        max_length=32,
    )

    source: Optional[str] = Field(
        default=None,
        max_length=100,
    )


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    first_name: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    last_name: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    username: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    phone: Optional[str] = Field(
        default=None,
        max_length=32,
    )

    is_active: Optional[bool] = None


class AdminTokenResponse(BaseModel):
    authenticated: bool


# ============================================================================
# ADMIN AUTHENTICATION
# ============================================================================

async def require_admin(
    request: Request,
    token: str = Query(...),
) -> bool:
    if not Security.constant_time_compare(
        token,
        settings.ADMIN_TOKEN,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid administrator token.",
        )

    return True


# ============================================================================
# REQUEST MIDDLEWARE
# ============================================================================

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        request_id = Security.request_id()

        request.state.request_id = request_id

        start = time.monotonic()

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        try:
            response = await call_next(request)

        except Exception:
            log.exception(
                "Unhandled request error | %s %s | request_id=%s",
                request.method,
                request.url.path,
                request_id,
            )

            response = JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "Internal server error.",
                    "request_id": request_id,
                },
            )

        duration = (
            time.monotonic() - start
        ) * 1000

        response.headers["X-Request-ID"] = request_id

        log.info(
            "%s %s | %s | %.2fms | ip=%s | request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration,
            client_ip,
            request_id,
        )

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        if request.url.path in {
            "/api/v1/system/health",
            "/favicon.ico",
        }:
            return await call_next(request)

        allowed = await rate_limiter.check(client_ip)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "status": "error",
                    "message": "Rate limit exceeded.",
                    "retry_after": settings.RATE_LIMIT_WINDOW,
                },
            )

        return await call_next(request)


# ============================================================================
# LIFESPAN
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "Starting %s v%s",
        settings.APP_NAME,
        settings.APP_VERSION,
    )

    await db.initialize()

    log.info(
        "Environment: %s",
        settings.ENVIRONMENT.value,
    )

    log.info(
        "Database: %s",
        settings.db_path,
    )

    yield

    log.info("Application shutdown completed.")


# ============================================================================
# FASTAPI
# ============================================================================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Production-ready asynchronous API "
        "for Render deployment."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestContextMiddleware)


# ============================================================================
# ROOT
# ============================================================================

@app.get(
    "/",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def root():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pro Shop API</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    font-family:Inter,system-ui,sans-serif;
    background:
        radial-gradient(circle at 20% 20%,#19325c 0,transparent 35%),
        radial-gradient(circle at 80% 80%,#38204d 0,transparent 35%),
        #070b12;
    color:#fff;
}
.card{
    width:min(680px,92vw);
    padding:48px;
    border:1px solid rgba(255,255,255,.12);
    border-radius:28px;
    background:rgba(15,21,32,.78);
    backdrop-filter:blur(24px);
    box-shadow:0 30px 100px rgba(0,0,0,.45);
}
.badge{
    display:inline-block;
    padding:7px 12px;
    border-radius:999px;
    background:rgba(0,230,118,.12);
    color:#00e676;
    font-size:12px;
    font-weight:700;
}
h1{font-size:38px;margin:18px 0 10px}
p{color:#98a5b8;line-height:1.7}
.grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:12px;
    margin-top:30px;
}
.item{
    padding:18px;
    border-radius:16px;
    background:rgba(255,255,255,.045);
    border:1px solid rgba(255,255,255,.08);
}
.item strong{display:block;margin-bottom:6px}
.item span{color:#8290a5;font-size:13px}
a{
    color:#8ab4ff;
    text-decoration:none;
}
@media(max-width:600px){
    .card{padding:30px}
    h1{font-size:30px}
    .grid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="card">
    <span class="badge">● SYSTEM ONLINE</span>
    <h1>Pro Shop Enterprise API</h1>
    <p>
        Production FastAPI service is running successfully.
        The application is optimized for asynchronous SQLite,
        Render deployment, structured logging and API administration.
    </p>
    <div class="grid">
        <div class="item">
            <strong>FastAPI</strong>
            <span>Async API</span>
        </div>
        <div class="item">
            <strong>SQLite</strong>
            <span>WAL enabled</span>
        </div>
        <div class="item">
            <strong>Render</strong>
            <span>Cloud ready</span>
        </div>
    </div>
    <p style="margin-top:28px">
        <a href="/docs">Open API Documentation →</a>
    </p>
</div>
</body>
</html>
"""


# ============================================================================
# HEALTH
# ============================================================================

@app.get(
    "/api/v1/system/health",
    tags=["System"],
)
async def health():
    started = getattr(
        app.state,
        "started_at",
        time.time(),
    )

    try:
        user_count = await db.count_users()
        database_status = "healthy"

    except Exception:
        log.exception("Health check database failure")
        user_count = None
        database_status = "unhealthy"

    return {
        "status": (
            "healthy"
            if database_status == "healthy"
            else "degraded"
        ),
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT.value,
        "database": database_status,
        "users": user_count,
        "uptime_seconds": round(
            time.time() - started,
            2,
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


@app.get(
    "/api/v1/system/ready",
    tags=["System"],
)
async def readiness():
    try:
        await db.count_users()

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Database is not ready.",
        ) from exc

    return {
        "status": "ready",
    }


# ============================================================================
# USERS
# ============================================================================

@app.post(
    "/api/v1/users",
    tags=["Users"],
)
async def create_user(
    payload: UserCreate,
    request: Request,
):
    try:
        user = await db.create_user(
            external_id=Security.sanitize_text(
                payload.external_id,
                255,
            ),
            first_name=Security.sanitize_text(
                payload.first_name,
                100,
            ),
            last_name=Security.sanitize_text(
                payload.last_name,
                100,
            ),
            username=Security.sanitize_text(
                payload.username,
                100,
            ),
            phone=Security.sanitize_text(
                payload.phone,
                32,
            ),
            source=Security.sanitize_text(
                payload.source,
                100,
            ),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    return {
        "status": "success",
        "message": "User created.",
        "data": user,
        "request_id": request.state.request_id,
    }


@app.get(
    "/api/v1/users",
    tags=["Users"],
)
async def get_users(
    limit: int = Query(
        100,
        ge=1,
        le=settings.MAX_USERS_PER_REQUEST,
    ),
    offset: int = Query(
        0,
        ge=0,
    ),
    _: bool = Depends(require_admin),
):
    users = await db.get_users(
        limit=limit,
        offset=offset,
    )

    return {
        "status": "success",
        "count": len(users),
        "limit": limit,
        "offset": offset,
        "data": users,
    }


@app.get(
    "/api/v1/users/{user_id}",
    tags=["Users"],
)
async def get_user(
    user_id: int,
    _: bool = Depends(require_admin),
):
    user = await db.get_user(user_id)

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    return {
        "status": "success",
        "data": user,
    }


@app.patch(
    "/api/v1/users/{user_id}",
    tags=["Users"],
)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    _: bool = Depends(require_admin),
):
    try:
        user = await db.update_user(
            user_id=user_id,
            first_name=Security.sanitize_text(
                payload.first_name,
                100,
            ),
            last_name=Security.sanitize_text(
                payload.last_name,
                100,
            ),
            username=Security.sanitize_text(
                payload.username,
                100,
            ),
            phone=Security.sanitize_text(
                payload.phone,
                32,
            ),
            is_active=payload.is_active,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    await db.write_admin_log(
        action="UPDATE_USER",
        details=f"user_id={user_id}",
        ip=client_ip,
        request_id=request.state.request_id,
    )

    return {
        "status": "success",
        "message": "User updated.",
        "data": user,
    }


@app.delete(
    "/api/v1/users/{user_id}",
    tags=["Users"],
)
async def deactivate_user(
    user_id: int,
    request: Request,
    _: bool = Depends(require_admin),
):
    changed = await db.deactivate_user(user_id)

    if not changed:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    await db.write_admin_log(
        action="DEACTIVATE_USER",
        details=f"user_id={user_id}",
        ip=client_ip,
        request_id=request.state.request_id,
    )

    return {
        "status": "success",
        "message": "User deactivated.",
    }


# ============================================================================
# ADMIN
# ============================================================================

@app.get(
    "/api/v1/admin/verify",
    response_model=AdminTokenResponse,
    tags=["Admin"],
)
async def verify_admin(
    _: bool = Depends(require_admin),
):
    return {
        "authenticated": True,
    }


@app.get(
    "/api/v1/admin/logs",
    tags=["Admin"],
)
async def admin_logs(
    limit: int = Query(
        100,
        ge=1,
        le=500,
    ),
    _: bool = Depends(require_admin),
):
    logs = await db.get_admin_logs(limit)

    return {
        "status": "success",
        "count": len(logs),
        "data": logs,
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "request_id": getattr(
                request.state,
                "request_id",
                None,
            ),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):
    log.exception(
        "Unhandled exception | request_id=%s",
        getattr(
            request.state,
            "request_id",
            "unknown",
        ),
    )

    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error.",
            "request_id": getattr(
                request.state,
                "request_id",
                None,
            ),
        },
    )


# ============================================================================
# STARTUP TIMESTAMP
# ============================================================================

app.state.started_at = time.time()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower(),
        workers=1,
    )
