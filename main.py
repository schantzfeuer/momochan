from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "momochan.sqlite3"
TEMPLATES = Jinja2Templates(directory=str(ROOT / "templates"))
GAMES = {
	"la-puta": {"title": "La Puta", "file": "La Puta.html", "icon": "✿", "tone": "rose"},
	"pirate": {"title": "The Pirate's Fortune", "file": "The Pirate's Fortune.html", "icon": "☠", "tone": "lilac"},
	"fish": {"title": "The Fish", "file": "fish.html", "icon": "✧", "tone": "peach"},
}
MAX_SAVE_BYTES = 15 * 1024 * 1024


def connect_db() -> sqlite3.Connection:
	connection = sqlite3.connect(DB_PATH, timeout=15)
	connection.row_factory = sqlite3.Row
	connection.execute("PRAGMA foreign_keys = ON")
	connection.execute("PRAGMA busy_timeout = 15000")
	return connection


def initialize_db() -> str:
	with connect_db() as db:
		db.executescript(
			"""
			CREATE TABLE IF NOT EXISTS app_meta (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL COLLATE NOCASE UNIQUE,
				password_hash TEXT NOT NULL,
				created_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS game_saves (
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				game_id TEXT NOT NULL,
				storage_key TEXT NOT NULL,
				payload TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				PRIMARY KEY (user_id, game_id, storage_key)
			);
			"""
		)
		row = db.execute("SELECT value FROM app_meta WHERE key = 'session_secret'").fetchone()
		if row:
			return row["value"]
		secret = secrets.token_urlsafe(48)
		db.execute("INSERT INTO app_meta(key, value) VALUES ('session_secret', ?)", (secret,))
		return secret


def hash_password(password: str) -> str:
	salt = secrets.token_bytes(16)
	digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
	return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
	try:
		algorithm, salt_hex, digest_hex = encoded.split("$", 2)
		if algorithm != "pbkdf2_sha256":
			return False
		digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 600_000)
		return hmac.compare_digest(digest.hex(), digest_hex)
	except (ValueError, TypeError):
		return False


app = FastAPI(title="Project Momochan")
app.add_middleware(
	SessionMiddleware,
	secret_key=initialize_db(),
	session_cookie="momochan_session",
	same_site="lax",
	https_only=os.getenv("MOMOCHAN_HTTPS_ONLY", "0") == "1",
	max_age=60 * 60 * 24 * 30,
)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


def current_user(request: Request) -> sqlite3.Row | None:
	user_id = request.session.get("user_id")
	if not isinstance(user_id, int):
		return None
	with connect_db() as db:
		return db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()


def require_user(request: Request) -> sqlite3.Row:
	user = current_user(request)
	if user is None:
		raise HTTPException(status_code=401, detail="Please sign in again.")
	return user


def render_page(template: str, request: Request, **context: Any) -> HTMLResponse:
	return TEMPLATES.TemplateResponse(
		request=request,
		name=template,
		context={"request": request, **context},
	)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
	user = current_user(request)
	if user is None:
		return RedirectResponse("/register", status_code=303)
	return render_page("dashboard.html", request, user=user, games=GAMES)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
	if current_user(request):
		return RedirectResponse("/", status_code=303)
	return render_page("auth.html", request, mode="register", message=request.query_params.get("message", ""))


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
	username = username.strip()
	if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
		return RedirectResponse("/register?message=" + quote("Username must be 3-24 characters: letters, numbers, or underscores."), status_code=303)
	if len(password) < 10 or len(password) > 128:
		return RedirectResponse("/register?message=" + quote("Password must be 10-128 characters long."), status_code=303)
	try:
		with connect_db() as db:
			cursor = db.execute(
				"INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
				(username, hash_password(password), datetime.now(timezone.utc).isoformat()),
			)
			request.session["user_id"] = cursor.lastrowid
			request.session["username"] = username
	except sqlite3.IntegrityError:
		return RedirectResponse("/register?message=" + quote("That username is already taken."), status_code=303)
	return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
	if current_user(request):
		return RedirectResponse("/", status_code=303)
	return render_page("auth.html", request, mode="login", message=request.query_params.get("message", ""))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
	with connect_db() as db:
		user = db.execute("SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)).fetchone()
	if user is None or not verify_password(password, user["password_hash"]):
		return RedirectResponse("/login?message=" + quote("Username or password is incorrect."), status_code=303)
	request.session.clear()
	request.session["user_id"] = user["id"]
	request.session["username"] = user["username"]
	return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
	request.session.clear()
	return RedirectResponse("/login", status_code=303)


@app.get("/api/storage/{game_id}")
def read_game_storage(game_id: str, request: Request):
	user = require_user(request)
	if game_id not in GAMES:
		raise HTTPException(status_code=404, detail="Game not found.")
	with connect_db() as db:
		rows = db.execute(
			"SELECT storage_key, payload FROM game_saves WHERE user_id = ? AND game_id = ?",
			(user["id"], game_id),
		).fetchall()
	return {row["storage_key"]: row["payload"] for row in rows}


@app.post("/api/storage/{game_id}")
async def write_game_storage(game_id: str, request: Request):
	user = require_user(request)
	if game_id not in GAMES:
		raise HTTPException(status_code=404, detail="Game not found.")
	if int(request.headers.get("content-length", "0") or 0) > MAX_SAVE_BYTES:
		raise HTTPException(status_code=413, detail="Save data is too large.")
	try:
		body = await request.json()
	except Exception as exc:
		raise HTTPException(status_code=400, detail="Invalid data format.") from exc
	if not isinstance(body, dict):
		raise HTTPException(status_code=400, detail="Invalid data format.")
	key, value = body.get("key"), body.get("value")
	if not isinstance(key, str) or not 1 <= len(key) <= 200 or not isinstance(value, str):
		raise HTTPException(status_code=400, detail="Invalid save key or data.")
	if len(value.encode("utf-8")) > MAX_SAVE_BYTES:
		raise HTTPException(status_code=413, detail="Save data is too large.")
	updated_at = datetime.now(timezone.utc).isoformat()
	with connect_db() as db:
		db.execute(
			"INSERT INTO game_saves(user_id, game_id, storage_key, payload, updated_at) VALUES (?, ?, ?, ?, ?) "
			"ON CONFLICT(user_id, game_id, storage_key) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
			(user["id"], game_id, key, value, updated_at),
		)
	return {"ok": True, "updated_at": updated_at}


@app.delete("/api/storage/{game_id}/{storage_key}")
def delete_game_storage(game_id: str, storage_key: str, request: Request):
	user = require_user(request)
	if game_id not in GAMES:
		raise HTTPException(status_code=404, detail="Game not found.")
	with connect_db() as db:
		db.execute(
			"DELETE FROM game_saves WHERE user_id = ? AND game_id = ? AND storage_key = ?",
			(user["id"], game_id, storage_key),
		)
	return {"ok": True}


@app.get("/play/{game_id}", response_class=HTMLResponse)
def play_game(game_id: str, request: Request):
	user = require_user(request)
	game = GAMES.get(game_id)
	if game is None:
		raise HTTPException(status_code=404, detail="Game not found.")
	source = (ROOT / game["file"]).read_text(encoding="utf-8")
	with connect_db() as db:
		rows = db.execute(
			"SELECT storage_key, payload FROM game_saves WHERE user_id = ? AND game_id = ?",
			(user["id"], game_id),
		).fetchall()
	saved_values = {row["storage_key"]: row["payload"] for row in rows}
	bootstrap = """<script>
window.__MOMOCHAN_GAME__ = __GAME__;
window.__MOMOCHAN_VALUES__ = __VALUES__;
(() => {
  const values = window.__MOMOCHAN_VALUES__;
  const endpoint = '/api/storage/' + encodeURIComponent(window.__MOMOCHAN_GAME__);
  const pending = new Map();
	let syncQueue = Promise.resolve();
  let timer;
  const flush = () => {
		clearTimeout(timer);
		const entries = Array.from(pending);
		pending.clear();
		if (entries.length) syncQueue = syncQueue.then(async () => {
			for (const [key, value] of entries) {
				await fetch(endpoint, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, value }) });
			}
		}).catch(error => console.error('Save sync failed:', error));
  };
  window.momochanStorage = {
	getItem(key) { key = String(key); return Object.prototype.hasOwnProperty.call(values, key) ? values[key] : null; },
	setItem(key, value) { key = String(key); value = String(value); values[key] = value; pending.set(key, value); clearTimeout(timer); timer = setTimeout(flush, 250); },
	removeItem(key) { key = String(key); delete values[key]; pending.delete(key); syncQueue = syncQueue.then(() => fetch(endpoint + '/' + encodeURIComponent(key), { method: 'DELETE', credentials: 'same-origin' })).catch(error => console.error('Save sync failed:', error)); },
	clear() { for (const key of Object.keys(values)) this.removeItem(key); },
	key(index) { return Object.keys(values)[index] ?? null; },
	get length() { return Object.keys(values).length; }
  };
  window.addEventListener('pagehide', flush);
})();
</script>""".replace("__GAME__", json.dumps(game_id)).replace("__VALUES__", json.dumps(saved_values).replace("</", "<\\/"))
	source = source.replace("</head>", bootstrap + "</head>", 1)
	source = source.replace("localStorage", "momochanStorage")
	source = source.replace("Saves go to momochanStorage.", "Saves sync to your account.")
	source = source.replace("Browser storage", "Account storage").replace("browser storage", "account storage")
	source = source.replace("local save", "account save")
	source = source.replace("Progress saves automatically in this browser.", "Progress saves automatically to your account.")
	source = source.replace("Browser storage may be full.", "Account storage may be unavailable.")
	source = source.replace("<body>", '<body><a href="/" aria-label="Back to the Project Momochan library" style="position:fixed;top:10px;right:10px;z-index:10000;padding:7px 11px;border:1px solid #8c668f;border-radius:8px;background:#21182a;color:#f8effb;font:700 12px Nunito, sans-serif;text-decoration:none;box-shadow:0 3px 12px #0005">← Momochan</a>', 1)
	return HTMLResponse(source, headers={"Cache-Control": "no-store"})


@app.get("/api/health")
def health():
	return JSONResponse({"ok": True, "app": "Project Momochan"})
