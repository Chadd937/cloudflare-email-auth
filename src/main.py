"""Reusable passwordless email auth for Cloudflare Python Workers + D1 + Resend."""

import hashlib
import json
import re
import secrets
import time

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from workers import asgi
from workers import fetch as worker_fetch

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
Default = asgi.entrypoint(app)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
VERIFY_TTL_SECONDS = 10 * 60
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_VERIFY_ATTEMPTS = 5


class EmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class VerifyRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    code: str = Field(min_length=6, max_length=6)


def env_for(request: Request):
    return request.scope.get("env")


def db_for(request: Request):
    env = env_for(request)
    db = getattr(env, "DB", None) if env is not None else None
    if db is None:
        raise HTTPException(503, "Auth database is not configured")
    return db


def env_text(request: Request, name: str, default: str = "") -> str:
    env = env_for(request)
    if env is None:
        return default
    return str(getattr(env, name, "") or default).strip()


def now_seconds() -> int:
    return int(time.time())


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Enter a valid email address")
    return email


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def email_hash(request: Request, email: str) -> str:
    pepper = env_text(request, "AUTH_EMAIL_PEPPER")
    return sha256_text(f"{pepper}:{email}" if pepper else email)


def cookie_name(request: Request) -> str:
    return env_text(request, "AUTH_COOKIE_NAME", "site_session")


def cookie_secure(request: Request) -> bool:
    return env_text(request, "AUTH_COOKIE_SECURE", "true").lower() != "false"


def public_session(account: dict | None) -> dict:
    if account is None:
        return {"authenticated": False, "verified": False}
    return {"authenticated": True, "verified": True}


async def current_account(request: Request):
    token = request.cookies.get(cookie_name(request))
    if not token:
        return None

    db = db_for(request)
    token_hash = sha256_text(token)
    now = now_seconds()

    session = await (
        db.prepare(
            """
            SELECT token_hash, email_hash, expires_at
            FROM auth_sessions
            WHERE token_hash = ?
            """
        )
        .bind(token_hash)
        .first()
    )

    if not session:
        return None

    expires_at = int(session.expires_at)
    if expires_at <= now:
        await db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(token_hash).run()
        return None

    account = await (
        db.prepare(
            """
            SELECT email_hash, verified_at
            FROM auth_email_accounts
            WHERE email_hash = ?
            """
        )
        .bind(session.email_hash)
        .first()
    )
    if not account:
        return None

    await db.prepare("UPDATE auth_sessions SET last_seen_at = ? WHERE token_hash = ?").bind(now, token_hash).run()
    await db.prepare("UPDATE auth_email_accounts SET last_seen_at = ? WHERE email_hash = ?").bind(now, session.email_hash).run()

    return {"email_hash": str(account.email_hash), "verified_at": int(account.verified_at)}


async def require_account(request: Request):
    account = await current_account(request)
    if account is None:
        raise HTTPException(401, "Confirm your email before continuing")
    return account


async def send_verification_email(request: Request, email: str, code: str):
    api_key = env_text(request, "RESEND_API_KEY")
    email_from = env_text(request, "AUTH_EMAIL_FROM")
    app_name = env_text(request, "AUTH_APP_NAME", "Your App")

    if not api_key or not email_from:
        raise HTTPException(503, "Email confirmation delivery is not configured")

    payload = {
        "from": email_from,
        "to": [email],
        "subject": f"Confirm your {app_name} account",
        "html": (
            "<div style='font-family:Arial,sans-serif;max-width:520px'>"
            f"<h2>Confirm your {app_name} account</h2>"
            f"<p>Your one-time confirmation code is <strong style='font-size:24px'>{code}</strong>.</p>"
            "<p>This code expires in 10 minutes.</p>"
            "</div>"
        ),
    }

    try:
        response = await worker_fetch(
            "https://api.resend.com/emails",
            method="POST",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            body=json.dumps(payload),
        )
    except Exception as exc:
        print(f"RESEND_FETCH_ERROR type={type(exc).__name__} message={exc}")
        raise HTTPException(503, "Could not send confirmation email") from exc

    if int(response.status) >= 300:
        try:
            detail = await response.text()
        except Exception:
            detail = ""
        print(f"RESEND_REJECTED status={response.status} body={detail[:800]}")
        raise HTTPException(503, "Could not send confirmation email")


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/auth/session")
async def session(request: Request):
    return public_session(await current_account(request))


@app.get("/auth/identity")
async def identity(request: Request):
    """Return the authenticated account identifier for trusted server-side callers."""
    account = await require_account(request)
    return {"authenticated": True, "verified": True, "account_id": str(account["email_hash"])}


@app.post("/auth/email/request")
async def request_email_code(payload: EmailRequest, request: Request):
    email = normalize_email(payload.email)
    db = db_for(request)
    now = now_seconds()
    code = f"{secrets.randbelow(1_000_000):06d}"
    ehash = email_hash(request, email)
    chash = sha256_text(f"{ehash}:{code}")

    await (
        db.prepare(
            """
            INSERT INTO auth_email_challenges (email_hash, code_hash, expires_at, attempts, created_at)
            VALUES (?, ?, ?, 0, ?)
            ON CONFLICT(email_hash) DO UPDATE SET
              code_hash = excluded.code_hash,
              expires_at = excluded.expires_at,
              attempts = 0,
              created_at = excluded.created_at
            """
        )
        .bind(ehash, chash, now + VERIFY_TTL_SECONDS, now)
        .run()
    )

    await send_verification_email(request, email, code)
    return {"ok": True, "sent": True, "expiresIn": VERIFY_TTL_SECONDS}


@app.post("/auth/email/verify")
async def verify_email_code(payload: VerifyRequest, request: Request, response: Response):
    email = normalize_email(payload.email)
    code = payload.code.strip()
    if not re.fullmatch(r"\d{6}", code):
        raise HTTPException(400, "Enter the 6-digit confirmation code")

    db = db_for(request)
    now = now_seconds()
    ehash = email_hash(request, email)

    challenge = await (
        db.prepare(
            """
            SELECT email_hash, code_hash, expires_at, attempts
            FROM auth_email_challenges
            WHERE email_hash = ?
            """
        )
        .bind(ehash)
        .first()
    )

    if not challenge:
        raise HTTPException(400, "Request a new confirmation code")
    if int(challenge.expires_at) <= now:
        await db.prepare("DELETE FROM auth_email_challenges WHERE email_hash = ?").bind(ehash).run()
        raise HTTPException(400, "Confirmation code expired")

    attempts = int(challenge.attempts)
    if attempts >= MAX_VERIFY_ATTEMPTS:
        await db.prepare("DELETE FROM auth_email_challenges WHERE email_hash = ?").bind(ehash).run()
        raise HTTPException(400, "Too many attempts. Request a new code")

    supplied = sha256_text(f"{ehash}:{code}")
    if not secrets.compare_digest(str(challenge.code_hash), supplied):
        await db.prepare("UPDATE auth_email_challenges SET attempts = attempts + 1 WHERE email_hash = ?").bind(ehash).run()
        raise HTTPException(400, "Incorrect confirmation code")

    await (
        db.prepare(
            """
            INSERT INTO auth_email_accounts (email_hash, created_at, verified_at, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(email_hash) DO UPDATE SET
              verified_at = excluded.verified_at,
              last_seen_at = excluded.last_seen_at
            """
        )
        .bind(ehash, now, now, now)
        .run()
    )
    await db.prepare("DELETE FROM auth_email_challenges WHERE email_hash = ?").bind(ehash).run()

    raw_token = secrets.token_urlsafe(32)
    token_hash = sha256_text(raw_token)
    await (
        db.prepare(
            """
            INSERT INTO auth_sessions (token_hash, email_hash, created_at, expires_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            """
        )
        .bind(token_hash, ehash, now, now + SESSION_TTL_SECONDS, now)
        .run()
    )

    response.set_cookie(
        key=cookie_name(request), value=raw_token, max_age=SESSION_TTL_SECONDS,
        path="/", secure=cookie_secure(request), httponly=True, samesite="lax"
    )
    return {"ok": True, "authenticated": True, "verified": True}


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(cookie_name(request))
    if token:
        db = db_for(request)
        await db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(sha256_text(token)).run()

    response.delete_cookie(
        key=cookie_name(request), path="/", secure=cookie_secure(request),
        httponly=True, samesite="lax"
    )
    return {"ok": True}


@app.get("/auth/protected-example")
async def protected_example(request: Request):
    await require_account(request)
    return {"ok": True, "message": "You are signed in."}
