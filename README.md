# Cloudflare Email Auth

Reusable passwordless email authentication extracted from the working BuildAWallet login flow.

## Features

- Email + 6-digit one-time confirmation code
- Resend delivery
- Cloudflare D1 accounts, challenges and sessions
- 10-minute codes
- Maximum 5 code attempts
- 30-day HttpOnly session cookie
- `Secure` + `SameSite=Lax`
- Session endpoint and logout
- Tiny TypeScript client
- Minimal React example
- No passwords or OAuth provider dependency

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/auth/session` | Check the current browser session |
| POST | `/auth/email/request` | Send a 6-digit login code |
| POST | `/auth/email/verify` | Verify code and set session cookie |
| POST | `/auth/logout` | Delete session |
| GET | `/auth/protected-example` | Example protected route |
| GET | `/healthz` | Worker health |

## Best way to reuse it across your sites

Deploy the same repository on each site's own domain and route `/auth/*` to it. That keeps the cookie first-party and avoids cross-site cookie issues.

Examples:

- `btcme.click/auth/*`
- `ltcme.click/auth/*`
- `monadblockchain.com/auth/*`
- `buildawallet.xyz/auth/*`

Each deployment can use its own D1 database, cookie name and app name while sharing this exact codebase.

## Set up a new site

### 1. Create D1

```bash
npx wrangler d1 create my-site-auth
```

Copy the returned database ID.

### 2. Configure Wrangler

```bash
cp wrangler.example.jsonc wrangler.jsonc
```

Edit the Worker name, app name, sender, cookie name, D1 database name/ID, and add your desired route, for example:

```jsonc
"routes": [
  { "pattern": "example.com/auth/*", "zone_name": "example.com" },
  { "pattern": "example.com/healthz", "zone_name": "example.com" }
]
```

### 3. Apply schema

```bash
npx wrangler d1 execute my-site-auth \
  --remote \
  --file=./migrations/0001_email_auth.sql
```

### 4. Add secrets

```bash
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put AUTH_EMAIL_PEPPER
```

Generate a pepper with:

```bash
openssl rand -hex 32
```

Enter that only into the Wrangler secret prompt. Do not commit it.

### 5. Deploy

Cloudflare's current Python tooling supports FastAPI through Pywrangler:

```bash
uv run pywrangler deploy
```

If your existing project already bundles Python Worker dependencies through Wrangler, you can keep using that deployment path.

## Smoke test

Before login:

```bash
curl -sS https://example.com/auth/session
```

Expected:

```json
{"authenticated":false,"verified":false}
```

Send code:

```bash
curl -sS \
  -X POST \
  https://example.com/auth/email/request \
  -H 'content-type: application/json' \
  --data '{"email":"you@example.com"}'
```

Verify code:

```bash
curl -i \
  -c /tmp/site-auth-cookie.txt \
  -X POST \
  https://example.com/auth/email/verify \
  -H 'content-type: application/json' \
  --data '{"email":"you@example.com","code":"123456"}'
```

Check session:

```bash
curl -sS \
  -b /tmp/site-auth-cookie.txt \
  https://example.com/auth/session
```

Expected:

```json
{"authenticated":true,"verified":true}
```

## Frontend

Copy `frontend/auth-client.ts` into any frontend project. A minimal React component is included at `examples/react/EmailCodeLogin.tsx`.

Typical guard:

```ts
const session = await getSession();
if (!session.authenticated || !session.verified) {
  // show login UI
}
```

## Protect an API route

```python
@app.post("/api/private-action")
async def private_action(request: Request):
    await require_account(request)
    return {"ok": True}
```

## Per-site configuration example

BTCme.click:

```json
{
  "AUTH_APP_NAME": "BTCme.click",
  "AUTH_EMAIL_FROM": "BTCme.click <accounts@your-verified-domain.com>",
  "AUTH_COOKIE_NAME": "btcme_session"
}
```

LTCme.click:

```json
{
  "AUTH_APP_NAME": "LTCme.click",
  "AUTH_EMAIL_FROM": "LTCme.click <accounts@your-verified-domain.com>",
  "AUTH_COOKIE_NAME": "ltcme_session"
}
```

## Security notes

- Random session tokens; only hashes are stored in D1.
- HttpOnly, Secure, SameSite=Lax cookies by default.
- Emails are normalized and hashed before storage.
- `AUTH_EMAIL_PEPPER` makes leaked email hashes much harder to reverse.
- Codes expire after 10 minutes.
- Challenges are discarded after 5 failed attempts.
- Add Cloudflare rate limiting to `/auth/email/request` before high-volume use.
- Keep `RESEND_API_KEY` and `AUTH_EMAIL_PEPPER` as Worker secrets.

## Origin

Extracted and generalized from the passwordless HUMAN account flow used by BuildAWallet.xyz.
