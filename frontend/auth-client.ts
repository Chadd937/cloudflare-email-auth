export type AuthSession = {
  authenticated: boolean;
  verified: boolean;
};

export async function getSession(): Promise<AuthSession> {
  const res = await fetch('/auth/session', { credentials: 'include', cache: 'no-store' });
  if (!res.ok) return { authenticated: false, verified: false };
  return res.json();
}

export async function requestEmailCode(email: string) {
  const res = await fetch('/auth/email/request', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || 'Could not send confirmation email');
  return body as { ok: true; sent: true; expiresIn: number };
}

export async function verifyEmailCode(email: string, code: string) {
  const res = await fetch('/auth/email/verify', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || 'Could not verify confirmation code');
  return body as AuthSession & { ok: true };
}

export async function logout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
}
