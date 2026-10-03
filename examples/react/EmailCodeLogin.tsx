import { FormEvent, useEffect, useState } from 'react';
import { getSession, requestEmailCode, verifyEmailCode } from '../../frontend/auth-client';

export function EmailCodeLogin({ onVerified }: { onVerified?: () => void }) {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [sent, setSent] = useState(false);
  const [verified, setVerified] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    getSession().then((s) => setVerified(s.authenticated && s.verified));
  }, []);

  async function send(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { await requestEmailCode(email); setSent(true); }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not send code'); }
    finally { setBusy(false); }
  }

  async function verify(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('');
    try { await verifyEmailCode(email, code); setVerified(true); onVerified?.(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not verify code'); }
    finally { setBusy(false); }
  }

  if (verified) return <p>Signed in.</p>;

  return (
    <div>
      {!sent ? (
        <form onSubmit={send}>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" required />
          <button disabled={busy}>{busy ? 'Sending…' : 'Email me a code'}</button>
        </form>
      ) : (
        <form onSubmit={verify}>
          <input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} placeholder="6-digit code" required />
          <button disabled={busy || code.length !== 6}>{busy ? 'Checking…' : 'Confirm code'}</button>
        </form>
      )}
      {error ? <p role="alert">{error}</p> : null}
    </div>
  );
}
