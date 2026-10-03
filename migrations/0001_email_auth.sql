DROP TABLE IF EXISTS auth_email_challenges;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS auth_email_accounts;

CREATE TABLE auth_email_accounts (
  email_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE TABLE auth_email_challenges (
  email_hash TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE auth_sessions (
  token_hash TEXT PRIMARY KEY,
  email_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires ON auth_email_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_email ON auth_sessions(email_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
