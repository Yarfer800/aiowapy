CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS creds (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS prekeys (
    id       INTEGER PRIMARY KEY,
    key_pair BLOB NOT NULL,
    uploaded INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    jid    TEXT PRIMARY KEY,
    record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_keys (
    jid   TEXT PRIMARY KEY,
    key   BLOB NOT NULL,
    trust TEXT NOT NULL DEFAULT 'trusted'
);

CREATE TABLE IF NOT EXISTS app_state_keys (
    key_id   BLOB PRIMARY KEY,
    key_data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS app_state_ver (
    name    TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    hash    BLOB NOT NULL
);
