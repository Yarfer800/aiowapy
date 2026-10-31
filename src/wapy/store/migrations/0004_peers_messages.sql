CREATE TABLE IF NOT EXISTS peers (
    jid            TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    phone          TEXT,
    push_name      TEXT,
    contact_name   TEXT,
    subject        TEXT,
    last_update_on INTEGER NOT NULL DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_peers_kind ON peers (kind);
CREATE INDEX IF NOT EXISTS idx_peers_phone ON peers (phone);

CREATE TABLE IF NOT EXISTS messages (
    chat_jid   TEXT NOT NULL,
    message_id TEXT NOT NULL,
    sender_jid TEXT,
    timestamp  INTEGER,
    text       TEXT,
    media_json TEXT,
    outgoing   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (chat_jid, message_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages (chat_jid, timestamp DESC);
