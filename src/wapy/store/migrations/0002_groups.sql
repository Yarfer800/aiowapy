CREATE TABLE IF NOT EXISTS sender_keys (
    group_jid TEXT NOT NULL,
    sender    TEXT NOT NULL,
    record    BLOB NOT NULL,
    PRIMARY KEY (group_jid, sender)
);

CREATE TABLE IF NOT EXISTS groups (
    jid      TEXT PRIMARY KEY,
    record   BLOB NOT NULL,
    fetched  REAL NOT NULL
);
