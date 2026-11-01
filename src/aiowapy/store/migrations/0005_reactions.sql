CREATE TABLE IF NOT EXISTS deleted_messages (
    chat_jid   TEXT NOT NULL,
    message_id TEXT NOT NULL,
    PRIMARY KEY (chat_jid, message_id)
);

CREATE TABLE IF NOT EXISTS reactions (
    chat_jid   TEXT NOT NULL,
    message_id TEXT NOT NULL,
    sender_jid TEXT NOT NULL,
    text       TEXT NOT NULL,
    timestamp  INTEGER,
    PRIMARY KEY (chat_jid, message_id, sender_jid)
);
