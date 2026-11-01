CREATE TABLE IF NOT EXISTS lid_mappings (
    pn_jid TEXT PRIMARY KEY,
    lid_jid TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_lid_mappings_lid ON lid_mappings (lid_jid);
