CREATE TABLE IF NOT EXISTS app_state_data (
    collection TEXT NOT NULL,
    index_json TEXT NOT NULL,
    value      BLOB NOT NULL,
    timestamp  INTEGER NOT NULL,
    value_mac  BLOB NOT NULL,
    PRIMARY KEY (collection, index_json)
);
