-- Channel workspace key-value storage for WASM channels.
-- Replaces filesystem-based persistence with database-backed storage.
CREATE TABLE IF NOT EXISTS channel_workspace (
    channel_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, key)
);

-- Index for prefix-based listing (e.g., listing all keys under "crypto/").
CREATE INDEX idx_channel_workspace_prefix
    ON channel_workspace (channel_id, key text_pattern_ops);
