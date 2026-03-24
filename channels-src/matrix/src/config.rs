//! Matrix channel configuration.
//!
//! Parsed from the `config` section of `matrix.capabilities.json`
//! and injected via `on_start(config_json)`.

use serde::Deserialize;

/// Channel configuration from the capabilities file.
#[derive(Debug, Deserialize)]
pub struct MatrixConfig {
    /// Matrix homeserver URL (e.g. "https://matrix.example.com").
    /// Used to construct API endpoint URLs.
    #[serde(default)]
    pub homeserver_url: String,

    /// Matrix user ID (e.g. "@bot:example.com").
    /// If empty, auto-detected from /whoami at startup.
    #[serde(default)]
    pub user_id: Option<String>,

    /// Device ID for E2EE. If empty, auto-generated.
    #[serde(default)]
    pub device_id: Option<String>,

    /// DM policy: "pairing" (default), "allowlist", or "open".
    #[serde(default = "default_dm_policy")]
    pub dm_policy: String,

    /// Allowed sender user IDs (merged with pairing-approved store).
    #[serde(default)]
    pub allow_from: Vec<String>,

    /// Whether to respond to all messages in rooms (not just DMs).
    #[serde(default)]
    pub respond_to_all_room_messages: bool,

    /// Restrict to these room IDs. Empty means all rooms (subject to DM policy).
    #[serde(default)]
    pub allowed_room_ids: Vec<String>,

    /// Sync long-poll timeout in milliseconds.
    #[serde(default = "default_sync_timeout")]
    pub sync_timeout_ms: u32,

    /// Whether E2EE is enabled.
    #[serde(default)]
    pub enable_e2ee: bool,
}

fn default_dm_policy() -> String {
    "pairing".to_string()
}

fn default_sync_timeout() -> u32 {
    30_000
}

#[cfg(test)]
impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            homeserver_url: String::new(),
            user_id: None,
            device_id: None,
            dm_policy: default_dm_policy(),
            allow_from: Vec::new(),
            respond_to_all_room_messages: false,
            allowed_room_ids: Vec::new(),
            sync_timeout_ms: default_sync_timeout(),
            enable_e2ee: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MatrixConfig::default();
        assert_eq!(config.dm_policy, "pairing");
        assert_eq!(config.sync_timeout_ms, 30_000);
        assert!(!config.enable_e2ee);
        assert!(!config.respond_to_all_room_messages);
    }

    #[test]
    fn test_parse_minimal_config() {
        let json = r#"{"homeserver_url": "https://matrix.example.com"}"#;
        let config: MatrixConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.homeserver_url, "https://matrix.example.com");
        assert_eq!(config.dm_policy, "pairing");
        assert!(config.user_id.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let json = r#"{
            "homeserver_url": "https://matrix.example.com",
            "user_id": "@bot:example.com",
            "device_id": "ABCDEF",
            "dm_policy": "open",
            "allow_from": ["@alice:example.com"],
            "respond_to_all_room_messages": true,
            "allowed_room_ids": ["!room1:example.com"],
            "sync_timeout_ms": 60000,
            "enable_e2ee": true
        }"#;
        let config: MatrixConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.user_id.as_deref(), Some("@bot:example.com"));
        assert_eq!(config.dm_policy, "open");
        assert!(config.enable_e2ee);
        assert_eq!(config.sync_timeout_ms, 60_000);
        assert_eq!(config.allowed_room_ids.len(), 1);
    }
}
