//! CryptoStore backend using IronClaw's workspace storage.
//!
//! Persists E2EE state (Olm/Megolm sessions, device keys) across WASM
//! invocations using the host-provided workspace read/write functions.
//!
//! All data is stored under the `crypto/` prefix within the channel's
//! workspace namespace (i.e., `channels/matrix/crypto/...`).
//!
//! # Security
//!
//! - Private keys are serialized using vodozemac's pickle format with an
//!   encryption key derived from the `matrix_pickle_key` secret.
//! - The pickle key itself is stored in IronClaw's secrets store, never
//!   in the workspace.
//! - Key material is never logged or included in error messages.

use serde::{Deserialize, Serialize};

use crate::channel_host;

/// Prefix for all crypto state in workspace storage.
const CRYPTO_PREFIX: &str = "crypto/";

/// Account state (identity keys, pickled Olm account).
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredAccount {
    /// User ID of the account owner.
    pub user_id: String,

    /// Device ID.
    pub device_id: String,

    /// Pickled Olm account (encrypted with pickle key).
    pub pickled_account: String,

    /// Ed25519 identity key (public, safe to store in plaintext).
    pub ed25519_key: String,

    /// Curve25519 identity key (public, safe to store in plaintext).
    pub curve25519_key: String,

    /// Whether device keys have been uploaded to the homeserver.
    pub keys_uploaded: bool,

    /// Number of one-time keys uploaded.
    pub uploaded_key_count: u32,
}

/// A stored Olm session for device-to-device communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOlmSession {
    /// Sender's Curve25519 key (identifies the remote device).
    pub sender_key: String,

    /// Pickled Olm session (encrypted with pickle key).
    pub pickled_session: String,

    /// Timestamp of last use.
    pub last_use_ts: u64,
}

/// A stored inbound Megolm session for room message decryption.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredInboundMegolmSession {
    /// Room ID this session belongs to.
    pub room_id: String,

    /// Session ID.
    pub session_id: String,

    /// Sender's Curve25519 key.
    pub sender_key: String,

    /// Pickled session (encrypted with pickle key).
    pub pickled_session: String,

    /// Whether we forwarded this session (key request).
    pub forwarded: bool,

    /// Set of already-seen message indices for replay detection.
    #[serde(default)]
    pub seen_indices: Vec<u32>,
}

/// A stored outbound Megolm session for room message encryption.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredOutboundMegolmSession {
    /// Room ID this session belongs to.
    pub room_id: String,

    /// Session ID.
    pub session_id: String,

    /// Pickled session (encrypted with pickle key).
    pub pickled_session: String,

    /// Number of messages sent with this session.
    pub message_count: u32,

    /// Creation timestamp.
    pub created_ts: u64,
}

/// Read the stored Olm account.
pub fn read_account() -> Option<StoredAccount> {
    let path = format!("{}account.json", CRYPTO_PREFIX);
    let data = channel_host::workspace_read(&path)?;
    match serde_json::from_str::<StoredAccount>(&data) {
        Ok(account) => Some(account),
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("read_account: failed to deserialize: {}", e),
            );
            None
        }
    }
}

/// Write the Olm account.
pub fn write_account(account: &StoredAccount) -> Result<(), String> {
    let path = format!("{}account.json", CRYPTO_PREFIX);
    let json = serde_json::to_string(account)
        .map_err(|e| format!("Failed to serialize account: {}", e))?;
    channel_host::workspace_write(&path, &json)
}

/// Read Olm sessions for a given sender key.
pub fn read_olm_sessions(sender_key: &str) -> Vec<StoredOlmSession> {
    let safe_key = sanitize_key(sender_key);
    let path = format!("{}olm_sessions/{}.json", CRYPTO_PREFIX, safe_key);
    match channel_host::workspace_read(&path) {
        Some(data) => serde_json::from_str(&data).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// Write Olm sessions for a given sender key.
pub fn write_olm_sessions(
    sender_key: &str,
    sessions: &[StoredOlmSession],
) -> Result<(), String> {
    let safe_key = sanitize_key(sender_key);
    let path = format!("{}olm_sessions/{}.json", CRYPTO_PREFIX, safe_key);
    let json = serde_json::to_string(sessions)
        .map_err(|e| format!("Failed to serialize Olm sessions: {}", e))?;
    channel_host::workspace_write(&path, &json)
}

/// Read an inbound Megolm session.
pub fn read_inbound_megolm_session(
    room_id: &str,
    session_id: &str,
) -> Option<StoredInboundMegolmSession> {
    let safe_room = sanitize_key(room_id);
    let safe_session = sanitize_key(session_id);
    let path = format!(
        "{}megolm_inbound/{}/{}.json",
        CRYPTO_PREFIX, safe_room, safe_session
    );
    channel_host::workspace_read(&path)
        .and_then(|data| serde_json::from_str(&data).ok())
}

/// Write an inbound Megolm session.
pub fn write_inbound_megolm_session(
    session: &StoredInboundMegolmSession,
) -> Result<(), String> {
    let safe_room = sanitize_key(&session.room_id);
    let safe_session = sanitize_key(&session.session_id);
    let path = format!(
        "{}megolm_inbound/{}/{}.json",
        CRYPTO_PREFIX, safe_room, safe_session
    );
    let json = serde_json::to_string(session)
        .map_err(|e| format!("Failed to serialize inbound Megolm session: {}", e))?;
    channel_host::workspace_write(&path, &json)
}

/// Read an outbound Megolm session for a room.
pub fn read_outbound_megolm_session(
    room_id: &str,
) -> Option<StoredOutboundMegolmSession> {
    let safe_room = sanitize_key(room_id);
    let path = format!("{}megolm_outbound/{}.json", CRYPTO_PREFIX, safe_room);
    channel_host::workspace_read(&path)
        .and_then(|data| serde_json::from_str(&data).ok())
}

/// Write an outbound Megolm session for a room.
pub fn write_outbound_megolm_session(
    session: &StoredOutboundMegolmSession,
) -> Result<(), String> {
    let safe_room = sanitize_key(&session.room_id);
    let path = format!("{}megolm_outbound/{}.json", CRYPTO_PREFIX, safe_room);
    let json = serde_json::to_string(session)
        .map_err(|e| format!("Failed to serialize outbound Megolm session: {}", e))?;
    channel_host::workspace_write(&path, &json)
}

/// Sanitize a key for use as a filename.
///
/// Matrix identifiers contain characters like `!`, `:`, `@` that may not
/// be valid in file paths. Replace them with safe alternatives.
fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

/// Minimum one-time keys to keep uploaded. When the server count falls
/// below this, we generate and upload more. Set conservatively low to
/// avoid unnecessary uploads — each key is a Curve25519 scalar
/// multiplication in the WASM sandbox.
pub const OTK_MIN_COUNT: usize = 10;

/// Number of one-time keys to generate at a time.
///
/// Kept modest because each key requires a Curve25519 scalar
/// multiplication which is compute-heavy inside the WASM sandbox.
/// More keys are uploaded on subsequent polls when the server count
/// drops below `OTK_MIN_COUNT`.
pub const OTK_UPLOAD_BATCH: usize = 10;

/// Maximum messages before Megolm session rotation.
pub const MEGOLM_ROTATION_MESSAGE_COUNT: u32 = 100;

/// Maximum age before Megolm session rotation (1 week in milliseconds).
pub const MEGOLM_ROTATION_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Check if an outbound Megolm session needs rotation.
pub fn should_rotate_session(session: &StoredOutboundMegolmSession, now_ms: u64) -> bool {
    if session.message_count >= MEGOLM_ROTATION_MESSAGE_COUNT {
        return true;
    }
    if now_ms.saturating_sub(session.created_ts) >= MEGOLM_ROTATION_AGE_MS {
        return true;
    }
    false
}

// ==================== Host-side encryption helpers ====================
//
// Instead of the pickle key entering WASM memory, encryption/decryption is
// delegated to the host via `secure-encrypt` / `secure-decrypt` WIT functions.
// The host holds the key in its secrets store; WASM never sees it.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Encrypt a serde-serializable pickle via the host, returning a base64 string for storage.
pub fn host_encrypt_pickle<T: serde::Serialize>(pickle: &T) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(pickle).map_err(|e| format!("Failed to serialize pickle: {}", e))?;
    let encrypted = channel_host::secure_encrypt(&bytes)
        .map_err(|e| format!("Host encryption failed: {}", e))?;
    Ok(BASE64.encode(&encrypted))
}

/// Decrypt a base64 string via the host, deserializing into a pickle type.
pub fn host_decrypt_pickle<T: serde::de::DeserializeOwned>(stored: &str) -> Result<T, String> {
    let encrypted =
        BASE64.decode(stored).map_err(|e| format!("Invalid base64 in stored pickle: {}", e))?;
    let decrypted = channel_host::secure_decrypt(&encrypted)
        .map_err(|e| format!("Host decryption failed: {}", e))?;
    serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to deserialize pickle: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_key() {
        assert_eq!(sanitize_key("hello"), "hello");
        assert_eq!(sanitize_key("!room:example.com"), "_room_example.com");
        assert_eq!(sanitize_key("@user:matrix.org"), "_user_matrix.org");
        assert_eq!(
            sanitize_key("curve25519_key_abc123"),
            "curve25519_key_abc123"
        );
    }

    #[test]
    fn test_should_rotate_session_by_count() {
        let session = StoredOutboundMegolmSession {
            room_id: "!room:example.com".to_string(),
            session_id: "session1".to_string(),
            pickled_session: String::new(),
            message_count: 100,
            created_ts: 0,
        };
        assert!(should_rotate_session(&session, 1000));
    }

    #[test]
    fn test_should_rotate_session_by_age() {
        let session = StoredOutboundMegolmSession {
            room_id: "!room:example.com".to_string(),
            session_id: "session1".to_string(),
            pickled_session: String::new(),
            message_count: 1,
            created_ts: 0,
        };
        // More than 1 week old
        let now_ms = 8 * 24 * 60 * 60 * 1000;
        assert!(should_rotate_session(&session, now_ms));
    }

    #[test]
    fn test_should_not_rotate_fresh_session() {
        let session = StoredOutboundMegolmSession {
            room_id: "!room:example.com".to_string(),
            session_id: "session1".to_string(),
            pickled_session: String::new(),
            message_count: 5,
            created_ts: 1000,
        };
        assert!(!should_rotate_session(&session, 2000));
    }

    #[test]
    fn test_stored_account_roundtrip() {
        let account = StoredAccount {
            user_id: "@bot:example.com".to_string(),
            device_id: "ABCDEF".to_string(),
            pickled_account: "pickled_data".to_string(),
            ed25519_key: "ed25519_pub".to_string(),
            curve25519_key: "curve25519_pub".to_string(),
            keys_uploaded: true,
            uploaded_key_count: 50,
        };
        let json = serde_json::to_string(&account).unwrap();
        let parsed: StoredAccount = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.user_id, account.user_id);
        assert_eq!(parsed.device_id, account.device_id);
        assert!(parsed.keys_uploaded);
    }
}
