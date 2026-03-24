//! Matrix event types for parsing /sync responses and constructing requests.
//!
//! Hand-written serde types rather than depending on `ruma-events` to avoid
//! potential `wasm32-wasip2` compilation issues. Covers the subset of the
//! Matrix Client-Server API that IronClaw needs.

use serde::{Deserialize, Serialize};

// ============================================================================
// Sync Response Types
// ============================================================================

/// Top-level /sync response.
#[derive(Debug, Deserialize)]
pub struct SyncResponse {
    /// Token for the next /sync call.
    pub next_batch: String,

    /// Room-related events.
    #[serde(default)]
    pub rooms: Option<SyncRooms>,

    /// To-device events (used for E2EE key delivery).
    #[serde(default)]
    pub to_device: Option<ToDeviceEvents>,
}

/// Container for to-device events in a /sync response.
#[derive(Debug, Deserialize)]
pub struct ToDeviceEvents {
    /// List of to-device events.
    #[serde(default)]
    pub events: Vec<ToDeviceEvent>,
}

/// A to-device event from /sync.
#[derive(Debug, Clone, Deserialize)]
pub struct ToDeviceEvent {
    /// Event type (e.g., "m.room.encrypted", "m.room_key").
    #[serde(rename = "type")]
    pub event_type: String,

    /// Sender user ID.
    #[allow(dead_code)]
    #[serde(default)]
    pub sender: Option<String>,

    /// Event content.
    #[serde(default)]
    pub content: serde_json::Value,
}

/// Room categories in a /sync response.
#[derive(Debug, Deserialize)]
pub struct SyncRooms {
    /// Joined rooms with new events.
    #[serde(default)]
    pub join: Option<std::collections::HashMap<String, JoinedRoom>>,

    /// Rooms the user has been invited to.
    #[serde(default)]
    pub invite: Option<std::collections::HashMap<String, serde_json::Value>>,
}

/// A joined room in the /sync response.
#[derive(Debug, Deserialize)]
pub struct JoinedRoom {
    /// Timeline events (messages, state changes).
    #[serde(default)]
    pub timeline: Option<Timeline>,

    /// State events (room name, membership, encryption).
    #[serde(default)]
    pub state: Option<StateEvents>,
}

/// Timeline within a joined room.
#[derive(Debug, Deserialize)]
pub struct Timeline {
    /// List of events.
    #[serde(default)]
    pub events: Vec<RoomEvent>,
}

/// State events within a joined room.
#[derive(Debug, Deserialize)]
pub struct StateEvents {
    /// List of state events.
    #[serde(default)]
    pub events: Vec<RoomEvent>,
}

/// A room event (timeline or state).
#[derive(Debug, Clone, Deserialize)]
pub struct RoomEvent {
    /// Event type (e.g., "m.room.message", "m.room.encrypted").
    #[serde(rename = "type")]
    pub event_type: String,

    /// Event ID.
    #[serde(default)]
    pub event_id: Option<String>,

    /// Sender user ID.
    #[serde(default)]
    pub sender: Option<String>,

    /// Server timestamp in milliseconds.
    #[allow(dead_code)]
    #[serde(default)]
    pub origin_server_ts: Option<u64>,

    /// Event content (varies by event type).
    #[serde(default)]
    pub content: serde_json::Value,

    /// State key (for state events).
    #[allow(dead_code)]
    #[serde(default)]
    pub state_key: Option<String>,
}

// ============================================================================
// Message Content Types
// ============================================================================

/// Content of an m.room.message event.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageContent {
    /// Message type: "m.text", "m.image", "m.file", etc.
    #[serde(default)]
    pub msgtype: Option<String>,

    /// Plain text body.
    #[serde(default)]
    pub body: Option<String>,

    /// Formatted body (HTML).
    #[allow(dead_code)]
    #[serde(default)]
    pub formatted_body: Option<String>,

    /// Format of formatted_body (e.g., "org.matrix.custom.html").
    #[allow(dead_code)]
    #[serde(default)]
    pub format: Option<String>,
}

/// Content of an m.room.encrypted event.
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptedContent {
    /// Encryption algorithm (e.g., "m.megolm.v1.aes-sha2").
    pub algorithm: String,

    /// Sender's Curve25519 key.
    #[serde(default)]
    pub sender_key: Option<String>,

    /// Megolm session ID.
    #[serde(default)]
    pub session_id: Option<String>,

    /// Device ID of the sender.
    #[allow(dead_code)]
    #[serde(default)]
    pub device_id: Option<String>,

    /// Ciphertext (format depends on algorithm).
    #[serde(default)]
    pub ciphertext: Option<String>,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response from GET /_matrix/client/v3/account/whoami.
#[derive(Debug, Deserialize)]
pub struct WhoamiResponse {
    pub user_id: String,
    pub device_id: Option<String>,
}

/// Response from PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}.
#[derive(Debug, Deserialize)]
pub struct SendEventResponse {
    #[allow(dead_code)]
    pub event_id: String,
}

/// Body for sending an m.room.message event.
#[derive(Debug, Serialize)]
pub struct TextMessageBody {
    pub msgtype: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<String>,
}

/// Sync filter to reduce response size.
#[derive(Debug, Serialize)]
pub struct SyncFilter {
    pub room: RoomFilter,
}

/// Room filter for /sync.
#[derive(Debug, Serialize)]
pub struct RoomFilter {
    pub timeline: TimelineFilter,
    pub state: StateFilter,
}

/// Timeline filter.
#[derive(Debug, Serialize)]
pub struct TimelineFilter {
    /// Event types to include.
    pub types: Vec<String>,
    /// Maximum number of events to return.
    pub limit: u32,
}

/// State filter.
#[derive(Debug, Serialize)]
pub struct StateFilter {
    /// Event types to include.
    pub types: Vec<String>,
}

// ============================================================================
// E2EE Key Types
// ============================================================================

/// Request body for POST /_matrix/client/v3/keys/upload.
#[derive(Debug, Serialize)]
pub struct KeysUploadRequest {
    /// Device keys (identity keys + signatures).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_keys: Option<DeviceKeys>,

    /// One-time keys for Olm session establishment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_keys: Option<std::collections::HashMap<String, serde_json::Value>>,
}

/// Device keys for /keys/upload.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceKeys {
    /// User ID of the device owner.
    pub user_id: String,

    /// Device ID.
    pub device_id: String,

    /// Supported algorithms.
    pub algorithms: Vec<String>,

    /// Identity keys: {"curve25519:<device_id>": "<key>", "ed25519:<device_id>": "<key>"}.
    pub keys: std::collections::HashMap<String, String>,

    /// Signatures: {user_id: {key_id: signature}}.
    pub signatures: std::collections::HashMap<String, std::collections::HashMap<String, String>>,
}

/// Response from POST /_matrix/client/v3/keys/upload.
#[derive(Debug, Deserialize)]
pub struct KeysUploadResponse {
    /// Count of one-time keys by algorithm.
    pub one_time_key_counts: std::collections::HashMap<String, u32>,
}

/// Response from POST /_matrix/client/v3/keys/query.
#[derive(Debug, Deserialize)]
pub struct KeysQueryResponse {
    /// Device keys: {user_id: {device_id: DeviceKeys}}.
    #[serde(default)]
    pub device_keys: std::collections::HashMap<
        String,
        std::collections::HashMap<String, DeviceKeys>,
    >,
}

/// Response from POST /_matrix/client/v3/keys/claim.
#[derive(Debug, Deserialize)]
pub struct KeysClaimResponse {
    /// Claimed one-time keys: {user_id: {device_id: {key_id: key}}}.
    #[serde(default)]
    pub one_time_keys: std::collections::HashMap<
        String,
        std::collections::HashMap<String, serde_json::Value>,
    >,
}

/// Metadata stored with emitted messages for response routing.
#[derive(Debug, Serialize, Deserialize)]
pub struct MatrixMessageMetadata {
    /// Room ID where the message was received.
    pub room_id: String,

    /// Event ID of the original message.
    pub event_id: String,

    /// Sender user ID.
    pub sender: String,

    /// Whether the room has encryption enabled.
    #[serde(default)]
    pub encrypted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sync_response_minimal() {
        let json = r#"{"next_batch": "s123_456"}"#;
        let resp: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.next_batch, "s123_456");
        assert!(resp.rooms.is_none());
    }

    #[test]
    fn test_parse_room_message_event() {
        let json = r#"{
            "type": "m.room.message",
            "event_id": "$evt1",
            "sender": "@alice:example.com",
            "origin_server_ts": 1234567890,
            "content": {
                "msgtype": "m.text",
                "body": "Hello, world!"
            }
        }"#;
        let event: RoomEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "m.room.message");
        assert_eq!(event.sender.as_deref(), Some("@alice:example.com"));

        let content: MessageContent = serde_json::from_value(event.content).unwrap();
        assert_eq!(content.msgtype.as_deref(), Some("m.text"));
        assert_eq!(content.body.as_deref(), Some("Hello, world!"));
    }

    #[test]
    fn test_parse_encrypted_event() {
        let json = r#"{
            "type": "m.room.encrypted",
            "event_id": "$evt2",
            "sender": "@bob:example.com",
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": "curve25519key",
                "session_id": "session123",
                "ciphertext": "encrypted_data_here"
            }
        }"#;
        let event: RoomEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "m.room.encrypted");

        let content: EncryptedContent = serde_json::from_value(event.content).unwrap();
        assert_eq!(content.algorithm, "m.megolm.v1.aes-sha2");
        assert_eq!(content.session_id.as_deref(), Some("session123"));
    }

    #[test]
    fn test_text_message_body_serialization() {
        let body = TextMessageBody {
            msgtype: "m.text".to_string(),
            body: "Hello".to_string(),
            format: None,
            formatted_body: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("format"));
        assert!(!json.contains("formatted_body"));
    }

    #[test]
    fn test_text_message_body_with_html() {
        let body = TextMessageBody {
            msgtype: "m.text".to_string(),
            body: "Hello **world**".to_string(),
            format: Some("org.matrix.custom.html".to_string()),
            formatted_body: Some("Hello <b>world</b>".to_string()),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("org.matrix.custom.html"));
        assert!(json.contains("Hello <b>world</b>"));
    }

    #[test]
    fn test_metadata_roundtrip() {
        let meta = MatrixMessageMetadata {
            room_id: "!room:example.com".to_string(),
            event_id: "$evt123".to_string(),
            sender: "@alice:example.com".to_string(),
            encrypted: true,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: MatrixMessageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.room_id, meta.room_id);
        assert_eq!(parsed.event_id, meta.event_id);
        assert!(parsed.encrypted);
    }

    #[test]
    fn test_parse_sync_with_rooms() {
        let json = r#"{
            "next_batch": "s200",
            "rooms": {
                "join": {
                    "!room1:example.com": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.room.message",
                                    "event_id": "$msg1",
                                    "sender": "@user:example.com",
                                    "origin_server_ts": 1000000,
                                    "content": {
                                        "msgtype": "m.text",
                                        "body": "test message"
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }"#;
        let resp: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.next_batch, "s200");
        let rooms = resp.rooms.unwrap();
        let join = rooms.join.unwrap();
        assert!(join.contains_key("!room1:example.com"));
        let room = &join["!room1:example.com"];
        let events = &room.timeline.as_ref().unwrap().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "m.room.message");
    }

    #[test]
    fn test_parse_whoami_response() {
        let json = r#"{"user_id": "@bot:example.com", "device_id": "ABCDEF"}"#;
        let resp: WhoamiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.user_id, "@bot:example.com");
        assert_eq!(resp.device_id.as_deref(), Some("ABCDEF"));
    }

}
