//! Matrix /sync long-polling and event processing.
//!
//! Handles the /sync loop, extracts incoming messages from timeline events,
//! and persists the `since` token between poll cycles.

use crate::channel_host;
use crate::client;
use crate::types::{
    JoinedRoom, MatrixMessageMetadata, MessageContent, RoomEvent, RoomFilter, StateFilter,
    SyncFilter, SyncResponse, TimelineFilter,
};

/// Workspace paths for persistent state.
const SINCE_TOKEN_PATH: &str = "state/since_token";
const HOMESERVER_URL_PATH: &str = "state/homeserver_url";
const USER_ID_PATH: &str = "state/user_id";
const ENCRYPTED_ROOMS_PATH: &str = "state/encrypted_rooms";

/// Read the stored since token.
pub fn read_since_token() -> Option<String> {
    channel_host::workspace_read(SINCE_TOKEN_PATH).filter(|s| !s.is_empty())
}

/// Write the since token.
pub fn write_since_token(token: &str) {
    if let Err(e) = channel_host::workspace_write(SINCE_TOKEN_PATH, token) {
        channel_host::log(
            channel_host::LogLevel::Error,
            &format!("Failed to save since token: {}", e),
        );
    }
}

/// Read the stored homeserver URL.
pub fn read_homeserver_url() -> Option<String> {
    channel_host::workspace_read(HOMESERVER_URL_PATH).filter(|s| !s.is_empty())
}

/// Write the homeserver URL.
pub fn write_homeserver_url(url: &str) {
    let _ = channel_host::workspace_write(HOMESERVER_URL_PATH, url);
}

/// Read the stored user ID (our bot's Matrix user ID).
pub fn read_user_id() -> Option<String> {
    channel_host::workspace_read(USER_ID_PATH).filter(|s| !s.is_empty())
}

/// Write our user ID.
pub fn write_user_id(user_id: &str) {
    let _ = channel_host::workspace_write(USER_ID_PATH, user_id);
}

/// Read the set of encrypted room IDs (stored as JSON array).
pub fn read_encrypted_rooms() -> Vec<String> {
    channel_host::workspace_read(ENCRYPTED_ROOMS_PATH)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Add a room ID to the encrypted rooms set.
pub fn mark_room_encrypted(room_id: &str) {
    let mut rooms = read_encrypted_rooms();
    if !rooms.contains(&room_id.to_string()) {
        rooms.push(room_id.to_string());
        let json = serde_json::to_string(&rooms).unwrap_or_else(|_| "[]".to_string());
        let _ = channel_host::workspace_write(ENCRYPTED_ROOMS_PATH, &json);
    }
}

/// Check if a room is known to have encryption enabled.
pub fn is_room_encrypted(room_id: &str) -> bool {
    read_encrypted_rooms().contains(&room_id.to_string())
}

/// Build a default sync filter that only fetches message-related events.
pub fn default_sync_filter() -> SyncFilter {
    SyncFilter {
        room: RoomFilter {
            timeline: TimelineFilter {
                types: vec![
                    "m.room.message".to_string(),
                    "m.room.encrypted".to_string(),
                ],
                limit: 50,
            },
            state: StateFilter {
                types: vec![
                    "m.room.encryption".to_string(),
                    "m.room.member".to_string(),
                ],
            },
        },
    }
}

/// Perform a single /sync poll and return any new message events.
///
/// Returns a list of (room_id, event) tuples for message events that
/// should be forwarded to the agent.
pub fn poll_sync(
    homeserver_url: &str,
    timeout_ms: u32,
    our_user_id: &str,
    e2ee_enabled: bool,
) -> (Vec<(String, RoomEvent)>, crate::crypto::MegolmSessionCache) {
    let since = read_since_token();
    let filter = default_sync_filter();

    let response = match client::sync(
        homeserver_url,
        since.as_deref(),
        timeout_ms,
        Some(&filter),
    ) {
        Ok(result) => result,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Sync failed: {}", e),
            );
            return (Vec::new(), crate::crypto::MegolmSessionCache::new());
        }
    };

    write_since_token(&response.next_batch);
    handle_invites(homeserver_url, &response);

    // Process to-device events (for E2EE key delivery) regardless of
    // whether this is an initial sync, since room keys need to be stored.
    // Returns a cache of newly-received inbound Megolm sessions so that
    // try_decrypt_event can find them before buffered workspace writes commit.
    let session_cache = if e2ee_enabled {
        if let Some(ref td) = response.to_device {
            if !td.events.is_empty() {
                crate::crypto::handle_to_device_events(&td.events)
            } else {
                crate::crypto::MegolmSessionCache::new()
            }
        } else {
            crate::crypto::MegolmSessionCache::new()
        }
    } else {
        crate::crypto::MegolmSessionCache::new()
    };

    if since.is_none() {
        channel_host::log(
            channel_host::LogLevel::Info,
            "Initial sync complete, skipping historical events",
        );
        return (Vec::new(), session_cache);
    }

    (
        extract_message_events(&response, our_user_id, e2ee_enabled),
        session_cache,
    )
}

/// Auto-join rooms the bot has been invited to.
///
/// Iterates over `rooms.invite` in the sync response and calls the /join
/// endpoint for each room. Failures are logged but do not interrupt processing.
fn handle_invites(homeserver_url: &str, response: &SyncResponse) {
    let invite_rooms = match response.rooms.as_ref().and_then(|r| r.invite.as_ref()) {
        Some(inv) if !inv.is_empty() => inv,
        _ => return,
    };

    for room_id in invite_rooms.keys() {
        channel_host::log(
            channel_host::LogLevel::Info,
            &format!("Received invite for room {}, joining", room_id),
        );
        match client::join_room(homeserver_url, room_id) {
            Ok(joined_room_id) => {
                channel_host::log(
                    channel_host::LogLevel::Info,
                    &format!("Joined room {}", joined_room_id),
                );
            }
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("Failed to join room {}: {}", room_id, e),
                );
            }
        }
    }
}

/// Extract message events from a sync response.
///
/// Filters out our own messages and processes state events for encryption status.
fn extract_message_events(
    response: &SyncResponse,
    our_user_id: &str,
    e2ee_enabled: bool,
) -> Vec<(String, RoomEvent)> {
    let mut messages = Vec::new();

    let rooms = match response.rooms.as_ref().and_then(|r| r.join.as_ref()) {
        Some(join) => join,
        None => return messages,
    };

    for (room_id, room) in rooms {
        process_state_events(room_id, room);

        let events = match room.timeline.as_ref() {
            Some(timeline) => &timeline.events,
            None => continue,
        };

        for event in events {
            // Skip our own messages to prevent echo loops
            if event.sender.as_deref() == Some(our_user_id) {
                continue;
            }

            match event.event_type.as_str() {
                "m.room.message" => {
                    match serde_json::from_value::<MessageContent>(event.content.clone()) {
                        Ok(content) => {
                            if content.msgtype.as_deref() == Some("m.text")
                                && content.body.is_some()
                            {
                                messages.push((room_id.clone(), event.clone()));
                            }
                        }
                        Err(e) => {
                            channel_host::log(
                                channel_host::LogLevel::Warn,
                                &format!("Failed to parse m.room.message content: {}", e),
                            );
                        }
                    }
                }
                "m.room.encrypted" => {
                    if e2ee_enabled {
                        messages.push((room_id.clone(), event.clone()));
                    }
                }
                _ => {}
            }
        }
    }

    messages
}

/// Process state events from a room to track encryption status.
fn process_state_events(room_id: &str, room: &JoinedRoom) {
    let state = match room.state.as_ref() {
        Some(s) => s,
        None => return,
    };

    for event in &state.events {
        if event.event_type == "m.room.encryption" {
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!("Room {} has encryption enabled", room_id),
            );
            mark_room_encrypted(room_id);
        }
    }

    // Also check timeline for encryption state events
    if let Some(ref timeline) = room.timeline {
        for event in &timeline.events {
            if event.event_type == "m.room.encryption" {
                channel_host::log(
                    channel_host::LogLevel::Info,
                    &format!("Room {} enabled encryption", room_id),
                );
                mark_room_encrypted(room_id);
            }
        }
    }
}

/// Parse a message event into components suitable for emitting to the agent.
///
/// Returns (sender, body, event_id) or None if the event cannot be parsed.
pub fn parse_message_event(event: &RoomEvent) -> Option<(String, String, String)> {
    let sender = event.sender.as_ref()?;
    let event_id = event.event_id.as_ref()?;

    match event.event_type.as_str() {
        "m.room.message" => {
            let content: MessageContent =
                serde_json::from_value(event.content.clone()).ok()?;
            let body = content.body?;
            Some((sender.clone(), body, event_id.clone()))
        }
        "m.room.encrypted" => {
            // Encrypted events are handled by the crypto layer in
            // process_incoming_event, not here.
            None
        }
        _ => None,
    }
}

/// Build metadata for an incoming message to enable response routing.
pub fn build_message_metadata(
    room_id: &str,
    event_id: &str,
    sender: &str,
    encrypted: bool,
) -> String {
    let metadata = MatrixMessageMetadata {
        room_id: room_id.to_string(),
        event_id: event_id.to_string(),
        sender: sender.to_string(),
        encrypted,
    };

    serde_json::to_string(&metadata).unwrap_or_else(|e| {
        channel_host::log(
            channel_host::LogLevel::Error,
            &format!("Failed to serialize metadata: {}", e),
        );
        "{}".to_string()
    })
}

/// Validate a Matrix user ID format (@localpart:domain).
pub fn is_valid_user_id(user_id: &str) -> bool {
    if !user_id.starts_with('@') {
        return false;
    }
    let rest = &user_id[1..];
    let colon_pos = match rest.find(':') {
        Some(pos) => pos,
        None => return false,
    };
    // Must have a localpart before the colon and a domain after
    colon_pos > 0 && colon_pos < rest.len() - 1
}

/// Validate a Matrix room ID format (!localpart:domain).
pub fn is_valid_room_id(room_id: &str) -> bool {
    // Room IDs must start with '!' and have at least one character after it.
    // We do not enforce ':server' — some homeservers use opaque v2 IDs
    // without a colon, and the homeserver is authoritative on format.
    room_id.starts_with('!') && room_id.len() > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_user_id() {
        assert!(is_valid_user_id("@alice:example.com"));
        assert!(is_valid_user_id("@bot:matrix.org"));
        assert!(!is_valid_user_id("alice:example.com")); // missing @
        assert!(!is_valid_user_id("@alice")); // missing domain
        assert!(!is_valid_user_id("@:example.com")); // empty localpart
        assert!(!is_valid_user_id("@alice:")); // empty domain
    }

    #[test]
    fn test_is_valid_room_id() {
        assert!(is_valid_room_id("!room123:example.com"));
        assert!(is_valid_room_id("!abc:matrix.org"));
        // Opaque v2 room IDs (no colon) are valid
        assert!(is_valid_room_id(
            "!ePIvvZfTk6aEXG-LDlA1bSU_-ClVbVEaDs7ykXqZhhs"
        ));
        assert!(is_valid_room_id("!room")); // minimal valid
        assert!(!is_valid_room_id("room:example.com")); // missing !
        assert!(!is_valid_room_id("!")); // just sigil, no content
        assert!(!is_valid_room_id("")); // empty
    }

    #[test]
    fn test_parse_message_event_text() {
        let event = RoomEvent {
            event_type: "m.room.message".to_string(),
            event_id: Some("$evt1".to_string()),
            sender: Some("@alice:example.com".to_string()),
            origin_server_ts: Some(1000),
            content: serde_json::json!({
                "msgtype": "m.text",
                "body": "Hello!"
            }),
            state_key: None,
        };

        let result = parse_message_event(&event);
        assert!(result.is_some());
        let (sender, body, event_id) = result.unwrap();
        assert_eq!(sender, "@alice:example.com");
        assert_eq!(body, "Hello!");
        assert_eq!(event_id, "$evt1");
    }

    #[test]
    fn test_parse_message_event_image_ignored() {
        let event = RoomEvent {
            event_type: "m.room.message".to_string(),
            event_id: Some("$evt2".to_string()),
            sender: Some("@alice:example.com".to_string()),
            origin_server_ts: Some(1000),
            content: serde_json::json!({
                "msgtype": "m.image",
                "body": "photo.jpg"
            }),
            state_key: None,
        };

        // m.image is not m.text, so it should be None
        let result = parse_message_event(&event);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_message_event_missing_sender() {
        let event = RoomEvent {
            event_type: "m.room.message".to_string(),
            event_id: Some("$evt3".to_string()),
            sender: None,
            origin_server_ts: None,
            content: serde_json::json!({"msgtype": "m.text", "body": "hi"}),
            state_key: None,
        };

        assert!(parse_message_event(&event).is_none());
    }

    #[test]
    fn test_build_message_metadata() {
        let json = build_message_metadata(
            "!room:example.com",
            "$evt1",
            "@alice:example.com",
            false,
        );
        let meta: MatrixMessageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta.room_id, "!room:example.com");
        assert_eq!(meta.event_id, "$evt1");
        assert!(!meta.encrypted);
    }
}
