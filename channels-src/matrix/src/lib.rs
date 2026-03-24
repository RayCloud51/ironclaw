//! Matrix messaging channel for IronClaw with E2EE support.
//!
//! This WASM component implements the channel interface for communicating
//! with Matrix homeservers via the Client-Server API. It supports:
//!
//! - Long-polling via /sync for incoming messages
//! - Plaintext message send/receive
//! - E2EE via Olm/Megolm (when enabled and vodozemac is compiled in)
//! - DM pairing, allowlist, and open access policies
//!
//! # Security
//!
//! - Access token is injected by the host at the HTTP boundary
//! - WASM code never sees raw credentials
//! - E2EE private keys are pickled with an encryption key from secrets
//! - All workspace writes are namespaced under `channels/matrix/`

// Generate bindings from the WIT file
wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "../../wit/channel.wit",
});

// Re-export generated types
use exports::near::agent::channel::{
    AgentResponse, ChannelConfig, Guest, HttpEndpointConfig, IncomingHttpRequest,
    OutgoingHttpResponse, PollConfig, StatusUpdate,
};
use near::agent::channel_host::{self, EmittedMessage};

mod client;
mod config;
mod crypto;
mod crypto_store;
mod sync;
mod types;

use crate::config::MatrixConfig;
use crate::types::MatrixMessageMetadata;

// ============================================================================
// Constants
// ============================================================================

/// Channel name for pairing store.
const CHANNEL_NAME: &str = "matrix";

/// Workspace paths for persistent state.
const DM_POLICY_PATH: &str = "state/dm_policy";
const ALLOW_FROM_PATH: &str = "state/allow_from";
const ALLOWED_ROOM_IDS_PATH: &str = "state/allowed_room_ids";
const RESPOND_ALL_PATH: &str = "state/respond_to_all_room_messages";
const E2EE_ENABLED_PATH: &str = "state/e2ee_enabled";
const SYNC_TIMEOUT_PATH: &str = "state/sync_timeout_ms";

// ============================================================================
// Channel Implementation
// ============================================================================

struct MatrixChannel;

impl Guest for MatrixChannel {
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        let mut config: MatrixConfig = serde_json::from_str(&config_json)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        channel_host::log(channel_host::LogLevel::Info, "Matrix channel starting");

        // Fall back to workspace storage if config fields are empty.
        // This handles the case where values were stored during a previous
        // on_start but the host didn't inject them from secrets this time.
        if config.homeserver_url.is_empty() {
            if let Some(url) = channel_host::workspace_read("state/homeserver_url") {
                if !url.is_empty() {
                    channel_host::log(
                        channel_host::LogLevel::Debug,
                        "Loaded homeserver_url from workspace storage",
                    );
                    config.homeserver_url = url;
                }
            }
        }
        if config.user_id.is_none() || config.user_id.as_deref() == Some("") {
            if let Some(uid) = channel_host::workspace_read("state/user_id") {
                if !uid.is_empty() {
                    config.user_id = Some(uid);
                }
            }
        }

        if config.homeserver_url.is_empty() {
            return Err(
                "homeserver_url is required. Set it in the config section of \
                 matrix.capabilities.json or run 'ironclaw onboard' to configure it."
                    .to_string(),
            );
        }

        // Persist homeserver URL for use in on_poll and on_respond
        sync::write_homeserver_url(&config.homeserver_url);

        // Auto-detect user ID if not configured
        let user_id = match config.user_id {
            Some(ref id) if !id.is_empty() => {
                channel_host::log(
                    channel_host::LogLevel::Info,
                    &format!("Using configured user ID: {}", id),
                );
                id.clone()
            }
            _ => {
                channel_host::log(
                    channel_host::LogLevel::Info,
                    "Auto-detecting user ID via /whoami",
                );
                let whoami = client::whoami(&config.homeserver_url)
                    .map_err(|e| format!("Failed to detect user ID: {}", e))?;
                channel_host::log(
                    channel_host::LogLevel::Info,
                    &format!("Detected user ID: {}", whoami.user_id),
                );
                whoami.user_id
            }
        };

        sync::write_user_id(&user_id);

        // Persist DM policy and allow_from
        let _ = channel_host::workspace_write(DM_POLICY_PATH, &config.dm_policy);

        let allow_from_json = serde_json::to_string(&config.allow_from)
            .unwrap_or_else(|_| "[]".to_string());
        let _ = channel_host::workspace_write(ALLOW_FROM_PATH, &allow_from_json);

        // Persist room settings
        let allowed_rooms_json = serde_json::to_string(&config.allowed_room_ids)
            .unwrap_or_else(|_| "[]".to_string());
        let _ = channel_host::workspace_write(ALLOWED_ROOM_IDS_PATH, &allowed_rooms_json);
        let _ = channel_host::workspace_write(
            RESPOND_ALL_PATH,
            &config.respond_to_all_room_messages.to_string(),
        );

        // Persist E2EE setting and sync timeout for on_poll
        let _ = channel_host::workspace_write(E2EE_ENABLED_PATH, &config.enable_e2ee.to_string());
        let _ = channel_host::workspace_write(SYNC_TIMEOUT_PATH, &config.sync_timeout_ms.to_string());

        // Initialize E2EE if enabled
        if config.enable_e2ee {
            let device_id = config.device_id.unwrap_or_else(|| {
                format!("IRONCLAW_{}", channel_host::now_millis())
            });
            if let Err(e) = crypto::init_crypto(&config.homeserver_url, &user_id, &device_id) {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("E2EE initialization failed: {}", e),
                );
                // Don't fail startup — fall back to plaintext
                let _ = channel_host::workspace_write(E2EE_ENABLED_PATH, "false");
            }
        }

        Ok(ChannelConfig {
            display_name: "Matrix".to_string(),
            http_endpoints: vec![HttpEndpointConfig {
                path: "/webhook/matrix".to_string(),
                methods: vec!["POST".to_string()],
                require_secret: false,
            }],
            poll: Some(PollConfig {
                interval_ms: config.sync_timeout_ms.max(30_000),
                enabled: true,
            }),
        })
    }

    fn on_http_request(_req: IncomingHttpRequest) -> OutgoingHttpResponse {
        // Matrix uses /sync polling; HTTP endpoint exists for health checks.
        json_response(200, serde_json::json!({"ok": true}))
    }

    fn on_poll() {
        let homeserver_url = match sync::read_homeserver_url() {
            Some(url) => url,
            None => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    "No homeserver URL configured",
                );
                return;
            }
        };

        let our_user_id = match sync::read_user_id() {
            Some(id) => id,
            None => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    "No user ID configured",
                );
                return;
            }
        };

        let e2ee_enabled = channel_host::workspace_read(E2EE_ENABLED_PATH)
            .map(|s| s == "true")
            .unwrap_or(false);

        // Read sync timeout from workspace (written by on_start), default 30s
        let timeout_ms: u32 = channel_host::workspace_read(SYNC_TIMEOUT_PATH)
            .and_then(|s| s.parse().ok())
            .unwrap_or(30_000);

        let (events, mut session_cache) =
            sync::poll_sync(&homeserver_url, timeout_ms, &our_user_id, e2ee_enabled);

        for (room_id, event) in events {
            process_incoming_event(
                &room_id,
                &event,
                &our_user_id,
                e2ee_enabled,
                &mut session_cache,
            );
        }
    }

    fn on_respond(response: AgentResponse) -> Result<(), String> {
        let metadata: MatrixMessageMetadata = serde_json::from_str(&response.metadata_json)
            .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        let homeserver_url = sync::read_homeserver_url()
            .ok_or("No homeserver URL configured")?;

        send_response_to_room(&homeserver_url, &metadata, &response.content)
    }

    fn on_status(_update: StatusUpdate) {
        // Matrix doesn't have a native typing indicator API that's useful
        // in this context (it requires continuous pinging). Skip for now.
    }

    fn on_broadcast(user_id: String, response: AgentResponse) -> Result<(), String> {
        // For Matrix, user_id in broadcast context is actually a room_id
        let homeserver_url = sync::read_homeserver_url()
            .ok_or("No homeserver URL configured")?;

        let room_id = user_id;

        let e2ee_enabled = channel_host::workspace_read(E2EE_ENABLED_PATH)
            .map(|s| s == "true")
            .unwrap_or(false);
        let room_encrypted = e2ee_enabled && sync::is_room_encrypted(&room_id);

        let chunks = client::split_message(&response.content);
        for chunk in chunks {
            if room_encrypted {
                let encrypted = crypto::encrypt_message(&homeserver_url, &room_id, &chunk)
                    .map_err(|e| format!("Broadcast encryption failed for {}: {}", room_id, e))?;
                let body = serde_json::to_vec(&encrypted)
                    .map_err(|e| format!("Failed to serialize encrypted broadcast: {}", e))?;
                let txn_id = client::generate_txn_id();
                client::send_message_event(&homeserver_url, &room_id, "m.room.encrypted", &txn_id, &body)?;
            } else {
                let txn_id = client::generate_txn_id();
                client::send_text_message(&homeserver_url, &room_id, &txn_id, &chunk)
                    .map_err(|e| format!("Failed to broadcast to {}: {}", room_id, e))?;
            }
        }

        Ok(())
    }

    fn on_shutdown() {
        channel_host::log(channel_host::LogLevel::Info, "Matrix channel shutting down");
    }
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process an incoming event from /sync.
fn process_incoming_event(
    room_id: &str,
    event: &types::RoomEvent,
    _our_user_id: &str,
    e2ee_enabled: bool,
    session_cache: &mut crypto::MegolmSessionCache,
) {
    if !sync::is_valid_room_id(room_id) {
        channel_host::log(
            channel_host::LogLevel::Warn,
            &format!("Rejected: invalid room ID format: {}", room_id),
        );
        return;
    }

    if !is_room_allowed(room_id) {
        return;
    }

    // Handle encrypted events
    if event.event_type == "m.room.encrypted" {
        if !e2ee_enabled {
            return;
        }

        match crypto::try_decrypt_event(room_id, event, session_cache) {
            Ok(plaintext) => {
                let sender = event.sender.as_deref().unwrap_or("");
                let event_id = event.event_id.as_deref().unwrap_or("");

                if !check_sender_permission(sender, room_id) {
                    return;
                }

                emit_agent_message(room_id, event_id, sender, &plaintext, true);
            }
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    &format!("Failed to decrypt event in {}: {}", room_id, e),
                );
            }
        }
        return;
    }

    // Handle plaintext message events
    if let Some((sender, body, event_id)) = sync::parse_message_event(event) {
        if !sync::is_valid_user_id(&sender) {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("Rejected: invalid sender user ID: {}", sender),
            );
            return;
        }

        if !check_sender_permission(&sender, room_id) {
            return;
        }

        let is_encrypted = sync::is_room_encrypted(room_id);
        channel_host::log(
            channel_host::LogLevel::Info,
            &format!(
                "Emitting message from {} in {} (encrypted={})",
                sender, room_id, is_encrypted
            ),
        );
        emit_agent_message(room_id, &event_id, &sender, &body, is_encrypted);
    }
}

/// Emit a message to the IronClaw agent.
fn emit_agent_message(
    room_id: &str,
    event_id: &str,
    sender: &str,
    body: &str,
    encrypted: bool,
) {
    let metadata_json = sync::build_message_metadata(room_id, event_id, sender, encrypted);

    // Extract display name from user ID (localpart before the colon)
    let user_name = extract_display_name(sender);

    channel_host::emit_message(&EmittedMessage {
        user_id: sender.to_string(),
        user_name: Some(user_name),
        content: body.to_string(),
        thread_id: None,
        metadata_json,
        attachments: Vec::new(),
    });
}

/// Extract a display name from a Matrix user ID.
///
/// "@alice:example.com" -> "alice"
fn extract_display_name(user_id: &str) -> String {
    let without_sigil = user_id.strip_prefix('@').unwrap_or(user_id);
    match without_sigil.find(':') {
        Some(pos) => without_sigil[..pos].to_string(),
        None => without_sigil.to_string(),
    }
}

// ============================================================================
// Permission & Pairing
// ============================================================================

/// Check if a sender is permitted. Returns true if allowed.
/// For pairing mode, sends a pairing code message if denied.
fn check_sender_permission(sender: &str, room_id: &str) -> bool {
    let dm_policy =
        channel_host::workspace_read(DM_POLICY_PATH).unwrap_or_else(|| "pairing".to_string());

    // "open" mode allows everything
    if dm_policy == "open" {
        return true;
    }

    // Check respond_to_all_room_messages flag
    let respond_all = channel_host::workspace_read(RESPOND_ALL_PATH)
        .map(|s| s == "true")
        .unwrap_or(false);

    if respond_all {
        return true;
    }

    // Build merged allow list: config allow_from + pairing store
    let mut allowed: Vec<String> = channel_host::workspace_read(ALLOW_FROM_PATH)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if let Ok(store_allowed) = channel_host::pairing_read_allow_from(CHANNEL_NAME) {
        allowed.extend(store_allowed);
    }

    // Check if sender is in the allowlist (by user ID or wildcard)
    let is_allowed =
        allowed.contains(&"*".to_string()) || allowed.contains(&sender.to_string());

    if is_allowed {
        return true;
    }

    // Check via pairing host function
    match channel_host::pairing_is_allowed(CHANNEL_NAME, sender, None) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Pairing check failed: {}", e),
            );
        }
    }

    // Not allowed — handle by policy
    if dm_policy == "pairing" {
        let meta = serde_json::json!({
            "user_id": sender,
            "room_id": room_id,
        })
        .to_string();

        match channel_host::pairing_upsert_request(CHANNEL_NAME, sender, &meta) {
            Ok(result) => {
                channel_host::log(
                    channel_host::LogLevel::Info,
                    &format!("Pairing request for {}: code {}", sender, result.code),
                );
                if result.created {
                    send_pairing_reply(room_id, &result.code);
                }
            }
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("Pairing upsert failed: {}", e),
                );
            }
        }
    }

    false
}

/// Send a pairing code message to a room.
fn send_pairing_reply(room_id: &str, code: &str) {
    let homeserver_url = match sync::read_homeserver_url() {
        Some(url) => url,
        None => return,
    };

    let text = format!(
        "To pair with this bot, run: `ironclaw pairing approve matrix {}`",
        code
    );

    let txn_id = client::generate_txn_id();
    if let Err(e) = client::send_text_message(&homeserver_url, room_id, &txn_id, &text) {
        channel_host::log(
            channel_host::LogLevel::Error,
            &format!("Failed to send pairing reply: {}", e),
        );
    }
}

/// Check if a room is in the allowed rooms list.
///
/// If the allowed list is empty, all rooms are allowed.
fn is_room_allowed(room_id: &str) -> bool {
    let allowed_rooms: Vec<String> = channel_host::workspace_read(ALLOWED_ROOM_IDS_PATH)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if allowed_rooms.is_empty() {
        return true;
    }

    allowed_rooms.contains(&room_id.to_string())
}

// ============================================================================
// Response Sending
// ============================================================================

/// Send a response message to a Matrix room.
fn send_response_to_room(
    homeserver_url: &str,
    metadata: &MatrixMessageMetadata,
    content: &str,
) -> Result<(), String> {
    let e2ee_enabled = channel_host::workspace_read(E2EE_ENABLED_PATH)
        .map(|s| s == "true")
        .unwrap_or(false);

    // Also check the encrypted_rooms list — the room may be encrypted even
    // if the original incoming message was plaintext (e.g., an m.room.encryption
    // state event arrived between receive and respond).
    let room_is_encrypted = metadata.encrypted || sync::is_room_encrypted(&metadata.room_id);

    if e2ee_enabled && room_is_encrypted {
        let chunks = client::split_message(content);
        for (i, chunk) in chunks.iter().enumerate() {
            let encrypted_content =
                crypto::encrypt_message(homeserver_url, &metadata.room_id, chunk)
                    .map_err(|e| {
                        format!(
                            "Encryption failed for room {} chunk {} — refusing plaintext in E2EE room: {}",
                            metadata.room_id, i, e
                        )
                    })?;

            let body = serde_json::to_vec(&encrypted_content)
                .map_err(|e| format!("Failed to serialize encrypted message: {}", e))?;
            let txn_id = client::generate_txn_id();
            client::send_message_event(
                homeserver_url,
                &metadata.room_id,
                "m.room.encrypted",
                &txn_id,
                &body,
            )?;
        }

        return Ok(());
    }

    // Send as plaintext for non-encrypted rooms
    let chunks = client::split_message(content);

    for chunk in chunks {
        let txn_id = client::generate_txn_id();
        client::send_text_message(homeserver_url, &metadata.room_id, &txn_id, &chunk)?;
    }

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Create a JSON HTTP response.
fn json_response(status: u16, value: serde_json::Value) -> OutgoingHttpResponse {
    let body = serde_json::to_vec(&value).unwrap_or_else(|e| {
        channel_host::log(
            channel_host::LogLevel::Error,
            &format!("Failed to serialize JSON response: {}", e),
        );
        Vec::new()
    });
    let headers = serde_json::json!({"Content-Type": "application/json"});

    OutgoingHttpResponse {
        status,
        headers_json: headers.to_string(),
        body,
    }
}

// Export the component
export!(MatrixChannel);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_display_name() {
        assert_eq!(extract_display_name("@alice:example.com"), "alice");
        assert_eq!(extract_display_name("@bot:matrix.org"), "bot");
        assert_eq!(extract_display_name("@user"), "user");
        assert_eq!(extract_display_name("plain"), "plain");
    }

    #[test]
    fn test_metadata_roundtrip() {
        let meta = MatrixMessageMetadata {
            room_id: "!room:example.com".to_string(),
            event_id: "$evt1".to_string(),
            sender: "@alice:example.com".to_string(),
            encrypted: false,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: MatrixMessageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.room_id, "!room:example.com");
        assert_eq!(parsed.sender, "@alice:example.com");
    }
}
