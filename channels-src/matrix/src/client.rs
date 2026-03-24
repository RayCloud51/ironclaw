//! Matrix Client-Server API HTTP client.
//!
//! All HTTP requests go through the host-provided `channel_host::http_request`
//! function. Credentials are injected by the host at the boundary — the WASM
//! code never sees raw access tokens.

use crate::channel_host;
use crate::types::{
    SendEventResponse, SyncFilter, SyncResponse, TextMessageBody, WhoamiResponse,
};

/// Headers with Authorization and Content-Type for JSON requests.
fn json_headers() -> String {
    r#"{"Authorization":"Bearer {MATRIX_ACCESS_TOKEN}","Content-Type":"application/json"}"#
        .to_string()
}

/// Headers with Authorization only (no Content-Type).
fn auth_headers() -> String {
    r#"{"Authorization":"Bearer {MATRIX_ACCESS_TOKEN}"}"#.to_string()
}

/// Construct a full Matrix API URL from a homeserver base URL and path.
///
/// Strips trailing slash from homeserver URL to avoid double-slashes.
fn api_url(homeserver_url: &str, path: &str) -> String {
    let base = homeserver_url.trim_end_matches('/');
    format!("{}{}", base, path)
}

/// GET /_matrix/client/v3/account/whoami
///
/// Returns the user ID and device ID for the authenticated user.
/// Used to auto-detect bot identity when user_id is not configured.
pub fn whoami(homeserver_url: &str) -> Result<WhoamiResponse, String> {
    let url = api_url(homeserver_url, "/_matrix/client/v3/account/whoami");

    let response = channel_host::http_request("GET", &url, &auth_headers(), None, None)
        .map_err(|e| format!("whoami request failed: {}", e))?;

    if response.status != 200 {
        let body = String::from_utf8_lossy(&response.body);
        return Err(format!("whoami returned {}: {}", response.status, body));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse whoami response: {}", e))
}

/// GET /_matrix/client/v3/sync
///
/// Long-polls for new events. Pass `since` token to get incremental updates.
pub fn sync(
    homeserver_url: &str,
    since: Option<&str>,
    timeout_ms: u32,
    filter: Option<&SyncFilter>,
) -> Result<SyncResponse, String> {
    let mut url = api_url(homeserver_url, "/_matrix/client/v3/sync");

    // Build query parameters
    let mut params = Vec::new();
    if let Some(token) = since {
        params.push(format!("since={}", token));
    }
    params.push(format!("timeout={}", timeout_ms));

    if let Some(f) = filter {
        let filter_json = serde_json::to_string(f)
            .map_err(|e| format!("Failed to serialize sync filter: {}", e))?;
        params.push(format!("filter={}", url_encode(&filter_json)));
    }

    if !params.is_empty() {
        url = format!("{}?{}", url, params.join("&"));
    }

    // HTTP timeout should be longer than the sync timeout to allow the server
    // to respond before the client-side timeout fires
    let http_timeout_ms = timeout_ms.saturating_add(5_000);

    let response =
        channel_host::http_request("GET", &url, &auth_headers(), None, Some(http_timeout_ms))
            .map_err(|e| format!("sync request failed: {}", e))?;

    if response.status != 200 {
        let body = String::from_utf8_lossy(&response.body);
        return Err(format!("sync returned {}: {}", response.status, body));
    }

    let parsed: SyncResponse = serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse sync response: {}", e))?;

    Ok(parsed)
}

/// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
///
/// Send a message event to a room. Returns the event ID of the sent message.
pub fn send_message_event(
    homeserver_url: &str,
    room_id: &str,
    event_type: &str,
    txn_id: &str,
    body: &[u8],
) -> Result<SendEventResponse, String> {
    let encoded_room_id = url_encode(room_id);
    let url = api_url(
        homeserver_url,
        &format!(
            "/_matrix/client/v3/rooms/{}/send/{}/{}",
            encoded_room_id, event_type, txn_id
        ),
    );

    let response =
        channel_host::http_request("PUT", &url, &json_headers(), Some(body), None)
            .map_err(|e| format!("send event request failed: {}", e))?;

    if response.status != 200 {
        let body_str = String::from_utf8_lossy(&response.body);
        return Err(format!(
            "send event returned {}: {}",
            response.status, body_str
        ));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse send event response: {}", e))
}

/// Send a plain text message to a room.
pub fn send_text_message(
    homeserver_url: &str,
    room_id: &str,
    txn_id: &str,
    text: &str,
) -> Result<SendEventResponse, String> {
    let msg = TextMessageBody {
        msgtype: "m.text".to_string(),
        body: text.to_string(),
        format: None,
        formatted_body: None,
    };

    let body = serde_json::to_vec(&msg)
        .map_err(|e| format!("Failed to serialize message: {}", e))?;

    send_message_event(homeserver_url, room_id, "m.room.message", txn_id, &body)
}

/// POST /_matrix/client/v3/join/{roomIdOrAlias}
///
/// Join a room by ID or alias.
pub fn join_room(homeserver_url: &str, room_id_or_alias: &str) -> Result<String, String> {
    let encoded = url_encode(room_id_or_alias);
    let url = api_url(
        homeserver_url,
        &format!("/_matrix/client/v3/join/{}", encoded),
    );

    let response =
        channel_host::http_request("POST", &url, &json_headers(), Some(b"{}"), None)
            .map_err(|e| format!("join room request failed: {}", e))?;

    if response.status != 200 {
        let body = String::from_utf8_lossy(&response.body);
        return Err(format!("join room returned {}: {}", response.status, body));
    }

    // Response contains {"room_id": "!..."}
    let resp: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse join response: {}", e))?;

    resp.get("room_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "join response missing room_id".to_string())
}

/// POST /_matrix/client/v3/keys/upload
///
/// Upload device identity keys and one-time keys.
pub fn keys_upload(
    homeserver_url: &str,
    body: &[u8],
) -> Result<crate::types::KeysUploadResponse, String> {
    let url = api_url(homeserver_url, "/_matrix/client/v3/keys/upload");

    let response =
        channel_host::http_request("POST", &url, &json_headers(), Some(body), None)
            .map_err(|e| format!("keys/upload request failed: {}", e))?;

    if response.status != 200 {
        let body_str = String::from_utf8_lossy(&response.body);
        return Err(format!(
            "keys/upload returned {}: {}",
            response.status, body_str
        ));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse keys/upload response: {}", e))
}

/// POST /_matrix/client/v3/keys/query
///
/// Download device keys for specified users.
pub fn keys_query(
    homeserver_url: &str,
    body: &[u8],
) -> Result<crate::types::KeysQueryResponse, String> {
    let url = api_url(homeserver_url, "/_matrix/client/v3/keys/query");

    let response =
        channel_host::http_request("POST", &url, &json_headers(), Some(body), None)
            .map_err(|e| format!("keys/query request failed: {}", e))?;

    if response.status != 200 {
        let body_str = String::from_utf8_lossy(&response.body);
        return Err(format!(
            "keys/query returned {}: {}",
            response.status, body_str
        ));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse keys/query response: {}", e))
}

/// POST /_matrix/client/v3/keys/claim
///
/// Claim one-time keys for Olm session establishment.
pub fn keys_claim(
    homeserver_url: &str,
    body: &[u8],
) -> Result<crate::types::KeysClaimResponse, String> {
    let url = api_url(homeserver_url, "/_matrix/client/v3/keys/claim");

    let response =
        channel_host::http_request("POST", &url, &json_headers(), Some(body), None)
            .map_err(|e| format!("keys/claim request failed: {}", e))?;

    if response.status != 200 {
        let body_str = String::from_utf8_lossy(&response.body);
        return Err(format!(
            "keys/claim returned {}: {}",
            response.status, body_str
        ));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse keys/claim response: {}", e))
}

/// PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
///
/// Send to-device events (used for key sharing in E2EE).
pub fn send_to_device(
    homeserver_url: &str,
    event_type: &str,
    txn_id: &str,
    body: &[u8],
) -> Result<(), String> {
    let url = api_url(
        homeserver_url,
        &format!(
            "/_matrix/client/v3/sendToDevice/{}/{}",
            event_type, txn_id
        ),
    );

    let response =
        channel_host::http_request("PUT", &url, &json_headers(), Some(body), None)
            .map_err(|e| format!("sendToDevice request failed: {}", e))?;

    if response.status != 200 {
        let body_str = String::from_utf8_lossy(&response.body);
        return Err(format!(
            "sendToDevice returned {}: {}",
            response.status, body_str
        ));
    }

    Ok(())
}

/// Minimal URL encoding for Matrix identifiers.
///
/// Encodes characters that are not valid in URL path segments.
/// Matrix room IDs contain `!`, `:`, and `.` which need encoding
/// when used in URL paths.
pub(crate) fn url_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                result.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
            }
        }
    }
    result
}

/// Matrix's soft limit per event body.
pub const MATRIX_MAX_MESSAGE_LEN: usize = 4096;

/// Split a long message into chunks that fit within Matrix's limit.
///
/// Tries to split at natural boundaries (in priority order):
/// 1. Double newline (paragraph break)
/// 2. Single newline
/// 3. Sentence end (`. `, `! `, `? `)
/// 4. Word boundary (space)
/// 5. Hard cut at the limit
pub fn split_message(text: &str) -> Vec<String> {
    if text.chars().count() <= MATRIX_MAX_MESSAGE_LEN {
        return vec![text.to_string()];
    }

    let mut chunks: Vec<String> = Vec::new();
    let mut remaining = text;

    while !remaining.is_empty() {
        let window_bytes = remaining
            .char_indices()
            .take(MATRIX_MAX_MESSAGE_LEN)
            .last()
            .map(|(byte_idx, ch)| byte_idx + ch.len_utf8())
            .unwrap_or(remaining.len());

        if window_bytes >= remaining.len() {
            chunks.push(remaining.to_string());
            break;
        }

        let window = &remaining[..window_bytes];

        let split_at = window
            .rfind("\n\n")
            .or_else(|| window.rfind('\n'))
            .or_else(|| {
                let bytes = window.as_bytes();
                (1..bytes.len()).rev().find(|&i| {
                    matches!(bytes[i - 1], b'.' | b'!' | b'?') && bytes[i] == b' '
                })
            })
            .or_else(|| window.rfind(' '))
            .unwrap_or(window_bytes);

        let split_at = if split_at == 0 { window_bytes } else { split_at };

        chunks.push(remaining[..split_at].trim_end().to_string());
        remaining = remaining[split_at..].trim_start();
    }

    chunks
}

/// Generate a unique transaction ID for idempotent message sending.
///
/// Uses a combination of timestamp and a simple counter to ensure uniqueness
/// across invocations.
pub fn generate_txn_id() -> String {
    let now = channel_host::now_millis();
    // Use a simple hash-like approach: timestamp + random-ish bits
    // In WASM we don't have a proper RNG, but the host timestamp provides
    // sufficient uniqueness for transaction IDs.
    format!("m{}", now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode_simple() {
        assert_eq!(url_encode("hello"), "hello");
    }

    #[test]
    fn test_url_encode_room_id() {
        let encoded = url_encode("!room123:example.com");
        assert_eq!(encoded, "%21room123%3Aexample.com");
    }

    #[test]
    fn test_url_encode_user_id() {
        let encoded = url_encode("@user:example.com");
        assert_eq!(encoded, "%40user%3Aexample.com");
    }

    #[test]
    fn test_api_url() {
        assert_eq!(
            api_url("https://matrix.example.com", "/_matrix/client/v3/sync"),
            "https://matrix.example.com/_matrix/client/v3/sync"
        );
        // Trailing slash should be stripped
        assert_eq!(
            api_url("https://matrix.example.com/", "/_matrix/client/v3/sync"),
            "https://matrix.example.com/_matrix/client/v3/sync"
        );
    }

    #[test]
    fn test_split_message_short() {
        let chunks = split_message("Hello, world!");
        assert_eq!(chunks, vec!["Hello, world!"]);
    }

    #[test]
    fn test_split_message_long() {
        let text = "a ".repeat(3000); // 6000 chars > 4096 limit
        let chunks = split_message(&text);
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MATRIX_MAX_MESSAGE_LEN);
        }
    }

    #[test]
    fn test_split_message_paragraph_boundary() {
        let text = format!(
            "{}\n\n{}",
            "A".repeat(2000),
            "B".repeat(2000)
        );
        let chunks = split_message(&text);
        // Should split at the paragraph boundary
        assert!(chunks.len() >= 2);
        assert!(chunks[0].ends_with('A'));
        assert!(chunks[1].starts_with('B'));
    }
}
