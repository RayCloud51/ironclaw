//! E2EE layer for Matrix channel using vodozemac.
//!
//! Implements Olm/Megolm encryption using vodozemac for real cryptographic
//! operations. This module provides:
//!
//! - Device key generation and upload (Ed25519 + Curve25519)
//! - One-time key management (Curve25519 signed keys)
//! - Olm session establishment for device-to-device key exchange
//! - Megolm session management for room message encryption/decryption
//! - Canonical JSON signing for Matrix device key signatures
//!
//! # Architecture
//!
//! Because the WASM sandbox creates a fresh instance per callback, all
//! cryptographic state must be persisted to the workspace between calls.
//! vodozemac's pickle format (encrypted with a 32-byte key) is used for
//! all private key material.
//!
//! # E2EE Flow
//!
//! 1. `init_crypto()` — called during on_start when E2EE is enabled
//! 2. `handle_to_device_events()` — processes incoming Olm key exchanges
//! 3. `try_decrypt_event()` — decrypts m.room.encrypted events
//! 4. `encrypt_message()` — encrypts outgoing messages for E2EE rooms
//! 5. `share_room_key()` — distributes Megolm session keys via Olm

use std::collections::HashMap;

use vodozemac::megolm::{
    GroupSession, InboundGroupSession, MegolmMessage,
    SessionConfig as MegolmSessionConfig,
};
use vodozemac::olm::{
    Account, Message as OlmNormalMessage, OlmMessage, PreKeyMessage,
    Session as OlmSession, SessionConfig as OlmSessionConfig,
};
use vodozemac::Curve25519PublicKey;

use crate::channel_host;
use crate::client;
use crate::crypto_store::{self, StoredInboundMegolmSession, StoredOutboundMegolmSession};
use crate::types::{DeviceKeys, EncryptedContent, KeysUploadRequest, RoomEvent};

/// Cache of inbound Megolm sessions created during to-device processing.
///
/// Keyed by `(room_id, session_id)`. Used to make newly-received room keys
/// visible to `try_decrypt_event` within the same callback, before buffered
/// workspace writes are committed.
pub type MegolmSessionCache = HashMap<(String, String), StoredInboundMegolmSession>;

// ============================================================================
// Canonical JSON for Matrix Signing
// ============================================================================

/// Produce canonical JSON per Matrix spec (sorted keys, no whitespace).
///
/// Matrix requires a specific canonical JSON format for signing:
/// - Objects have keys sorted lexicographically
/// - No insignificant whitespace
/// - Numbers use the shortest representation
fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let items: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_json = serde_json::to_string(*k).unwrap_or_default();
                    let val_json = canonicalize_json(obj.get(*k).unwrap_or(&serde_json::Value::Null));
                    format!("{}:{}", key_json, val_json)
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

/// Sign a JSON object with the device's Ed25519 key.
///
/// Per Matrix spec: remove `signatures` and `unsigned` keys before signing,
/// produce canonical JSON, sign the bytes with Ed25519.
fn sign_json(
    account: &Account,
    value: &serde_json::Value,
) -> Result<String, String> {
    let mut signable = value.clone();
    if let Some(obj) = signable.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }
    let canonical = canonicalize_json(&signable);
    let signature = account.sign(canonical.as_bytes());
    Ok(signature.to_base64())
}

// ============================================================================
// Account Initialization
// ============================================================================

/// Load an existing vodozemac Account from the crypto store.
fn load_account() -> Result<Account, String> {
    let stored = crypto_store::read_account()
        .ok_or("No crypto account in store")?;

    let pickle: vodozemac::olm::AccountPickle =
        crypto_store::host_decrypt_pickle(&stored.pickled_account)?;
    Ok(Account::from_pickle(pickle))
}

/// Pickle and persist a vodozemac Account.
fn save_account(
    account: &Account,
    user_id: &str,
    device_id: &str,
    keys_uploaded: bool,
    uploaded_key_count: u32,
) -> Result<(), String> {
    let pickled = crypto_store::host_encrypt_pickle(&account.pickle())?;

    let stored = crypto_store::StoredAccount {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        pickled_account: pickled,
        ed25519_key: account.ed25519_key().to_base64(),
        curve25519_key: account.curve25519_key().to_base64(),
        keys_uploaded,
        uploaded_key_count,
    };
    crypto_store::write_account(&stored)
}

/// Initialize the E2EE subsystem.
///
/// On first run, generates a new Olm account with identity keys and uploads
/// device keys to the homeserver. On subsequent runs, loads the existing
/// account from the crypto store and checks one-time key counts.
///
/// The `device_id` parameter is a hint from config. If it is empty or does
/// not match the access token's device, we call `/whoami` to get the real
/// device_id bound to the authenticated session.
pub fn init_crypto(
    homeserver_url: &str,
    user_id: &str,
    device_id: &str,
) -> Result<(), String> {
    channel_host::log(
        channel_host::LogLevel::Info,
        "Initializing E2EE crypto layer",
    );

    // Resolve the real device_id from the homeserver. The access token is
    // bound to a specific device; uploading keys for a different device_id
    // will be rejected.
    let real_device_id = resolve_device_id(homeserver_url, device_id)?;

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!("Using device_id={} for E2EE", real_device_id),
    );

    // Persist device_id to workspace so other callbacks can use it.
    let _ = channel_host::workspace_write("state/device_id", &real_device_id);

    // Check for existing account
    if let Some(stored) = crypto_store::read_account() {
        // If the stored account was created with a different device_id
        // (e.g., a self-generated one), we need to re-create the account
        // with the correct device_id.
        if stored.device_id != real_device_id {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!(
                    "Stored device_id {} does not match authenticated device_id {}, \
                     re-initializing crypto account",
                    stored.device_id, real_device_id
                ),
            );
            // Fall through to create a new account with the correct device_id.
        } else {
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!(
                    "Loaded existing crypto account for device {}",
                    stored.device_id
                ),
            );

            let mut account = load_account()?;
            check_and_upload_one_time_keys(homeserver_url, &mut account, &stored)?;
            return Ok(());
        }
    }

    // First run (or device_id mismatch): generate a new account
    let account = Account::new();

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!(
            "Generated new crypto account: ed25519={}, curve25519={}",
            account.ed25519_key().to_base64(),
            account.curve25519_key().to_base64()
        ),
    );

    // Upload device keys. We keep the Account in scope rather than pickling
    // and reloading — workspace writes aren't committed until the callback
    // returns, so a save-then-reload within the same callback would fail.
    upload_device_keys(homeserver_url, &account, user_id, &real_device_id)?;

    // Generate and upload initial batch of one-time keys on the same
    // Account instance (requires &mut for generate_one_time_keys).
    let mut account = account;
    upload_one_time_keys(homeserver_url, &mut account, user_id, &real_device_id)?;

    // Persist the final account state (with keys marked as published).
    // upload_one_time_keys saves internally, but this covers the edge case
    // where OTK generation produced zero keys and the early return skipped save.
    save_account(&account, user_id, &real_device_id, true, 0)?;

    channel_host::log(
        channel_host::LogLevel::Info,
        "E2EE crypto initialization complete",
    );

    Ok(())
}

/// Resolve the device_id for the authenticated session.
///
/// Calls GET /whoami to get the device_id bound to the access token.
/// Falls back to the config hint if /whoami fails or returns no device_id.
fn resolve_device_id(homeserver_url: &str, config_hint: &str) -> Result<String, String> {
    match client::whoami(homeserver_url) {
        Ok(resp) => {
            if let Some(ref did) = resp.device_id {
                if !did.is_empty() {
                    if !config_hint.is_empty() && config_hint != did {
                        channel_host::log(
                            channel_host::LogLevel::Warn,
                            &format!(
                                "Config device_id={} differs from authenticated device_id={}; \
                                 using authenticated value",
                                config_hint, did
                            ),
                        );
                    }
                    return Ok(did.clone());
                }
            }
            // whoami succeeded but no device_id — use config hint if available
            if !config_hint.is_empty() {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    "whoami returned no device_id; using config hint",
                );
                Ok(config_hint.to_string())
            } else {
                Err(
                    "Cannot initialize E2EE: whoami returned no device_id and \
                     no device_id configured. The access token may not be bound \
                     to a device."
                        .to_string(),
                )
            }
        }
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("whoami failed: {}; falling back to config device_id", e),
            );
            if !config_hint.is_empty() {
                Ok(config_hint.to_string())
            } else {
                Err(format!(
                    "Cannot initialize E2EE: whoami failed ({}) and no device_id configured",
                    e
                ))
            }
        }
    }
}

// ============================================================================
// Key Upload
// ============================================================================

/// Upload device identity keys to the homeserver with Ed25519 signatures.
fn upload_device_keys(
    homeserver_url: &str,
    account: &Account,
    user_id: &str,
    device_id: &str,
) -> Result<(), String> {
    let mut keys = HashMap::new();
    keys.insert(
        format!("curve25519:{}", device_id),
        account.curve25519_key().to_base64(),
    );
    keys.insert(
        format!("ed25519:{}", device_id),
        account.ed25519_key().to_base64(),
    );

    // Build the device_keys object for signing
    let device_keys_value = serde_json::json!({
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": [
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        ],
        "keys": keys,
    });

    // Sign the canonical JSON
    let signature = sign_json(account, &device_keys_value)?;

    let mut user_sigs = HashMap::new();
    user_sigs.insert(
        format!("ed25519:{}", device_id),
        signature,
    );
    let mut signatures = HashMap::new();
    signatures.insert(user_id.to_string(), user_sigs);

    let device_keys = DeviceKeys {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        algorithms: vec![
            "m.olm.v1.curve25519-aes-sha2".to_string(),
            "m.megolm.v1.aes-sha2".to_string(),
        ],
        keys,
        signatures,
    };

    let request = KeysUploadRequest {
        device_keys: Some(device_keys),
        one_time_keys: None,
    };

    let body = serde_json::to_vec(&request)
        .map_err(|e| format!("Failed to serialize keys/upload: {}", e))?;

    client::keys_upload(homeserver_url, &body)?;

    save_account(account, user_id, device_id, true, 0)?;

    Ok(())
}

/// Generate and upload one-time keys.
fn upload_one_time_keys(
    homeserver_url: &str,
    account: &mut Account,
    user_id: &str,
    device_id: &str,
) -> Result<(), String> {
    account.generate_one_time_keys(crypto_store::OTK_UPLOAD_BATCH);

    let otks = account.one_time_keys();
    if otks.is_empty() {
        return Ok(());
    }

    // Build signed one-time keys
    let mut one_time_keys_map: HashMap<String, serde_json::Value> = HashMap::new();
    for (key_id, key) in otks.iter() {
        let key_base64 = key.to_base64();
        let key_name = format!("signed_curve25519:{}", key_id.to_base64());

        let key_json = serde_json::json!({ "key": key_base64 });
        let signature = sign_json(account, &key_json)?;

        let mut user_sigs = HashMap::new();
        user_sigs.insert(
            format!("ed25519:{}", device_id),
            serde_json::Value::String(signature),
        );
        let mut signatures = HashMap::new();
        signatures.insert(
            user_id.to_string(),
            serde_json::Value::Object(serde_json::Map::from_iter(
                user_sigs.into_iter(),
            )),
        );

        one_time_keys_map.insert(
            key_name,
            serde_json::json!({
                "key": key_base64,
                "signatures": signatures,
            }),
        );
    }

    let request = KeysUploadRequest {
        device_keys: None,
        one_time_keys: Some(one_time_keys_map),
    };

    let body = serde_json::to_vec(&request)
        .map_err(|e| format!("Failed to serialize OTK upload: {}", e))?;

    match client::keys_upload(homeserver_url, &body) {
        Ok(response) => {
            account.mark_keys_as_published();

            let count = response
                .one_time_key_counts
                .get("signed_curve25519")
                .copied()
                .unwrap_or(0);

            channel_host::log(
                channel_host::LogLevel::Info,
                &format!("Uploaded one-time keys. Server count: {}", count),
            );
            save_account(account, user_id, device_id, true, count)?;
        }
        Err(e) if e.contains("400") => {
            // 400 from keys/upload typically means "key already exists" — the
            // server already has OTKs from a previous upload with this device.
            // This is not fatal: existing OTKs still work for Olm session
            // establishment. Mark keys as published so the account's internal
            // counter advances past these colliding keys.
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!(
                    "OTK upload got 400 (likely key collision with existing upload): {}. \
                     Continuing with existing server OTKs.",
                    e
                ),
            );
            account.mark_keys_as_published();
            save_account(account, user_id, device_id, true, 0)?;
        }
        Err(e) => {
            return Err(format!("OTK upload failed: {}", e));
        }
    }

    Ok(())
}

/// Query the server for current one-time key counts.
///
/// Sends an empty keys/upload request (no device_keys, no one_time_keys)
/// which returns the server's current OTK counts without changing anything.
fn query_server_otk_count(homeserver_url: &str) -> Result<u32, String> {
    let request = KeysUploadRequest {
        device_keys: None,
        one_time_keys: None,
    };
    let body = serde_json::to_vec(&request)
        .map_err(|e| format!("Failed to serialize empty keys/upload: {}", e))?;
    let response = client::keys_upload(homeserver_url, &body)?;
    let count = response
        .one_time_key_counts
        .get("signed_curve25519")
        .copied()
        .unwrap_or(0);
    Ok(count)
}

/// Check one-time key count and upload more if needed.
///
/// Queries the server for the actual OTK count rather than relying on
/// the locally stored count, which may be stale after a restart.
fn check_and_upload_one_time_keys(
    homeserver_url: &str,
    account: &mut Account,
    stored: &crypto_store::StoredAccount,
) -> Result<(), String> {
    if !stored.keys_uploaded {
        upload_device_keys(
            homeserver_url,
            account,
            &stored.user_id,
            &stored.device_id,
        )?;
    }

    // Query the server for the real OTK count instead of using stale local value
    let server_count = query_server_otk_count(homeserver_url).unwrap_or_else(|e| {
        channel_host::log(
            channel_host::LogLevel::Warn,
            &format!("Failed to query server OTK count: {}; using stored count", e),
        );
        stored.uploaded_key_count
    });

    channel_host::log(
        channel_host::LogLevel::Debug,
        &format!(
            "Server OTK count: {} (stored: {}, threshold: {})",
            server_count, stored.uploaded_key_count, crypto_store::OTK_MIN_COUNT
        ),
    );

    if (server_count as usize) < crypto_store::OTK_MIN_COUNT {
        channel_host::log(
            channel_host::LogLevel::Info,
            &format!(
                "OTK count {} below threshold {}, uploading more",
                server_count,
                crypto_store::OTK_MIN_COUNT
            ),
        );
        upload_one_time_keys(
            homeserver_url,
            account,
            &stored.user_id,
            &stored.device_id,
        )?;
    }

    Ok(())
}

// ============================================================================
// To-Device Event Handling (Room Key Delivery)
// ============================================================================

/// Process incoming to-device events from /sync.
///
/// Handles:
/// - `m.room.encrypted`: Olm-encrypted payloads (contain m.room_key events)
/// - `m.room_key`: Direct room key delivery (rare, usually Olm-wrapped)
pub fn handle_to_device_events(events: &[crate::types::ToDeviceEvent]) -> MegolmSessionCache {
    let mut cache = MegolmSessionCache::new();
    for event in events {
        match event.event_type.as_str() {
            "m.room.encrypted" => {
                if let Err(e) = handle_olm_encrypted_to_device(event, &mut cache) {
                    channel_host::log(
                        channel_host::LogLevel::Warn,
                        &format!("Failed to handle Olm to-device event: {}", e),
                    );
                }
            }
            "m.room_key" => {
                // Direct room key (unusual but possible)
                match handle_room_key_event(&event.content) {
                    Ok(Some(stored)) => {
                        cache.insert(
                            (stored.room_id.clone(), stored.session_id.clone()),
                            stored,
                        );
                    }
                    Ok(None) => {}
                    Err(e) => {
                        channel_host::log(
                            channel_host::LogLevel::Warn,
                            &format!("Failed to handle direct room_key: {}", e),
                        );
                    }
                }
            }
            _ => {
                channel_host::log(
                    channel_host::LogLevel::Debug,
                    &format!("Ignoring to-device event type: {}", event.event_type),
                );
            }
        }
    }
    cache
}

/// Decrypt an Olm-encrypted to-device event and process the inner payload.
fn handle_olm_encrypted_to_device(
    event: &crate::types::ToDeviceEvent,
    cache: &mut MegolmSessionCache,
) -> Result<(), String> {
    let content: OlmEncryptedContent = serde_json::from_value(event.content.clone())
        .map_err(|e| format!("Failed to parse Olm encrypted content: {}", e))?;

    if content.algorithm != "m.olm.v1.curve25519-aes-sha2" {
        return Err(format!("Unsupported to-device algorithm: {}", content.algorithm));
    }

    let sender_key_str = &content.sender_key;
    let sender_curve = Curve25519PublicKey::from_base64(sender_key_str)
        .map_err(|e| format!("Invalid sender Curve25519 key: {}", e))?;

    let account_stored = crypto_store::read_account()
        .ok_or("No crypto account for Olm decryption")?;

    // Look for our ciphertext entry (keyed by our Curve25519 key)
    let our_ciphertext = content
        .ciphertext
        .get(&account_stored.curve25519_key)
        .ok_or("No ciphertext for our device")?;

    let msg_type = our_ciphertext
        .get("type")
        .and_then(|v| v.as_u64())
        .ok_or("Missing message type in Olm ciphertext")? as usize;
    let body_str = our_ciphertext
        .get("body")
        .and_then(|v| v.as_str())
        .ok_or("Missing body in Olm ciphertext")?;

    // Matrix spec: the ciphertext body is base64-encoded. Decode via
    // vodozemac's typed from_base64() to get the correct binary format.
    let olm_message = match msg_type {
        0 => {
            let pre_key = PreKeyMessage::from_base64(body_str)
                .map_err(|e| format!("Invalid Olm PreKey message: {}", e))?;
            OlmMessage::PreKey(pre_key)
        }
        1 => {
            let normal = OlmNormalMessage::from_base64(body_str)
                .map_err(|e| format!("Invalid Olm normal message: {}", e))?;
            OlmMessage::Normal(normal)
        }
        _ => return Err(format!("Unknown Olm message type: {}", msg_type)),
    };

    let plaintext = decrypt_olm_message(&sender_curve, &olm_message)?;

    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|e| format!("Olm plaintext not valid UTF-8: {}", e))?;

    let inner: serde_json::Value = serde_json::from_str(&plaintext_str)
        .map_err(|e| format!("Olm plaintext not valid JSON: {}", e))?;

    let inner_type = inner
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match inner_type {
        "m.room_key" => {
            let inner_content = inner
                .get("content")
                .ok_or("m.room_key missing content")?;
            if let Some(stored) = handle_room_key_event(inner_content)? {
                cache.insert(
                    (stored.room_id.clone(), stored.session_id.clone()),
                    stored,
                );
            }
        }
        other => {
            channel_host::log(
                channel_host::LogLevel::Debug,
                &format!("Ignoring Olm inner event type: {}", other),
            );
        }
    }

    Ok(())
}

/// Decrypt an Olm message, trying existing sessions first, then creating
/// a new inbound session for PreKey messages.
fn decrypt_olm_message(
    sender_key: &Curve25519PublicKey,
    message: &OlmMessage,
) -> Result<Vec<u8>, String> {
    let sender_key_b64 = sender_key.to_base64();

    // Try existing Olm sessions first
    let stored_sessions = crypto_store::read_olm_sessions(&sender_key_b64);
    for stored in &stored_sessions {
        let session_pickle: vodozemac::olm::SessionPickle =
            crypto_store::host_decrypt_pickle(&stored.pickled_session)?;
        let mut session = OlmSession::from_pickle(session_pickle);

        match session.decrypt(message) {
            Ok(plaintext) => {
                // Re-pickle and save the updated session
                let new_pickle = crypto_store::host_encrypt_pickle(&session.pickle())?;
                let mut updated = stored.clone();
                updated.pickled_session = new_pickle;
                updated.last_use_ts = channel_host::now_millis();
                save_olm_session(&sender_key_b64, &updated)?;
                return Ok(plaintext);
            }
            Err(_) => continue, // Try next session
        }
    }

    // No existing session worked. For PreKey messages, create a new inbound session.
    match message {
        OlmMessage::PreKey(pre_key_msg) => {
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!(
                    "Creating new inbound Olm session from PreKey (sender_key={})",
                    sender_key_b64
                ),
            );

            let account_stored = crypto_store::read_account()
                .ok_or("No crypto account for inbound session")?;
            let account_pickle: vodozemac::olm::AccountPickle =
                crypto_store::host_decrypt_pickle(&account_stored.pickled_account)?;
            let mut account = Account::from_pickle(account_pickle);

            let result = account
                .create_inbound_session(*sender_key, pre_key_msg)
                .map_err(|e| format!("Failed to create inbound Olm session: {}", e))?;

            // Save the updated account (one-time key consumed)
            save_account(
                &account,
                &account_stored.user_id,
                &account_stored.device_id,
                account_stored.keys_uploaded,
                account_stored.uploaded_key_count,
            )?;

            // Save the new session keyed by sender's curve25519 key.
            // This key must match what get_or_create_olm_session() uses for
            // lookup so that outbound messages reuse this session.
            let session_pickle = crypto_store::host_encrypt_pickle(&result.session.pickle())?;
            let stored_session = crypto_store::StoredOlmSession {
                sender_key: sender_key_b64.clone(),
                pickled_session: session_pickle,
                last_use_ts: channel_host::now_millis(),
            };
            save_olm_session(&sender_key_b64, &stored_session)?;

            Ok(result.plaintext)
        }
        OlmMessage::Normal(_) => {
            Err(format!(
                "No matching Olm session for sender_key={} and message is not a PreKey message \
                 (stored_sessions_tried={})",
                sender_key_b64,
                stored_sessions.len()
            ))
        }
    }
}

/// Save an Olm session, merging with existing sessions for the same sender key.
fn save_olm_session(
    sender_key: &str,
    session: &crypto_store::StoredOlmSession,
) -> Result<(), String> {
    // For simplicity, we store one session per sender key.
    // A production implementation would maintain a list and try each.
    crypto_store::write_olm_sessions(sender_key, std::slice::from_ref(session))
}

/// Handle an m.room_key event content — store the inbound Megolm session.
fn handle_room_key_event(
    content: &serde_json::Value,
) -> Result<Option<StoredInboundMegolmSession>, String> {
    let algorithm = content
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or("room_key missing algorithm")?;

    if algorithm != "m.megolm.v1.aes-sha2" {
        return Err(format!("Unsupported room key algorithm: {}", algorithm));
    }

    let room_id = content
        .get("room_id")
        .and_then(|v| v.as_str())
        .ok_or("room_key missing room_id")?;

    let session_id = content
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or("room_key missing session_id")?;

    let session_key_str = content
        .get("session_key")
        .and_then(|v| v.as_str())
        .ok_or("room_key missing session_key")?;

    let sender_key = content
        .get("sender_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Create the inbound Megolm session from the session key
    let session_key = vodozemac::megolm::SessionKey::from_base64(session_key_str)
        .map_err(|e| format!("Invalid Megolm session key: {}", e))?;

    let inbound = InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1());

    // Verify session ID matches
    if inbound.session_id() != session_id {
        return Err(format!(
            "Session ID mismatch: expected {}, got {}",
            session_id,
            inbound.session_id()
        ));
    }

    // Pickle and store
    let pickled = crypto_store::host_encrypt_pickle(&inbound.pickle())?;

    let stored = StoredInboundMegolmSession {
        room_id: room_id.to_string(),
        session_id: session_id.to_string(),
        sender_key: sender_key.to_string(),
        pickled_session: pickled,
        forwarded: false,
        seen_indices: Vec::new(),
    };

    crypto_store::write_inbound_megolm_session(&stored)?;

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!(
            "Stored inbound Megolm session {} for room {}",
            session_id, room_id
        ),
    );

    Ok(Some(stored))
}

// ============================================================================
// Megolm Decryption
// ============================================================================

/// Try to decrypt an encrypted room event.
///
/// Returns the decrypted plaintext body if successful. Performs message
/// index replay detection to prevent replay attacks.
pub fn try_decrypt_event(
    room_id: &str,
    event: &RoomEvent,
    session_cache: &mut MegolmSessionCache,
) -> Result<String, String> {
    let content: EncryptedContent = serde_json::from_value(event.content.clone())
        .map_err(|e| format!("Failed to parse encrypted content: {}", e))?;

    if content.algorithm != "m.megolm.v1.aes-sha2" {
        return Err(format!("Unsupported algorithm: {}", content.algorithm));
    }

    let session_id = content
        .session_id
        .as_ref()
        .ok_or("Missing session_id in encrypted event")?;

    let _sender_key = content
        .sender_key
        .as_ref()
        .ok_or("Missing sender_key in encrypted event")?;

    let ciphertext = content
        .ciphertext
        .as_ref()
        .ok_or("Missing ciphertext in encrypted event")?;

    // Check the in-memory cache first (for sessions received via to-device
    // in the same callback — workspace buffered writes aren't visible yet).
    let cache_key = (room_id.to_string(), session_id.clone());
    let mut stored = if let Some(cached) = session_cache.remove(&cache_key) {
        cached
    } else {
        crypto_store::read_inbound_megolm_session(room_id, session_id)
            .ok_or_else(|| format!("Missing Megolm session {}", session_id))?
    };

    // Unpickle the session
    let pickle: vodozemac::megolm::InboundGroupSessionPickle =
        crypto_store::host_decrypt_pickle(&stored.pickled_session)?;
    let mut session = InboundGroupSession::from_pickle(pickle);

    // Parse the ciphertext as a MegolmMessage
    let megolm_msg = MegolmMessage::from_base64(ciphertext)
        .map_err(|e| format!("Invalid Megolm ciphertext: {}", e))?;

    // Decrypt
    let decrypted = session
        .decrypt(&megolm_msg)
        .map_err(|e| format!("Megolm decryption failed: {}", e))?;

    // Replay detection: check message index hasn't been seen before
    if stored.seen_indices.contains(&decrypted.message_index) {
        return Err(format!(
            "Replay detected: message index {} already seen for session {}",
            decrypted.message_index, session_id
        ));
    }

    // Record this message index
    stored.seen_indices.push(decrypted.message_index);

    // Re-pickle and save the updated session
    stored.pickled_session = crypto_store::host_encrypt_pickle(&session.pickle())?;
    crypto_store::write_inbound_megolm_session(&stored)?;

    // Update cache so subsequent events in the same callback see the
    // updated seen_indices (workspace writes are buffered).
    session_cache.insert(cache_key, stored);

    // Parse the plaintext JSON to extract the body.
    // Decrypted Megolm content has the structure:
    // {"type": "m.room.message", "content": {"msgtype": "m.text", "body": "..."}, "room_id": "..."}
    let plaintext_str = String::from_utf8(decrypted.plaintext)
        .map_err(|e| format!("Decrypted plaintext not valid UTF-8: {}", e))?;

    let plaintext_json: serde_json::Value = serde_json::from_str(&plaintext_str)
        .map_err(|e| format!("Decrypted plaintext not valid JSON: {}", e))?;

    // Try content.body first (full event wrapper), then body directly (bare content)
    let body = plaintext_json
        .get("content")
        .and_then(|c| c.get("body"))
        .and_then(|v| v.as_str())
        .or_else(|| plaintext_json.get("body").and_then(|v| v.as_str()))
        .ok_or("Decrypted event missing body field")?;

    Ok(body.to_string())
}

// ============================================================================
// Megolm Encryption
// ============================================================================

/// Encrypt a plaintext message for an E2EE-enabled room.
///
/// Uses the outbound Megolm session for the room, creating one if needed.
/// Room keys are shared with other devices via Olm before encryption.
pub fn encrypt_message(
    homeserver_url: &str,
    room_id: &str,
    plaintext: &str,
) -> Result<serde_json::Value, String> {
    let now = channel_host::now_millis();
    let account_stored = crypto_store::read_account()
        .ok_or("No crypto account for encryption")?;

    // Check for existing outbound session
    let stored_session = crypto_store::read_outbound_megolm_session(room_id);

    let needs_new_session = match &stored_session {
        Some(s) => crypto_store::should_rotate_session(s, now),
        None => true,
    };

    // Extract previous session metadata before potentially consuming stored_session
    let prev_message_count = stored_session.as_ref().map(|s| s.message_count).unwrap_or(0);
    let prev_created_ts = stored_session.as_ref().map(|s| s.created_ts).unwrap_or(now);

    let (mut group_session, session_id) = if needs_new_session {
        channel_host::log(
            channel_host::LogLevel::Info,
            &format!("Creating new outbound Megolm session for room {}", room_id),
        );

        let session = GroupSession::new(MegolmSessionConfig::version_1());
        let session_key = session.session_key();
        let sid = session.session_id();

        // Create a corresponding inbound session for our own messages
        let inbound = InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1());
        let inbound_pickle = crypto_store::host_encrypt_pickle(&inbound.pickle())?;
        let stored_inbound = StoredInboundMegolmSession {
            room_id: room_id.to_string(),
            session_id: sid.clone(),
            sender_key: account_stored.curve25519_key.clone(),
            pickled_session: inbound_pickle,
            forwarded: false,
            seen_indices: Vec::new(),
        };
        crypto_store::write_inbound_megolm_session(&stored_inbound)?;

        // Share the room key with other devices in the room
        share_room_key(homeserver_url, room_id, &session_key, &sid, &account_stored)?;

        (session, sid)
    } else {
        let s = stored_session.ok_or("Session disappeared")?;
        let pickle: vodozemac::megolm::GroupSessionPickle =
            crypto_store::host_decrypt_pickle(&s.pickled_session)?;
        let session = GroupSession::from_pickle(pickle);
        let sid = s.session_id.clone();
        (session, sid)
    };

    // Build the event content to encrypt
    let event_content = serde_json::json!({
        "type": "m.room.message",
        "content": {
            "msgtype": "m.text",
            "body": plaintext,
        },
        "room_id": room_id,
    });
    let content_str = serde_json::to_string(&event_content)
        .map_err(|e| format!("Failed to serialize event content: {}", e))?;

    // Encrypt with Megolm
    let ciphertext = group_session.encrypt(&content_str);

    // Save the updated outbound session
    let outbound_pickle = crypto_store::host_encrypt_pickle(&group_session.pickle())?;
    let msg_count = if needs_new_session { 1 } else { prev_message_count + 1 };
    let created_ts = if needs_new_session { now } else { prev_created_ts };

    let stored_outbound = StoredOutboundMegolmSession {
        room_id: room_id.to_string(),
        session_id: session_id.clone(),
        pickled_session: outbound_pickle,
        message_count: msg_count,
        created_ts,
    };
    crypto_store::write_outbound_megolm_session(&stored_outbound)?;

    // Build the encrypted event content
    Ok(serde_json::json!({
        "algorithm": "m.megolm.v1.aes-sha2",
        "sender_key": account_stored.curve25519_key,
        "session_id": session_id,
        "device_id": account_stored.device_id,
        "ciphertext": ciphertext.to_base64(),
    }))
}

// ============================================================================
// Room Key Sharing (Olm)
// ============================================================================

/// Share Megolm room key with all devices in a room via Olm.
///
/// Steps:
/// 1. Query device keys for all users in the room
/// 2. For each device, establish or reuse an Olm session
/// 3. Encrypt the room key with each Olm session
/// 4. Send encrypted keys via sendToDevice
fn share_room_key(
    homeserver_url: &str,
    room_id: &str,
    session_key: &vodozemac::megolm::SessionKey,
    session_id: &str,
    account_stored: &crypto_store::StoredAccount,
) -> Result<(), String> {
    // Get room members by querying joined members
    // For now, we query for all users we know about from the room
    // In a full implementation, we'd track room membership from /sync state events
    let members = get_room_members(homeserver_url, room_id)?;

    if members.is_empty() {
        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!("No other members in room {} to share keys with", room_id),
        );
        return Ok(());
    }

    // Query device keys for all members
    let mut device_keys_request: HashMap<String, Vec<String>> = HashMap::new();
    for member in &members {
        device_keys_request.insert(member.clone(), Vec::new()); // empty = all devices
    }

    let query_body = serde_json::to_vec(&serde_json::json!({
        "device_keys": device_keys_request,
    }))
    .map_err(|e| format!("Failed to serialize keys/query: {}", e))?;

    let query_response = client::keys_query(homeserver_url, &query_body)?;

    // Build to-device messages for each device
    let mut messages: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();

    for (user_id, devices) in &query_response.device_keys {
        for (target_device_id, device_info) in devices {
            // Skip ALL of our own user's devices — we don't need to share
            // room keys with ourselves, and creating Olm sessions with our
            // own stale devices can waste OTKs or cause errors.
            if user_id == &account_stored.user_id {
                channel_host::log(
                    channel_host::LogLevel::Trace,
                    &format!(
                        "share_room_key: skipping own device {}:{}",
                        user_id, target_device_id
                    ),
                );
                continue;
            }

            // Get the target device's Curve25519 key
            let target_curve_key = device_info
                .keys
                .get(&format!("curve25519:{}", target_device_id))
                .ok_or_else(|| {
                    format!("No Curve25519 key for {}:{}", user_id, target_device_id)
                })?;

            let target_curve = Curve25519PublicKey::from_base64(target_curve_key)
                .map_err(|e| format!("Invalid target Curve25519 key: {}", e))?;

            // Establish or reuse an Olm session with this device.
            // get_or_create_olm_session returns immediately if an existing
            // session is found — it only calls keys/claim when none exists.
            let mut olm_session = match get_or_create_olm_session(
                homeserver_url,
                &target_curve,
                user_id,
                target_device_id,
            ) {
                Ok(session) => session,
                Err(e) => {
                    // Don't abort the entire share — skip this device and
                    // continue with others. The recipient can request the
                    // key later via m.room_key_request.
                    channel_host::log(
                        channel_host::LogLevel::Warn,
                        &format!(
                            "share_room_key: failed to get Olm session for {}:{}: {}. Skipping.",
                            user_id, target_device_id, e
                        ),
                    );
                    continue;
                }
            };

            // Get the recipient's Ed25519 key from the keys/query response
            let target_ed25519_key = device_info
                .keys
                .get(&format!("ed25519:{}", target_device_id))
                .ok_or_else(|| {
                    format!("No Ed25519 key for {}:{}", user_id, target_device_id)
                })?;

            // Build the room key payload per Matrix spec for to-device events.
            let room_key_content = serde_json::json!({
                "type": "m.room_key",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "room_id": room_id,
                    "session_id": session_id,
                    "session_key": session_key.to_base64(),
                },
                "sender": account_stored.user_id,
                "sender_device": account_stored.device_id,
                "keys": {
                    "ed25519": account_stored.ed25519_key,
                },
                "recipient": user_id,
                "recipient_keys": {
                    "ed25519": target_ed25519_key,
                },
            });

            let payload = serde_json::to_string(&room_key_content)
                .map_err(|e| format!("Failed to serialize room key: {}", e))?;

            // Encrypt with Olm
            let olm_msg = olm_session.encrypt(&payload);

            // Save the updated Olm session
            let session_pickle = crypto_store::host_encrypt_pickle(&olm_session.pickle())?;
            let stored_session = crypto_store::StoredOlmSession {
                sender_key: target_curve_key.clone(),
                pickled_session: session_pickle,
                last_use_ts: channel_host::now_millis(),
            };
            save_olm_session(target_curve_key, &stored_session)?;

            // Build the to-device message.
            // OlmMessage's Serialize impl produces {"type": N, "body": "base64..."}
            // which matches the Matrix ciphertext format for m.olm.v1.
            let olm_msg_json = serde_json::to_value(&olm_msg)
                .map_err(|e| format!("Failed to serialize Olm message: {}", e))?;
            let encrypted_content = serde_json::json!({
                "algorithm": "m.olm.v1.curve25519-aes-sha2",
                "sender_key": account_stored.curve25519_key,
                "ciphertext": {
                    target_curve_key: olm_msg_json,
                }
            });

            messages
                .entry(user_id.clone())
                .or_default()
                .insert(target_device_id.clone(), encrypted_content);
        }
    }

    if messages.is_empty() {
        return Ok(());
    }

    // Send via sendToDevice
    let send_body = serde_json::to_vec(&serde_json::json!({
        "messages": messages,
    }))
    .map_err(|e| format!("Failed to serialize sendToDevice: {}", e))?;

    let txn_id = client::generate_txn_id();
    client::send_to_device(homeserver_url, "m.room.encrypted", &txn_id, &send_body)?;

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!("Shared room key with {} users in {}", messages.len(), room_id),
    );

    Ok(())
}

/// Get or create an Olm session with a target device.
fn get_or_create_olm_session(
    homeserver_url: &str,
    target_curve: &Curve25519PublicKey,
    user_id: &str,
    device_id: &str,
) -> Result<OlmSession, String> {
    let target_key_b64 = target_curve.to_base64();

    // Try existing sessions (keyed by the remote party's curve25519 key)
    let stored_sessions = crypto_store::read_olm_sessions(&target_key_b64);
    if let Some(stored) = stored_sessions.first() {
        let session_pickle: vodozemac::olm::SessionPickle =
            crypto_store::host_decrypt_pickle(&stored.pickled_session)?;
        return Ok(OlmSession::from_pickle(session_pickle));
    }

    channel_host::log(
        channel_host::LogLevel::Debug,
        &format!(
            "No existing Olm session for {}:{}, claiming OTK",
            user_id, device_id
        ),
    );

    // Claim a one-time key and create outbound session
    let mut claim_request: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut device_map = HashMap::new();
    device_map.insert(device_id.to_string(), "signed_curve25519".to_string());
    claim_request.insert(user_id.to_string(), device_map);

    let claim_body = serde_json::to_vec(&serde_json::json!({
        "one_time_keys": claim_request,
    }))
    .map_err(|e| format!("Failed to serialize keys/claim: {}", e))?;

    let claim_response = client::keys_claim(homeserver_url, &claim_body)?;

    // Extract the claimed one-time key
    let user_keys = claim_response
        .one_time_keys
        .get(user_id)
        .ok_or_else(|| format!("No OTK claimed for user {}", user_id))?;

    let device_keys = user_keys
        .get(device_id)
        .ok_or_else(|| format!("No OTK claimed for device {}", device_id))?;

    // The response is {key_id: {key: "base64...", signatures: {...}}}
    let otk_value = device_keys
        .as_object()
        .and_then(|obj| obj.values().next())
        .ok_or("Empty OTK response for device")?;

    let otk_base64 = otk_value
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or("OTK response missing key field")?;

    let one_time_key = Curve25519PublicKey::from_base64(otk_base64)
        .map_err(|e| format!("Invalid OTK Curve25519 key: {}", e))?;

    // Load our account to create the outbound session
    let account_stored = crypto_store::read_account()
        .ok_or("No crypto account for outbound Olm session")?;
    let account_pickle: vodozemac::olm::AccountPickle =
        crypto_store::host_decrypt_pickle(&account_stored.pickled_account)?;
    let account = Account::from_pickle(account_pickle);

    let session = account.create_outbound_session(
        OlmSessionConfig::version_1(),
        *target_curve,
        one_time_key,
    );

    // Save for persistence across restarts (buffered — not readable until
    // commit_writes() runs after the callback returns). Return the live
    // session object directly for immediate use within this callback.
    let session_pickle = crypto_store::host_encrypt_pickle(&session.pickle())?;
    let stored_session = crypto_store::StoredOlmSession {
        sender_key: target_key_b64,
        pickled_session: session_pickle,
        last_use_ts: channel_host::now_millis(),
    };
    save_olm_session(&target_curve.to_base64(), &stored_session)?;

    Ok(session)
}

/// Get room members for key sharing.
///
/// Uses the /_matrix/client/v3/rooms/{roomId}/joined_members endpoint.
fn get_room_members(homeserver_url: &str, room_id: &str) -> Result<Vec<String>, String> {
    let encoded_room_id = crate::client::url_encode(room_id);
    let url = format!(
        "{}/_matrix/client/v3/rooms/{}/joined_members",
        homeserver_url.trim_end_matches('/'),
        encoded_room_id
    );

    let headers = r#"{"Authorization":"Bearer {MATRIX_ACCESS_TOKEN}"}"#;
    let response = channel_host::http_request("GET", &url, headers, None, None)
        .map_err(|e| format!("joined_members request failed: {}", e))?;

    if response.status != 200 {
        let body = String::from_utf8_lossy(&response.body);
        return Err(format!("joined_members returned {}: {}", response.status, body));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse joined_members: {}", e))?;

    let members = parsed
        .get("joined")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    Ok(members)
}

// ============================================================================
// Internal Types
// ============================================================================

/// Content of an Olm-encrypted to-device event.
#[derive(serde::Deserialize)]
struct OlmEncryptedContent {
    algorithm: String,
    sender_key: String,
    /// Ciphertext map: {recipient_curve25519_key: {type: int, body: string}}
    ciphertext: HashMap<String, serde_json::Value>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_json_simple() {
        let val = serde_json::json!({"b": 2, "a": 1});
        assert_eq!(canonicalize_json(&val), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonicalize_json_nested() {
        let val = serde_json::json!({"z": {"b": true, "a": null}, "a": [1, "two"]});
        assert_eq!(
            canonicalize_json(&val),
            r#"{"a":[1,"two"],"z":{"a":null,"b":true}}"#
        );
    }

    #[test]
    fn test_canonicalize_json_string_escaping() {
        let val = serde_json::json!({"key": "hello \"world\""});
        assert_eq!(
            canonicalize_json(&val),
            r#"{"key":"hello \"world\""}"#
        );
    }

    #[test]
    fn test_vodozemac_account_roundtrip() {
        let account = Account::new();
        let ed25519 = account.ed25519_key().to_base64();
        let curve25519 = account.curve25519_key().to_base64();

        // Verify keys are non-empty base64
        assert!(!ed25519.is_empty());
        assert!(!curve25519.is_empty());

        // Serde roundtrip of pickle (mirrors host_encrypt_pickle/host_decrypt_pickle path)
        let pickle = account.pickle();
        let serialized = serde_json::to_vec(&pickle).expect("serialize pickle");
        let deserialized: vodozemac::olm::AccountPickle =
            serde_json::from_slice(&serialized).expect("deserialize pickle");
        let restored = Account::from_pickle(deserialized);

        assert_eq!(restored.ed25519_key().to_base64(), ed25519);
        assert_eq!(restored.curve25519_key().to_base64(), curve25519);
    }

    #[test]
    fn test_megolm_encrypt_decrypt_roundtrip() {
        let mut outbound = GroupSession::new(MegolmSessionConfig::version_1());
        let session_key = outbound.session_key();

        let inbound = InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1());

        assert_eq!(outbound.session_id(), inbound.session_id());

        let plaintext = r#"{"type":"m.room.message","content":{"msgtype":"m.text","body":"Hello!"}}"#;
        let ciphertext = outbound.encrypt(plaintext);

        let mut inbound_mut = inbound;
        let decrypted = inbound_mut.decrypt(&ciphertext).expect("decrypt should succeed");

        assert_eq!(
            String::from_utf8(decrypted.plaintext).expect("valid utf8"),
            plaintext
        );
        assert_eq!(decrypted.message_index, 0);
    }

    #[test]
    fn test_megolm_replay_detection_indices() {
        let mut outbound = GroupSession::new(MegolmSessionConfig::version_1());
        let session_key = outbound.session_key();
        let mut inbound = InboundGroupSession::new(&session_key, MegolmSessionConfig::version_1());

        let msg1 = outbound.encrypt("message 1");
        let msg2 = outbound.encrypt("message 2");

        let d1 = inbound.decrypt(&msg1).expect("decrypt msg1");
        let d2 = inbound.decrypt(&msg2).expect("decrypt msg2");

        assert_eq!(d1.message_index, 0);
        assert_eq!(d2.message_index, 1);

        // Replaying msg1 should still work at the vodozemac level
        // (our replay detection is at the stored-indices level, not vodozemac's)
        // vodozemac may or may not reject replays depending on version
    }

    #[test]
    fn test_olm_session_roundtrip() {
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);
        let bob_otks = bob.one_time_keys();
        let bob_otk = bob_otks.values().next().expect("should have OTK");
        bob.mark_keys_as_published();

        // Alice creates outbound session to Bob
        let mut alice_session = alice.create_outbound_session(
            OlmSessionConfig::version_1(),
            bob.curve25519_key(),
            *bob_otk,
        );

        // Alice encrypts
        let alice_msg = alice_session.encrypt("hello from alice");

        // Bob creates inbound session
        match alice_msg {
            OlmMessage::PreKey(ref pre_key) => {
                let result = bob
                    .create_inbound_session(alice.curve25519_key(), pre_key)
                    .expect("inbound session creation");

                assert_eq!(
                    String::from_utf8(result.plaintext).expect("valid utf8"),
                    "hello from alice"
                );

                // Bob can now respond
                let mut bob_session = result.session;
                let bob_msg = bob_session.encrypt("hello from bob");

                // Alice decrypts Bob's response
                let decrypted = alice_session
                    .decrypt(&bob_msg)
                    .expect("alice decrypt bob msg");

                assert_eq!(
                    String::from_utf8(decrypted).expect("valid utf8"),
                    "hello from bob"
                );
            }
            OlmMessage::Normal(_) => panic!("First message should be PreKey"),
        }
    }

    #[test]
    fn test_megolm_session_pickle_roundtrip() {
        let mut outbound = GroupSession::new(MegolmSessionConfig::version_1());
        let session_id = outbound.session_id();

        // Encrypt a message before pickling
        let _ = outbound.encrypt("test");

        // Serde roundtrip of pickle (mirrors host_encrypt_pickle/host_decrypt_pickle path)
        let pickle = outbound.pickle();
        let serialized = serde_json::to_vec(&pickle).expect("serialize pickle");
        let deserialized: vodozemac::megolm::GroupSessionPickle =
            serde_json::from_slice(&serialized).expect("deserialize pickle");
        let restored = GroupSession::from_pickle(deserialized);

        assert_eq!(restored.session_id(), session_id);
    }
}
