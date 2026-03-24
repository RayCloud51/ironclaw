# Matrix Channel Setup

Connect IronClaw to Matrix for end-to-end encrypted messaging.

## Prerequisites

- A Matrix account (on any homeserver: matrix.org, Element, self-hosted Synapse/Conduit/etc.)
- An access token for the bot account
- The homeserver URL

## Getting Your Access Token

### Option A: From Element (easiest)

1. Log into Element (web or desktop) with your bot account
2. Go to **Settings** > **Help & About**
3. Scroll to **Advanced** and click **Access Token**
4. Copy the token (starts with `syt_` or `MDAxN...`)

### Option B: Via the Matrix API

```bash
curl -X POST "https://YOUR_HOMESERVER/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "m.login.password",
    "identifier": {"type": "m.id.user", "user": "YOUR_USERNAME"},
    "password": "YOUR_PASSWORD"
  }'
```

The response contains `access_token` and `device_id`.

### Option C: Create a dedicated bot account

For production use, create a dedicated account on your homeserver and generate an access token for it.

## Installation

### 1. Build the WASM module

```bash
# Prerequisites
rustup target add wasm32-wasip2
cargo install wasm-tools  # optional but recommended

# Build
cd channels-src/matrix
./build.sh
```

### 2. Install

```bash
mkdir -p ~/.ironclaw/channels
cp channels-src/matrix/matrix.wasm ~/.ironclaw/channels/
cp channels-src/matrix/matrix.capabilities.json ~/.ironclaw/channels/
```

### 3. Configure the homeserver URL

Edit `~/.ironclaw/channels/matrix.capabilities.json`:

- Replace `HOMESERVER_HOST_PLACEHOLDER` in the HTTP allowlist with your homeserver domain (e.g., `matrix.example.com`)
- Set `homeserver_url` in the config section to your full homeserver URL (e.g., `https://matrix.example.com`)

### 4. Run onboarding

```bash
ironclaw onboard --channels-only
```

This will prompt you for:
- **Matrix access token** — paste the token from step above
- **Homeserver URL** — e.g., `https://matrix.example.com`
- **User ID** (optional) — e.g., `@bot:example.com` (auto-detected if empty)
- **Device ID** (optional) — for E2EE; auto-generated if empty

## Configuration

The `config` section in `matrix.capabilities.json` controls behavior:

| Field | Default | Description |
|-------|---------|-------------|
| `homeserver_url` | (required) | Your Matrix homeserver URL |
| `user_id` | (auto-detect) | Bot's Matrix user ID |
| `device_id` | (auto-generate) | Device ID for E2EE |
| `dm_policy` | `"pairing"` | Access control mode (see below) |
| `allow_from` | `[]` | Allowed user IDs for allowlist mode |
| `respond_to_all_room_messages` | `false` | Process all messages in joined rooms |
| `allowed_room_ids` | `[]` | Restrict to specific rooms (empty = all) |
| `sync_timeout_ms` | `30000` | Sync long-poll timeout |
| `enable_e2ee` | `false` | Enable end-to-end encryption |

## DM Policy Modes

### `pairing` (default)

Unknown users receive a pairing code. The bot owner approves them:

```bash
ironclaw pairing approve matrix <CODE>
```

### `allowlist`

Only user IDs in `allow_from` can interact with the bot:

```json
"allow_from": ["@alice:example.com", "@bob:matrix.org"]
```

### `open`

Any user can message the bot. Use with caution.

## Room Access Control

- If `allowed_room_ids` is non-empty, the bot only processes events from those rooms
- If `respond_to_all_room_messages` is `false` (default), the bot only responds in DM rooms
- Set `respond_to_all_room_messages` to `true` to respond in all joined rooms

## End-to-End Encryption (E2EE)

**Status:** E2EE framework is implemented. Full Olm/Megolm encryption requires the `vodozemac` crate compiled to `wasm32-wasip2`.

### Enabling E2EE

Set `enable_e2ee` to `true` in config. The bot will:

1. Generate device identity keys (Ed25519 + Curve25519)
2. Upload device keys to the homeserver
3. Decrypt incoming `m.room.encrypted` events using Megolm
4. Encrypt outgoing messages in E2EE-enabled rooms

### E2EE Limitations

- Cross-signing and device verification are not yet implemented
- Key backup/recovery is not yet supported
- The bot must be online when room keys are shared (no key forwarding yet)
- Megolm sessions rotate after 100 messages or 1 week

## Troubleshooting

### Bot doesn't receive messages

1. Check the access token is valid: `ironclaw doctor`
2. Verify the homeserver URL is correct (no trailing slash issues)
3. Check IronClaw logs: `RUST_LOG=ironclaw=debug cargo run`
4. Ensure the bot has joined the room (invite it first)

### "sync returned 401"

The access token is invalid or expired. Generate a new one.

### "sync returned 429"

Rate limited. The bot will automatically back off. If persistent, reduce `sync_timeout_ms` or check for duplicate bot instances.

### Messages not routed to responses

Ensure the metadata flow is intact — check logs for "Failed to parse metadata" errors.

### E2EE: "Missing Megolm session"

The bot doesn't have the room key. This happens if:
- The bot joined after the key was shared
- The bot was offline during key distribution
- Try: have another user send a message (triggering a new key share)

## Architecture

```
Matrix Homeserver ←──── /sync (long-poll) ────→ WASM Channel ──→ IronClaw Agent
                  ←── PUT /send (response) ────←              ←──
```

The channel uses polling mode (not webhooks) via the Matrix `/sync` endpoint. Each poll:
1. Calls `/sync` with the stored `since` token
2. Processes new `m.room.message` and `m.room.encrypted` events
3. Emits messages to the IronClaw agent
4. Stores the new `since` token for the next poll

All HTTP requests go through IronClaw's host function with automatic credential injection — the WASM module never handles raw tokens.
