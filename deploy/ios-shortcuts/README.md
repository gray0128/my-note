# iOS Shortcuts + Scriptable Setup (`my-note` M4a Clipboard)

Send text or compressed images from iOS Share Sheet, Action Button, Control Center, or Back Tap directly into your desktop `my-note` clipboard with end-to-end `MNC1` (`XChaCha20-Poly1305`) encryption and zero plaintext exposed to Cloudflare.

## Security Model

- Uses a **`clip-write`** one-way token: cannot read notes, keys, or clipboard history (`GET /v1/clip*` and all note endpoints return `403`).
- The pairing ticket for `clip-write` carries **only** `{ sync_url, device_id, device_token, clip_kid, clip_key }` — never `SMK` or `VKEK`.
- Credentials are stored strictly in Scriptable's native **iOS Keychain** (`mynote.clip.credentials.v1`), never hardcoded in shareable Shortcut files.
- Bitmap image MIME whitelist (`image/png`, `image/jpeg`, `image/webp`, `image/gif`): **`image/svg+xml` is strictly rejected** (share SVG source as plain text).
- Binary image uploads stream raw `MNC1` bytes via `PUT /v1/clip/blob` with zero Base64 body inflation.

> **Lossless Large Images (`> 1.5 MiB`, up to `10 MiB`)**: Use the installed Mobile PWA's **Clipboard** tab (`mynote-wasm` Rust WASM speed) to avoid iOS Shortcut extension Jetsam memory limits.

---

## Step 1: Issue a `clip-write` Pairing Code on Desktop

```bash
mynote device add --name iPhoneShortcuts --scope clip-write
```

Copy the printed `mynote-pair:v1:...` code (expires in 10 minutes, single-use).

## Step 2: Install Scriptable & Import Keychain Credentials

1. Install **Scriptable** from the iOS App Store.
2. Create a new script named `mynote-clip-push` and paste the full contents of [`mynote-clip-push.js`](./mynote-clip-push.js).
3. Run the script once inside Scriptable:
   - Paste the `mynote-pair:v1:...` pairing code (or raw credentials JSON).
   - Tap **Save to Keychain**. Scriptable claims the single-use ticket, decrypts `ClipKey`, and stores credentials in iOS Keychain.
4. Clear the pairing code from your iOS clipboard.

## Step 3: Wire iOS Shortcuts

### A. Share Sheet (Text + Pre-Compressed Image — Zero "Allow Paste" Prompt)

1. Open Apple **Shortcuts** → **New Shortcut** → enable **Show in Share Sheet** (accept **Text**, **URLs**, **Images**).
2. Add an **If** check for Image inputs:
   - **Resize Image**: Longest Edge `1920` px (keeps screenshots crisp and shrinks 48MP photos).
   - **Convert Image**: Format `JPEG` (Quality `80%`) or `PNG` (also converts HEIC to a Linux/Wayland-compatible bitmap, typically `200 KiB – 1.5 MiB`).
   - **Run Script** (`Scriptable` → `mynote-clip-push`) with **Parameter** = Converted Image (disable *Show When Run*).
3. **Otherwise** (Text / URL):
   - **Run Script** (`Scriptable` → `mynote-clip-push`) with **Parameter** = Shortcut Input (disable *Show When Run*).
4. Optionally add **Show Notification** displaying the Script Output.

### B. Action Button / Control Center (Quick Send Current Clipboard)

1. Create a Shortcut:
   - **Get Clipboard**
   - If image → **Resize Image** (`≤ 1920 px`) → **Convert Image** (`JPEG 80%`) → **Run Script** (`mynote-clip-push`, Parameter = Converted Image).
   - Otherwise → **Run Script** (`mynote-clip-push`, Parameter = Clipboard).
2. Bind the Shortcut to **Action Button**, **Control Center**, or **Back Tap**.

## Revoking or Rotating Keys

If the iPhone is lost or compromised:

```bash
mynote device ls
mynote device revoke <device_id>
mynote clip rotate-key
```

`clip rotate-key` destroys the old `ClipKey` across all devices and clears the cloud clipboard queue.
