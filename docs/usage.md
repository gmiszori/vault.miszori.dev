# Usage

## Create and share a package

1. Connect to WireGuard and sign in at the admin URL.
2. Choose files or a folder, or select **Format → Plain TXT** and enter a multiline secret.
3. Select an availability mode and expiration. Use a preset or **Choose date and time**, which uses the device's local time. Expiry starts at package creation, **including upload time**; allow enough time for large transfers.
4. Optionally add a private package name, then start encryption and upload. Keep the tab open until the share link is ready.
5. Copy the complete link and send it through a trusted, preferably end-to-end-encrypted channel.

The link contains the package ID in its path and the decryption key after `#`. URL fragments are not sent in HTTP requests, but a messaging provider receiving the complete link can read the key in the message. The server cannot recover a lost key or reconstruct the full link; create a new package if it is lost.

## Choose an availability mode

| Mode | Recipient action | Lifetime and failure behavior |
| --- | --- | --- |
| **One-time** (default) | Confirm the warning, then download or reveal | Exactly one authorized claim; ciphertext is deleted during/after the attempt, including failed or interrupted delivery. No retry or recovery. |
| **Available until expiry** | Download or reveal without a destructive-action warning | Repeated retrievals until expiry or deletion. Interrupted downloads can restart from the beginning, but cannot resume. |

The mode is fixed at creation. Older packages and omitted API mode values default to one-time. Opening a link, checking availability, or fetching a messaging preview does not claim a package or create a retrieval audit entry. Both modes require proof derived from the link's key.

Expiry and deletion immediately prevent new retrievals. Already-admitted reusable downloads may finish; their ciphertext remains allocated until active readers close and cleanup completes. Expired packages are unavailable immediately, independently of the 15-second cleanup sweep.

## Retrieve files or text

For files, the recipient opens the original link, chooses a destination where supported, and explicitly starts the download. The browser decrypts the package locally into one ZIP archive.

For text, **Reveal secret** decrypts into a read-only multiline field. **Copy secret** uses the clipboard when permitted, or selects the text for manual copying. Text is rendered literally, never executed as HTML, and does not create a ZIP or file download. One-time text is consumed when revelation starts, so copy it before leaving.

The page removes the key fragment from the current address/history entry after capturing it. Keys and decrypted text remain in tab memory; reloading requires reopening the original link. Text is cleared on leaving or initializing another package. The admin text editor is also cleared after upload, on leaving/sign-out, and when switching back to files. Copies retained by recipients or clipboard tools cannot be revoked.

## Private names and retrieval activity

Optional package names are visible only to the administrator and unlock at sign-in. Add a name during creation or use a package row's controls to rename or remove it. Names are encrypted separately from content and are absent from share links, recipient pages, archives, and previews. Signing out, leaving, or an authentication failure clears the name key and displayed names; reloading requires signing in again.

**Activity (count)** opens a paginated history of authorized retrieval starts, with up to 100 entries per page. It includes time, source IP, and reported browser, OS, and device details, including interrupted attempts. Closing the dialog or signing out clears displayed audit details. A `consumed` state means the server completed its response, **not** that the recipient successfully saved, extracted, or read it; `failed` includes interrupted uploads and aborted downloads.

Activity persists until 90 days after package expiry, including after deletion. Audit-write failures prevent ciphertext delivery. Browser/device details come from bounded User-Agent and low-entropy client-hint headers, which can be absent or forged; they are not proof of identity, hardware model, or location. No fingerprinting, geolocation, or persistent device identifier is used. Disclose this metadata collection to recipients and monitor audit disk usage separately from ciphertext quotas.

## Browser support and large downloads

Use trusted HTTPS, sufficient destination space, and a filesystem that supports files above 4 GiB; FAT32 is unsuitable for large archives. Desktop Chrome/Edge's File System Access API is preferred. Other compatible browsers use a same-origin Service Worker to stream into the native download mechanism without buffering the entire archive.

The worker is checked before a claim and uses a random, single-use local download route with backpressure. It receives ZIP bytes, not the key, does not upload plaintext, and does not cache files or keys in browser storage. It does not intercept unrelated routes or replace active transfers during updates.

If streaming is unavailable, the in-memory Blob fallback is limited to **128 MiB**. A failed worker preparation stops before claiming and requires renewed consent for fallback. Use working streaming support for large or unknown-size packages. Browser policies, Safari/iOS restrictions, private/embedded browsers, background suspension, and OS limits vary; a 10–20 GiB save is not guaranteed on every device. Keep the tab open and the device awake. Downloads cannot resume, and successful server delivery does not prove a successful local save.

## Messaging previews

Previews use one generic 1200×630 banner, with no package names, filenames, keys, contents, audit details, or package-specific availability. Preview requests do not consume packages. Image URLs use the configured public origin rather than request headers or VPN addresses; no canonical or `og:url` replacement is emitted, so clients can retain the original fragment-bearing link.

Messaging services may crop or cache the artwork, including after package deletion. Their access to the full message is separate from HTTP preview behavior: **a complete link still shares the decryption key with its recipients and messaging provider**. The application does not submit share links to external preview/debugging services.
