# Web Intrusion Detector (Extension Main)

This repository contains a demo Chrome extension and companion test site for experimenting with **clientside and networklevel security detections**. It is intended as a safe sandbox to simulate suspicious behaviour (SQLi, spam, malware downloads, clipboard theft, keylogging, UI hijacking, etc.) and see how the extension detects and reports it.

> Note: This is **training / demo code**, not a productiongrade security product.

## Project Structure

- `extension/`  Source code for the browser extension
  - `manifest.json`  Extension manifest and permissions (MV3 service worker)
  - `background.js`  Background/service worker logic
    - Monitors `webRequest` events
    - Classifies detections into OWASPstyle categories (INJECTION, XSS, MISCONFIGURATION, SENSITIVE_DATA_EXPOSURE, CLIENT_SIDE_ATTACKS)
    - Logs structured events to `chrome.storage.local` (`detections` array)
  - `content.js`  Content script injected into pages
    - Detects inline scripts, suspicious event handlers, clipboard access, keyloggers
    - Hooks APIs like `getUserMedia`, `document.write`, `innerHTML`, `insertAdjacentHTML`
    - Reports findings back to the background script
  - `rules.js`  Detection patterns and rule metadata (`ruleMetadata`)
  - `popup.html` / `popup.js`  Popup UI that shows a live log of detections
- `test-site/`  Local HTML pages used to exercise and debug the extension
  - `index.html`  Main attack playground
  - `redirect.html`  Redirect target page
  - `script.js`  Simulates suspicious browser behaviours
  - `spam.js`  Generates highvolume / spammy network patterns
- `INTERVIEW_PREP.md`  Notes and preparation material for interview practice

## What the Extension Detects

### Networklevel detections (background.js)

All network detections are logged via a central `logDetection()` helper into `chrome.storage.local.detections`. Each entry includes:

- `time`  timestamp (ms since epoch)
- `url` and derived `origin`
- `type`  detection key (e.g. `SQLI_URL_PATTERN`, `SPAM_REQUEST_BURST`)
- `category`  one of the OWASPstyle buckets
- `severity`  `info`, `warning`, or `critical`
- `details`  humanreadable details
- `ruleId`  stable rule identifier from `rules.js` (`ruleMetadata`)

Networklevel rules include:

- **SQL injectionlike URLs** (`SQLI_URL_PATTERN`)
- **Suspicious redirects** (`REDIRECT_SUSPICIOUS`)
- **Executable / malware downloads** (`MALWARE_EXECUTABLE_DOWNLOAD`)
- **Double extensions** like `invoice.pdf.exe` (`MALWARE_DOUBLE_EXTENSION`)
- **Downloads without recent user gesture** (`DOWNLOAD_WITHOUT_USER_GESTURE`)
- **Insecure HTTP downloads** (`DOWNLOAD_INSECURE_HTTP`)
- **Spam / bursty traffic** (`SPAM_REQUEST_BURST`)
- **MIME vs file extension mismatches**
  - Document MIME with executable extension (`MIME_MISMATCH_EXECUTABLE`)
  - General mismatch between extension and `Content-Type` (`MIME_MISMATCH_GENERAL`)
- **Security header issues**
  - Missing CSP on HTTPS (`HEADER_MISSING_CSP`)
  - Missing HSTS on HTTPS (`HEADER_MISSING_HSTS`)
  - Weak or missing `Referrer-Policy` (`HEADER_WEAK_REFERRER_POLICY`)
  - Missing `X-Frame-Options` (`HEADER_MISSING_XFO`)
- **Weak sensitive cookies** (`COOKIE_WEAK_SENSITIVE`)
  - E.g. auth/session cookies missing `HttpOnly` and/or `Secure`

Many of these also trigger a browser notification and an inpage alert via the content script.

### Clientside / DOMlevel detections (content.js)

The content script monitors the current page and reports threats back to the background script:

- **Inline scripts with XSSlike payloads** (`INLINE_SCRIPT`)
- **Suspicious inline event handlers** (`SUSPICIOUS_ATTRIBUTE`)
- **Clipboard read / write attempts**
  - `CLIPBOARD_THEFT`  reading from `navigator.clipboard.readText()`
  - `CLIPBOARD_MANIPULATION`  writing via `navigator.clipboard.writeText()`
- **Keyloggerlike behaviour** (`KEYLOGGER`)
  - Multiple listeners on keyboard events
- **Camera / microphone access**
  - `CAMERA_ACCESS` and `MICROPHONE_ACCESS` when `getUserMedia` is called
- **Automatic redirects** without a recent click (`AUTO_REDIRECT_BLOCKED`)
- **Credential hijacking** on form submission (`CREDENTIAL_HIJACKING_BLOCKED`)
  - Credentials leaving the current origin
  - HTTPS page submitting to HTTP endpoint
- **Runtime XSS sinks**
  - `innerHTML` assignments (`RUNTIME_XSS_INNERHTML`)
  - `document.write` (`RUNTIME_XSS_DOCUMENT_WRITE`)
  - `insertAdjacentHTML` (`RUNTIME_XSS_INSERT_ADJACENT_HTML`)

When a threat is detected, the content script:

1. Calls `safeSendMessage({ type: "THREAT_DETECTED", ... })` to the background.
2. The background logs a typed detection event.
3. For many threats, the background also shows a uservisible notification and/or inpage banner.

## Popup Log UI

Clicking the extension icon opens `popup.html`, which is backed by `popup.js` and reads all stored detections from `chrome.storage.local`.

Features:

- **Perorigin category summary** table at the top.
- **Recent events** table with:
  - Time, origin, category, rule ID, type, severity badge, and truncated details.
- **Filters & controls**:
  - Filter by origin.
  - Filter by category.
  - "Show last" selector including an **`All`** option (0) to display all stored events.
  - Manual **Refresh** button.
  - **Export JSON** button to download the raw `detections` array.
- **Live updates**:
  - The popup listens to `chrome.storage.onChanged` and autorefreshes when the `detections` array changes while the popup is open.

The background script also logs each stored event to the console as:

```text
[LOG DETECTION] Storing event { ... }
```

This makes it easy to crosscheck what the popup should be displaying.

## Getting Started

### 1. Clone or download

If you have not already, clone this repository:

```bash
git clone https://github.com/notaaaaaaa/extensionmain.git
cd extensionmain
```

Or open the folder if you already have it locally.

### 2. Load the extension in Chrome

1. Open `chrome://extensions` in Google Chrome.
2. Enable **Developer mode** (topright toggle).
3. Click **Load unpacked**.
4. Select the `extension/` folder from this project.
5. Pin the extension icon if you want quick access to the popup.

### 3. Open the test site

You can open the test pages directly from the file system:

1. In your browser, use **File  Open File** (or press `Ctrl+O`).
2. Navigate to the `test-site/` folder inside this project.
3. Open `index.html`.

Or serve it via a simple HTTP server, for example:

```bash
npx serve test-site
# or
cd test-site
python -m http.server 8000
```

Then browse to `http://localhost:PORT/index.html`.

### 4. Trigger detections

From the test site UI you can:

- Fire SQLilike requests
- Trigger weird redirects
- Generate spammy request bursts
- Start fake malware downloads and MIME mismatches
- Simulate clipboard theft / manipulation
- Start and stop a keylogger
- Request camera/microphone access
- Trigger autoredirects and credential hijacking
- Exercise fullscreen UI hijacks and fake security warnings

As you click these buttons, watch:

- The page logs (DevTools Console on the test page)
- The background page logs (Chrome extension background console)
- The extension popup **Recent events** and **summary** tables

## Development & Debugging

- Make changes to files in the `extension/` or `test-site/` folders.
- After changing extension code, reload it from **chrome://extensions** using the **Reload** button.
- Use DevTools:
  - For the test site: open the normal DevTools (F12).
  - For the extension background and popup: rightclick the extension icon  **Inspect popup** or use the background service worker console.
- All detections are persisted in `chrome.storage.local.detections` (up to the configured cap), which you can also inspect via the **Application** tab in DevTools.

## Notes & Limitations

- This is a **demo / learning** project; detection rules are heuristic and intentionally noisy.
- Some hooks (clipboard, camera, microphone) depend on browser support and permissions.
- Behaviour may differ slightly across Chrome versions due to MV3 service worker lifecycle.

## Contributing

This repo is primarily for personal experimentation. Feel free to fork it and adapt it to your own needs.

## License

No explicit license is provided; treat this as personal learning material unless you add a license of your choice.
