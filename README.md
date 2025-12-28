# CodeVault Main

This repository contains a small demo application built around a browser extension and a companion test site. It is meant as a sandbox for experimenting with content scripts, background scripts, and simple redirect rules.

## Project Structure

- `extension/` – Source code for the browser extension
  - `manifest.json` – Extension manifest and permissions
  - `background.js` – Background/service worker logic
  - `content.js` – Content script injected into pages
  - `rules.js` – Helper logic for rules / filtering
- `test-site/` – Local HTML pages used to exercise and debug the extension
  - `index.html` – Main test page
  - `redirect.html` – Redirect target page
  - `script.js` – Front‑end logic for the test page
  - `spam.js` – Additional script for spam / blocking scenarios
- `INTERVIEW_PREP.md` – Notes and preparation material for interview practice

## Getting Started

### 1. Clone or download

If you have not already, clone this repository:

```bash
git clone https://github.com/notaaaaaaa/codevaultmain.git
cd codevaultmain
```

If you are working locally already (for example from a ZIP), you can ignore the clone step and just open the folder in VS Code.

### 2. Load the extension in Chrome

1. Open **chrome://extensions** in Google Chrome.
2. Enable **Developer mode** (top‑right toggle).
3. Click **Load unpacked**.
4. Select the `extension/` folder from this project.
5. The extension should appear in your extensions list.

### 3. Open the test site

You can open the test pages directly from the file system:

1. In your browser, use **File → Open File** (or press `Ctrl+O`).
2. Navigate to the `test-site/` folder inside this project.
3. Open `index.html`.

Alternatively, you can serve the folder with a simple HTTP server (for example, using `npx serve` or `python -m http.server`) and then navigate to `http://localhost:PORT/index.html`.

## Development

- Make changes to files in the `extension/` or `test-site/` folders.
- After changing extension code, refresh the extension from **chrome://extensions** using the **Reload** button.
- Use the browser devtools (F12) on both the test site and the extension’s background/content scripts for debugging.

## Contributing

This repo is primarily for personal experimentation and interview preparation. Feel free to fork it and adapt it to your own needs.

## License

No explicit license is provided; treat this as personal learning material unless you add a license of your choice.
