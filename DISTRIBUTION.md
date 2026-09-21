# Vantage - Distribution & Store Submission Guide

This guide details how to publish **Vantage** to the **Firefox Add-ons Portal (AMO)** and the **Chrome Web Store (CWS)**, as well as how to test unpacked builds locally.

---

## 📦 Generated Packages

The automated build pipeline produces store-ready zip archives inside the `dist/` directory:

| Store | File / Path | Format | Notes |
| :--- | :--- | :--- | :--- |
| **Firefox Add-ons (AMO)** | `dist/vantage-firefox-v1.1.3.zip` | ZIP archive | Manifest V3 with `background.scripts` & Gecko ID |
| **Chrome Web Store (CWS)** | `dist/vantage-chrome-v1.1.3.zip` | ZIP archive | Manifest V3 with `background.service_worker` |
| **Microsoft Edge Add-ons** | `dist/vantage-chrome-v1.1.3.zip` | ZIP archive | Same Chromium Manifest V3 bundle as CWS |
| **Firefox Unpacked** | `dist/firefox/` | Directory | For temporary testing in Firefox |
| **Chrome / Edge Unpacked** | `dist/chrome/` | Directory | For "Load unpacked" in Chrome/Brave/Edge |

> **Rebuilding Packages:** Whenever code changes are made, run:
> ```bash
> npm run build
> # or
> node build.js
> ```

---

## 🦊 1. Firefox Add-ons Portal (AMO) Submission

### Step-by-Step Submission:
1. Log in to the [Firefox Add-on Developer Hub](https://addons.mozilla.org/developers/).
2. Click **"Submit a New Add-on"**.
3. Choose **"On this site"** (to distribute via Mozilla's directory) or "On your own" (self-hosted signed XPI).
4. When prompted to upload your add-on file, upload:
   `dist/vantage-firefox-v1.1.3.zip`
5. The AMO automated validator will run. Because all assets are plain, unminified JavaScript with zero remote code execution, it will pass initial validation.
6. Provide listing metadata:
   - **Name:** `Vantage`
   - **Summary:** `Passive attack surface reconnaissance, corporate infrastructure mapping, and exposure audit suite.`
   - **Categories:** `Web Development`, `Security & Privacy`
7. Submit for review (typically approved within 2–24 hours).

---

## 🌐 2. Chrome Web Store (CWS) Submission

### Step-by-Step Submission:
1. Log in to the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole).
2. Click **"New Item"** in the top right (or edit existing item draft).
3. Drag and drop:
   `dist/vantage-chrome-v1.1.3.zip`
4. Fill in the Store Listing tabs:
   - **Product Name:** `Vantage`
   - **Summary Description (<=132 chars):**  
     `Passive attack surface reconnaissance, corporate infrastructure mapping, and exposure audit suite.`
   - **Category:** `Developer Tools` or `Productivity`
   - **Icon:** Upload `icons/icon-128.png`.
   - **Privacy Policy URL:** `https://github.com/mrnickpeer/Vantage/blob/main/PRIVACY.md`
   - **Screenshots:** Provide at least one 1280x800 or 640x400 screenshot of the Vantage dashboard in action.

---

## 🌊 3. Microsoft Edge Add-ons Store Submission

Microsoft Edge runs on the Chromium engine and natively accepts the **Chrome Web Store Manifest V3 zip bundle**.

### Step-by-Step Submission:
1. Log in to the [Microsoft Partner Center Dashboard](https://partner.microsoft.com/dashboard/microsoftedge).
2. Click **"Create new extension"**.
3. When prompted to upload the extension package, upload:
   `dist/vantage-chrome-v1.1.3.zip` (for Vantage) or `dist/visage-chrome-v1.0.1.zip` (for Visage).
   *(Do NOT upload the Firefox zip, as Edge requires `background.service_worker` rather than `background.scripts`)*.
4. Complete the Store Listing:
   - **Extension Name:** `Vantage` (or `Visage`)
   - **Short Description:** Same concise description used for CWS.
   - **Store Logo:** Upload `icons/icon-300.png` (Edge strictly requires a **300x300 PNG** store logo).
   - **Extension Icon:** Upload `icons/icon-128.png`.
   - **Screenshots:** At least one 1280x800 or 640x400 PNG/JPEG.
   - **Privacy Policy URL:** Link to the GitHub `PRIVACY.md`.
5. Under **"Notes for certification"**, paste the permission justification and testing notes (see below).
6. Submit for certification (typically approved within 24–48 hours).

---

## 🛡️ Store Review: Permission Justifications

Both stores (especially Chrome) require a short justification for each requested permission in the Privacy tab. Use these exact descriptions:

- **`storage`**:  
  *Used to locally persist user dork templates, custom search profiles, analyst audit logs, and optional user-provided Shodan API keys. No data is transmitted to external servers.*
- **`tabs`**:  
  *Used to allow the analyst to extract the current target domain from the active tab via the "Current Tab" button and switch to existing Vantage dashboard tabs.*
- **`contextMenus`**:  
  *Adds right-click options ("Send Link to Vantage Audit Log", "Send Current Page to Vantage Audit Log") so researchers can catalog discovered exposure URLs directly into their local audit log.*
- **`host_permissions`**:  
  *Required to perform passive, client-side queries against public OSINT telemetry sources: Certificate Transparency logs (`crt.sh`), public DNS over HTTPS (`dns.google`, `cloudflare-dns.com`), regional internet registries (`whois.arin.net`, `rdap.arin.net`, `rest.db.ripe.net`, `rdap.db.ripe.net`, `rdap.apnic.net`), OpenPGP keyservers (`keyserver.ubuntu.com`, `pgp.surf.nl`), and IP host intelligence (`internetdb.shodan.io`, `api.shodan.io`).*

> **Note on File Downloads:**  
> Vantage does **not** request the `downloads` permission. Markdown audit reports and JSON backups are exported entirely client-side using standard HTML5 `Blob` and `<a download>` object URLs within the extension page context, strictly adhering to the Principle of Least Privilege.

---

## 🧪 Local Testing Instructions

### Testing in Firefox:
1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click **"Load Temporary Add-on..."**.
3. Select `dist/firefox/manifest.json` (or `manifest.json` in the root).
4. Click the extension icon in the toolbar or context menu to open Vantage.

### Testing in Chrome / Brave / Edge:
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **"Developer mode"** (toggle in top right).
3. Click **"Load unpacked"** (top left).
4. Select the folder: `dist/chrome/`.
5. Vantage will appear in your extensions list and toolbar!
