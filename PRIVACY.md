# Privacy Policy for Vantage

**Last Updated:** September 18, 2026

## 1. Overview & Commitment

Vantage is committed to protecting your privacy. This Privacy Policy governs the Vantage browser extension (available for Mozilla Firefox and Chromium-based browsers) developed by Nick Peer ("developer", "we", "us").

**Our core privacy principle is simple: Vantage does not collect, track, transmit, monetize, or store any personal data, usage metrics, or browsing activity on any remote server.** 

Vantage is an open-source, client-side security assessment and reconnaissance tool designed to operate entirely within the confines of your local browser environment.

---

## 2. Information We Do NOT Collect

We do not collect, monitor, or log:
- **Personally Identifiable Information (PII)**: Names, email addresses, physical addresses, IP addresses, phone numbers, or credentials.
- **Browsing History & Activity**: URLs visited, tabs browsed, search queries executed, or time spent on websites.
- **Telemetry & Analytics**: Usage statistics, session recordings, device fingerprints, or crash telemetry.
- **Account Credentials & API Keys**: Any optional third-party API keys you enter (such as a personal Shodan API key) are stored solely on your local device. We never have access to your keys.

---

## 3. Local Data Storage (`browser.storage.local`)

Vantage utilizes your browser's local storage mechanism solely to persist preferences and user-created data for your convenience:
- **Custom Templates & Profiles**: User-defined search syntax configurations.
- **Audit Logs**: Exposure URLs and analyst notes that you explicitly choose to save to your local audit log.
- **Application Preferences**: Display settings (e.g., Guidance HUD toggle, verbatim mode).
- **Optional API Keys**: Personal Shodan API keys provided via "Bring Your Own Key" (BYOK).

**All locally stored data remains entirely on your machine.** It is never transmitted, synced, or backed up to any server operated by the developer. You can completely wipe this data at any time by clearing the extension's data in your browser settings, uninstalling the extension, or using the in-app "Reset" and "Delete All" controls.

---

## 4. Network Communications & Third-Party Telemetry

To perform passive attack surface discovery and reconnaissance, Vantage initiates client-side HTTPS requests directly from your browser to public, third-party internet telemetry services:
- **Certificate Transparency Logs** (`crt.sh`) — For discovering public SSL/TLS certificate domain records.
- **Public DNS over HTTPS (DoH)** (`dns.google`, `cloudflare-dns.com`) — For resolving standard DNS resource records (A, NS, MX, SOA, PTR).
- **Regional Internet Registries (RIRs)** (`whois.arin.net`, `rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`) — For retrieving public organization registration and IP CIDR netblocks.
- **OpenPGP Keyservers** (`keyserver.ubuntu.com`, `pgp.surf.nl`) — For querying public cryptographic key signatures associated with domain names (with secondary failover for large enterprises or keyserver downtime).
- **Host Intelligence** (`internetdb.shodan.io`, `api.shodan.io`) — For checking publicly indexed open ports and known CVE vulnerabilities.

These requests are standard, client-initiated HTTPS connections. They are governed by the respective privacy policies of those third-party providers. Vantage does not route these requests through any intermediary proxy or developer-controlled proxy server.

---

## 5. Third-Party Sharing & Sale of Data

Because we collect no data, **we do not sell, rent, trade, share, or disclose any user data or research findings to third parties or advertising networks.**

---

## 6. Permissions Justification

Vantage requests only the minimal permissions required to function as an in-browser reconnaissance suite:
- **`storage`**: To store user templates, audit logs, and settings locally on your machine.
- **`tabs`**: To capture the target domain from the active tab upon user click ("Current Tab" button) and open search tabs.
- **`contextMenus`**: To provide right-click options for saving URLs to your local audit log.
- **`host_permissions`**: Explicitly scoped to the public OSINT telemetry providers listed in Section 4.

---

## 7. Open Source Verification

Vantage is open-source software licensed under the MIT License. You can inspect the complete source code to independently verify our privacy practices at:  
[https://github.com/mrnickpeer/Vantage](https://github.com/mrnickpeer/Vantage)

---

## 8. Changes to This Privacy Policy

If this Privacy Policy is updated in future releases, changes will be documented in this file and posted to the official GitHub repository.

---

## 9. Contact & Inquiries

For questions or feedback regarding this Privacy Policy or Vantage's data practices, please open an issue on the official GitHub repository:  
[https://github.com/mrnickpeer/Vantage/issues](https://github.com/mrnickpeer/Vantage/issues)
