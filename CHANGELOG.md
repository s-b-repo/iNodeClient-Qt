# Changelog

All notable changes to the iNode Client (Qt edition) are documented here.
This project loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — 2026-06-22

Audit pass over the UI/protocol layer: wired up controls that were collected but
ignored, fixed a credential-exposure issue, and corrected misleading labels.

### Added
- **Portable secure credential storage.** Added a freedesktop **Secret Service**
  backend (libsecret, `dlopen`'d at runtime — no build dependency) tried after
  KWallet and before the obfuscated fallback. This gives real keyring-backed
  storage on GNOME / XFCE / Cinnamon / most non-KDE distros (gnome-keyring,
  ksecretd, KeePassXC, …), so the "fallback storage" warning only appears when
  no keyring exists at all. Verified end-to-end (store/lookup round-trip) against
  a live `org.freedesktop.secrets` daemon.
- **Former stubs wired up (best-effort).**
  - **EAD host-check ack** — SSL VPN profiles gained a *“Send EAD host-check
    acknowledgement after login”* toggle (backend `--ead`). **Verified live**:
    auth still succeeds against `SSLVPN-Gateway/7.0` with it on. (Reverse-
    engineering `libInodeSecurityAuth.so` revised the standalone iMC posture
    verdict: it is **not** crypto-blocked — the UDP/9019 SEC packet is sealed
    only by a hardcoded keyed-MD5 seed `SC-EAD_Server$REQ&ShareKey@9019` and a
    static XTEA key, both recovered — and the OPSWAT collector does not sign the
    report at all — so a dummy posture is *feasible*; the
    remaining work is the result schema + SEC state machine, not breaking crypto.
    `EadProtocol`/docs now say so. Not yet built; no iMC server to test against.)
  - **SDP** — now a selectable protocol = SSL VPN preceded by a Single-Packet-
    Authorization knock. SPA *key / AID / ports* fields on the profile drive the
    RFC-4226-HOTP knock (`--spa-key/--spa-aid/--spa-ports/--spa-knock-port`;
    47-byte packet builder validated). The SDP *registration* that mints the
    per-client key/AID remains out of scope — supply them from an enrolled client.
  - **H3C Portal TLV dialect** — no longer rejected; `PortalProtocol::sendAuth()`
    appends the documented H3C **user-mac** TLV (`0x0A`) when the profile's
    dialect is *H3C TLV*. Best-effort and **untested against a live H3C Portal**;
    other TLVs need a packet capture to finalise.
- **GUI redesign.** A single **Connect ⇄ Disconnect** button that morphs and
  recolours with state; a **live connection panel** (replacing the separate
  badge / status-bar label / stats strip) showing IP, gateway, interface,
  uptime and live **↓↑ throughput with a sparkline**, plus an indeterminate
  progress bar while connecting; a **custom list delegate** rendering each
  profile as a state-dot + bold name + dim username/server subtitle + a
  right-aligned protocol pill; and **keyboard shortcuts** (Enter = connect the
  selected profile, Delete = remove).
- **GUI polish.** A **right-click context menu** on profiles (Connect /
  Disconnect / Edit / **Duplicate** / Remove), a **show/hide password** toggle in
  the profile editor, and a friendly empty-state hint when there are no profiles.
- **SSL VPN SHA-256 certificate pin in the GUI.** New per-profile *"Cert pin
  (SHA-256)"* field with a one-click **Fetch** button (reads the gateway's
  fingerprint via `openssl`). When set it passes `--pin-sha256` and overrides the
  trust mode. This is the secure way to trust a self-signed gateway whose cert CN
  doesn't match the host — previously only the CLI could do this, so the GUI
  failed such gateways with `CERTIFICATE_VERIFY_FAILED` on the default System-CA
  trust (the live `SSLVPN-Gateway/7.0` cert is `CN=HTTPS-Self-Signed-…`, no SAN).
- **SSL VPN split tunnel (enterprise).** New `--split-tunnel` backend flag and a
  per-profile *"Split tunnel"* checkbox (on by default). Only the gateway's own
  subnets are routed through the VPN; the host default route and system resolver
  are left untouched, so general internet traffic keeps using the physical link.
  **Verified end-to-end** against a live `SSLVPN-Gateway/7.0`: tunnel up on
  `inode0`, only the gateway's pushed corporate subnets routed, the host default
  route + `/etc/resolv.conf` left untouched, public HTTPS still reachable
  directly, and a corporate host reachable through the tunnel.
- **Modern "Mullvad" dark theme**, now the default. Deep-navy surfaces, flat
  rounded controls, a green *Connect* CTA / red *Disconnect* CTA, and a
  colour-coded connection-status badge that tracks state. Selectable alongside
  the existing themes in *Preferences → Theme*.
- **Static IP configuration is now applied** for 802.1X / WLAN profiles. The
  per-profile *IP mode* (Inherit / DHCP / Static) and the Static IP / netmask /
  gateway / DNS fields under *Advanced* were previously collected and persisted
  but never used. They are now programmed onto the interface after
  authentication and torn down on disconnect:
  - **Inherit** — no change (no extra privilege prompt)
  - **DHCP** — runs the existing DHCP renew path
  - **Static** — sets `ip addr` + default route and writes DNS to
    `/etc/resolv.conf` (original backed up, restored on disconnect)
  - New privileged helper `scripts/inode-ipcfg-helper`, polkit action
    `org.inode.ClientQt.ipcfg`, driven by `core/IpConfigurator`.

### Changed
- **SPA knock `portCount` corrected.** Reverse-engineering `libZeroTrust.so`
  (`onKnockUDPMsg`) confirmed `portCount = len(ports)`; the previous `(n//2)+1`
  guess was wrong for 3+ knock ports (1–2 port cases were unaffected). Also
  documented the verified SDP registration (rides on `pc/userLogin`, not a
  dedicated `/register` endpoint).
- **SSL VPN is no longer mislabeled a "stub".** The protocol dropdown now reads
  "SSL VPN" (was "SSL VPN (stub)") and the in-app *About* box lists it under
  *Working*. The protocol was already fully implemented via the bundled
  `h3csvpn` backend — only the UI strings were stale.
- **L2TP/IPSec credentials no longer reach the command line.** The PSK and
  password are streamed to `inode-l2tp-helper` on stdin (`--secrets-stdin`)
  instead of being passed as argv, so they no longer appear in `ps`/`/proc`.
  (The helper still accepts `--psk`/`--password` for manual CLI use.)
- **L2TP/IPSec privilege launch hardened.** Runs the helper directly when root,
  else `pkexec`, else `sudo -n` — so a missing polkit agent or TTY fails fast
  instead of blocking the UI. The helper wait is now bounded (≤120 s) rather
  than unbounded.

### Fixed
- **Auto-reconnect no longer hammers permanent failures.** A failed connection
  caused by a bad certificate, wrong credentials, an exhausted CAPTCHA, or an
  unsupported protocol is no longer retried on a timer (it would never succeed);
  only unexpected drops of a previously-working session trigger a reconnect.
- **SSL VPN tunnel now actually establishes.** The live `SSLVPN-Gateway/7.0`
  returns the tunnel's network-config block in the `NET_EXTEND` *HTTP response
  headers* (`IPADDRESS`/`SUBNETMASK`/`ROUTES`/`GATEWAY`, `Content-Length: 0`).
  The backend only looked for it in the body and so failed with "did not receive
  a valid network-config frame"; it now parses the header form too.
- **`SUBNETMASK` as a prefix length is handled.** This gateway sends
  `SUBNETMASK: 24` (i.e. `/24`); the mask→prefix helper previously treated `24`
  as dotted-decimal and computed `/2`. A bare integer is now read as the prefix.
- **CAPTCHA solver needs far fewer retries.** Glyphs are isolated by colour +
  connected components (so two same-coloured glyphs no longer merge and force a
  wasted refetch), OCR'd with multi-render majority voting, and a best-effort
  4-char guess is now submitted on every round-trip instead of spinning on
  low-confidence refetches. When glyphs can't be cleanly isolated it now falls
  back to a whole-image OCR guess instead of returning nothing, and the GUI asks
  the backend for a generous retry budget (`--captcha-retries 40`) so success is
  near-certain (each attempt is a cheap round-trip the server adjudicates).
  (The gateway's noisy bitmap font still defeats tesseract on individual glyphs;
  a trained classifier is possible future work.)
- **"Store password" checkbox is now honored.** Previously a password typed into
  the profile editor was stored regardless of the checkbox. Unchecking it now
  removes any stored credential; checking it stores the password, overwriting
  only when a new one is actually entered.

### Known limitations
- The profile **Service** field is still collected but unused — none of the
  supported open backends (minieap / strongSwan / Portal / h3csvpn) accept a
  service / display-name parameter, so wiring it would be guesswork that could
  break auth.
- L2TP connect is bounded but still synchronous (a brief UI pause during
  `ipsec up`); a fully asynchronous flow is a possible follow-up.
