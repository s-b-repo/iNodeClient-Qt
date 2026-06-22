# Protocol implementation status & roadmap

## 802.1X (iNode port id 8021) — ✅ working

Implemented in `src/protocols/Dot1xProtocol.cpp` as a thin wrapper around `minieap` (or `mentohust` as fallback). Both are open-source community reimplementations of the HC-CHAPv2 variant that H3C's `libInodeX1Pt.so` speaks.

The wrapper exposes the full knob set the original client offers through its "Advanced" panel:
- auth mode (PAP / CHAP / MSCHAPv2 / EAP-MD5 / EAP-PEAP / HC-CHAPv2)
- rjv3 on/off, service type, carrier string
- heartbeat (`-r` for minieap, `-t` for mentohust)
- arbitrary extra args (free-form) — useful for the campus-specific flags some iMC builds require

**IP addressing:** 802.1X only authenticates the port — the supplicant brings no
address of its own. The profile's *IP mode* (Advanced tab) is applied right after
auth succeeds: **Inherit** leaves the OS as-is, **DHCP** triggers a renew, and
**Static** programs the address / netmask / gateway / DNS via the privileged
`inode-ipcfg-helper` (polkit `org.inode.ClientQt.ipcfg`). It is torn down on
disconnect. The same applies to WLAN (which wraps the 802.1X plugin).

**Known limitations:**
- Campus deployments with custom iNode hash salts may require passing extra `--rjv3` flags through *Extra args*. Capture a successful auth from the original client and compare if the default profile doesn't work.
- `libInodeX1Pt.so` also implements H3C's "智能感知" (smart re-auth) heartbeat — `minieap` covers it for the common case, but some server builds expect a client-hello frame minieap doesn't send.

## WLAN (iNode port id 1100) — ✅ working

Wireless 802.1X in `src/protocols/WlanProtocol.cpp`:

1. `nmcli device wifi connect <ssid> password <pw> ifname <iface>` — hands association to NetworkManager, which is the only supplicant that plays nicely with WPA3/802.11w on modern distros.
2. Once associated, the Dot1x plugin runs the same 802.1X flow as the wired case on the now-connected `wlanX` interface.

If the profile's SSID field is empty, the plugin falls back to plain 802.1X (useful for pre-associated setups).

## L2TP/IPSec (port 2401) — ✅ working against RFC-compliant servers

Uses system `strongswan` + `xl2tpd`. The GUI writes fragment configs under `/etc/ipsec.conf.d/` and `/etc/xl2tpd/xl2tpd.conf.d/` through the polkit helper (`scripts/inode-l2tp-helper`). `forceencaps=yes` can be toggled per-profile for concentrators that always require UDP encap on 4500. The PSK and password are streamed to the helper on **stdin** (`--secrets-stdin`), never passed as command-line arguments, so they never appear in `ps`/`/proc`.

**Where it won't work:** iMC/EIA deployments that require H3C's proprietary IKE vendor ID exchange or custom phase-2 transforms. Those need custom strongswan plugin work or a userspace IKE implementation — not trivial, but out of scope here.

## Portal v2 — ✅ working

Implemented natively in `src/protocols/PortalProtocol.cpp`. Full state machine: REQ_CHALLENGE → ACK_CHALLENGE → REQ_AUTH → ACK_AUTH → AFF_ACK_AUTH, plus a timer-driven keep-alive and REQ_LOGOUT on disconnect. MD5-keyed checksum uses the per-profile shared secret (defaults to `h3c` if unset).

Each iMC Portal deployment ships with:
- a shared secret (typical defaults: `h3c`, `huawei3com`, `portalsecret`),
- a UDP port (2000 is default; some deployments use 50100),
- a dialect switch (v2 vs H3C-TLV).

The **v2 standard** dialect is on the wire here. The **H3C TLV** dialect is now wired up experimentally — see below.

## H3C Portal (TLV dialect) — 🧪 experimental

**Wire protocol reference:** `libInodePortalPt.so` in the original client. H3C's Portal extends the GB/T 28181 Portal standard with proprietary TLVs.

**Status.** `PortalProtocol::sendAuth()` now appends the documented H3C TLV(s) when `profile.portalDialect == 1` — currently the **user-mac** attribute (type `0x0A`), taken from the profile's interface. This is **best-effort and untested against a live H3C Portal** (we have none): some deployments also need `0x0F` (challenge-type), `0x13` (auth-vlan) and a checksum variant, whose exact layout requires a packet capture from the original client.

**To finish for a specific deployment:**

1. Capture a successful auth from the original client. Expect UDP to port 50100 plus optional HTTP redirects.
2. Confirm the extra attribute types/values and the checksum variant, then extend `sendAuth()` accordingly.
3. Some H3C builds change the shared secret to an iMC-generated string (check `custom/clientfiles/5020/*.icnf`).

## SSL VPN (port 7000) — ✅ working (via the bundled `h3csvpn` backend)

**Wire protocol reference:** `libiNodeSslvpnPt.so` (SslVpnXmlParser.cpp, SslvpnMgr.cpp, HttpsAuth.cpp) in the unstripped Linux iNode 7.3 client. The protocol was reverse-engineered first-hand and is **not** the speculative `POST /svpn/login` JSON flow earlier guessed here — it is XML-over-HTTPS ("V7").

**How it's implemented.** Rather than re-deriving the wire format in C++, `SslVpnProtocol` drives a bundled clean-room backend — the pure-Python `h3csvpn` package under `backends/h3csvpn/` — exactly as the 802.1X plugin wraps `minieap` and the L2TP plugin wraps `strongswan`. The backend was reverse-engineered from the binary above and validated end-to-end against a live `SSLVPN-Gateway/7.0`.

Flow (`backends/h3csvpn`; full spec in `docs/PROTOCOL.md` of the h3c-svpn source tree):

1. *(optional SPA knock)* → TLS → `GET /svpn/index.cgi` → **302 → `/client_getinfo.cgi`**; parse the `gatewayinfo` (capability flags `true`/`false`, CGI URLs in a `<url>` block, domain list).
2. *(optional CAPTCHA)* `GET /vldimg.cgi` → BMP; the backend OCR-solves it (`tesseract`) and auto-retries against the server's reply oracle.
3. `POST <login.cgi>` body `request=` + URL-encoded `<data>` login XML (username `user@domain`, password cleartext-in-TLS by default, or RSA/SM2 variants) → challenge/2FA loop (SMS, PROMPTPWD, CHANGEPWD), kick-concurrent-session, optional EAD ack.
4. `NET_EXTEND` on a fresh TLS socket → network-config block → program a TUN device + routes + DNS → raw IP packets in 4-byte frames with a 1 s heartbeat → `GET /svpn/logout.cgi` on teardown. The live `SSLVPN-Gateway/7.0` returns the param block in the **HTTP response headers** (`IPADDRESS`/`SUBNETMASK`/`ROUTES`/`GATEWAY`, with `Content-Length: 0`), and `SUBNETMASK` is a prefix length (e.g. `24` = `/24`); the backend parses both that header form and the older body/frame forms.

**Split tunnel (enterprise).** By default the client routes only the subnets the gateway pushes (`ROUTES`) through the VPN and leaves the host default route + system DNS untouched, so general internet traffic is unaffected. The per-profile *Split tunnel* toggle (CLI `--split-tunnel`) enforces this even if a gateway requests redirect-all. The test gateway used during development pushes specific corporate subnets and no DNS, so it is naturally split. Verified end-to-end: with the tunnel up, the host default route and `/etc/resolv.conf` are unchanged, public internet stays reachable directly, and the corporate subnets are reachable through `inode0`.

**Integration plumbing.** Because the tunnel needs `CAP_NET_ADMIN`, the GUI launches the backend through `scripts/inode-svpn-helper` via `pkexec` (polkit action `org.inode.ClientQt.svpn`), or directly if already root. The password is streamed on the helper's **stdin** (never in argv/`ps`); `PYTHONSAFEPATH=1` pins module resolution to the vendored backend. `disconnect()` runs `inode-svpn-helper stop`, which `SIGINT`s the backend for a clean gateway logout + TUN teardown. The Qt layer parses backend output to drive connection state and live stats (interface / IP / DNS).

**Profile mapping.** `serverHost[:serverPort]` (or the SSL VPN *Gateway URL*) → gateway; `username`/`domain` → `-u`/`-d`; trust mode → system CA (default) / `--cafile` (Pinned, from `caCertPath`) / `--insecure` (None); a per-profile **SHA-256 cert pin** (with a one-click *Fetch* button) → `--pin-sha256`, which **overrides** the trust mode — the correct, secure way to trust a self-signed gateway whose cert CN doesn't match the host (so a CA bundle can't validate it); `userCertPath` → mutual-TLS client cert.

**Runtime deps:** `python3` (stdlib only for the core), `tesseract` for CAPTCHA OCR, `pkexec`/polkit for the tunnel. Optional `python3-defusedxml` (hardened XML) and `python3-cryptography` (RSA password variant).

**Limitations (inherited from the backend):** GM/SM2 (CNTLS / SKF UKey) gateways are TLS-layer-only (unsupported); Zero-Trust SDP registration that issues the per-client SPA key is out of scope (only the knock builder exists).

## EAD (port 9019) — 🧪 host-check ack done; standalone posture *forgeable* (not yet built)

**Wire protocol reference:** `libInodeSecurityAuth.so` (`CreatePkt` @0x45cd0, `VerifyPkt` @0x44450, `PushSecurityResult` @0x46250).

**What works now.** The **SSL VPN EAD host-check acknowledgement** — tick *“Send EAD host-check acknowledgement after login”* on an SSL VPN profile (backend `--ead`); the client posts the host-check result after authentication. Verified against the live `SSLVPN-Gateway/7.0` (auth still succeeds with it on). Note: the original client sends this only on the legacy **V3** path and skips it on V7, so it is usually a no-op on modern gateways — harmless either way.

**Standalone iMC EAD posture (UDP/9019) — revised verdict: not crypto-blocked.** Earlier this doc said the posture blob was signed by a key inside the closed collector and was unreproducible. Reverse-engineering `libInodeSecurityAuth.so` shows that is **wrong**: the SEC posture packet carries **no RSA/HMAC/SHA signature**. It is sealed only by:

- a **RADIUS-style keyed-MD5** over (packet with a zeroed 16-byte checksum field at `+0x6` ‖ seed), with the **hardcoded** seed string `SC-EAD_Server$REQ&ShareKey@9019` (DIF/917T transport variant: `DIF-SERVER$RPT&CheckSum@917T`); and
- an optional **static XTEA** body cipher (Δ `0x9E3779B9`, 32 rounds, ECB) with the **hardcoded** key `g_arruiKey = {0x95632125, 0x74256318, 0x36752015, 0x67825319}` (`.data` @0x2df8d0).

> Both seals are **constant across all clients and sessions** (recovered from `libInodeSecurityAuth.so`). **Correction:** `libwacollector.so` is OPSWAT's **OESIS V4** collector, and the RSA/AES/cert material embedded in it is for OPSWAT's *own* module/cache integrity — it is **not** used to sign the H3C posture report. So there is no vendor signing key gating this at all.

Both seals are constant across all clients/sessions (no per-session derivation), so a clean-room client can build a valid `SEC_CHECK_RESULT` the server accepts. The 28-byte SEC header is `ulPktHeadId u32 · usPktHeadLen u16 · checkSum[16] @+6 · … · body @0x1c`; the body is an XML envelope of `<i n="field">value</i>` items (result fields `PMcheckResult/AVexception/FWcheckResult/HDcheckResult/passwordCheckResult/screenSaverResult/…` plus identity/asset fields). Flow is `SEC_START(1) → server SEC_CHECK_LIST(2) → SEC_CHECK_RESULT(3) → SUCCESS(4)/FAIL(6) → ACL_REQUEST(97) → HEARTBEAT(17)/MONITOR(7)`. So the remaining work is **transcribing the `<i n="…">` result-field set into a passing `SEC_CHECK_RESULT` and walking the handshake** — not breaking crypto, and no OPSWAT engine needed for a forgery. A dummy "compliant" posture is implementable; it is just not built yet (and we have no iMC EIA server to test against). The standalone `EadProtocol` reports this and points at the SSL VPN host-check above.

## SDP (port 19006) — 🧪 experimental (SPA knock + SSL VPN)

SDP (software-defined perimeter) is, in H3C's stack, an **SSL VPN preceded by a Single-Packet-Authorization (SPA) knock** that opens the otherwise-closed gateway port. That is now wired up: an **SDP** profile (or any SSL VPN profile with the *SPA key/AID/ports* filled in) sends the RFC-4226-HOTP knock — `backends/h3csvpn/spa.py`, validated 47-byte packet — before the TLS/auth flow (`--spa-key/--spa-aid/--spa-ports/--spa-knock-port`).

Verified against `libZeroTrust.so` (`onKnockUDPMsg` @0x22630): packet is `declaredLen=0x0110` · `aid[32]` · `pktID=bswap(rand)` · `password[6]` (HMAC-SHA1 HOTP, 5 digits + Luhn check) · `portCount=len(ports)` · ports (htons); knock is fire-and-forget UDP. Ports: register 19006, knock 59993, gateway-knock 8000. Our builder matches byte-for-byte (the earlier `portCount=(n//2)+1` guess is fixed to `len(ports)`).

**Out of scope:** the SDP **registration** that mints the per-client `clientKey`/`aid`. Per the binary it is **not** a dedicated `/register` call — it rides on the first auth: `POST https://<gw>/api/terminal/pc/userLogin` with JSON `{userAccount, userPassword, clientSn, clientMac, clientOsType}`; the response carries `clientAid`/`clientKey` (cached in `/etc/spa/spa_cfg.cnf` as `SdpAid-<ip>`/`SdpKey-<ip>`). Reproducible structurally but needs valid gateway credentials — supply the AID/key from an enrolled client.
