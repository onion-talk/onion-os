# OnionOS v1.0.0: System & Cryptographic Architecture

## 1. Design Overview

**OnionOS (`onion-os`)** packages a self-contained, amnesic Linux privacy workstation inside a single read-only Debian Bookworm OCI container (`< 95 MiB` idle RAM). Instead of running a multi-container bridge topology or streaming an always-on remote X11 desktop, OnionOS runs a native Rust HTTP/WebSocket compositor (`onion-os`, `UID 10014`) serving a zero-dependency **Onion Mesh** multi-window desktop shell (`default-src 'self'`, `0` external CDNs) strictly on host loopback (`127.0.0.1:8430`).

All external network traffic flows through **Tor `0.4.9.17`** compiled with **Equi-X Proof-of-Work (`pow: yes`)** anti-DoS defenses (`UID 10016`), which is the sole UID permitted by kernel Netfilter to transmit non-loopback packets. Within `UID 10014`, OnionOS embeds **OnionTalk Web (`v1.8.2-build75`)** (`ENVELOPE_V3`, `ML-KEM-768`, 18-gateway Dual-Ring Rendezvous, 1x ephemeral media, and `OnionVoice`) alongside an on-demand **OnionTalk Federated Relay (`oniontalk-relay-rs:1.8.2`)** (`127.0.0.1:8088`). For `.onion` and web reconnaissance, an airgapped **Tor Browser Sandbox** (`UID 10015`: `Xvfb` + `Openbox` + `Firefox ESR 153.x` + `x11vnc` + `noVNC`) remains suspended at `0 MiB` RAM until started by the operator.

---

## 2. Intra-Container 3-UID Privilege Separation & Netfilter Lock

During container initialization (`entrypoint.sh`), root privileges are used strictly once to verify `/etc/onionos/manifest.sha256`, prepare isolated `tmpfs` mount permissions, and install fail-closed `iptables` and `ip6tables` rules. The IPv4 and IPv6 `OUTPUT` chains accept loopback traffic (`-o lo`), allow established HTTP/WebSocket UI replies on `--sport 8430` (`-m conntrack --ctstate ESTABLISHED,RELATED`), allow outbound Tor circuit packets strictly from `-m owner --uid-owner 10016` (`oniontor`), and reject every other packet so `UID 10014` and `UID 10015` cannot emit clearnet traffic even under process compromise.

If either IPv4 or IPv6 Netfilter lock fails, `entrypoint.sh` aborts startup immediately (*fail-closed*). Every runtime daemon is then spawned via `setpriv --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs` (`CapEff=0x0`, `CapBnd=0x0`, `NoNewPrivs=1`).

| UID / GID | User | Processes | Accessible Paths | Outbound Network |
| :--- | :--- | :--- | :--- | :--- |
| `10016:10016` | `oniontor` | `tor` (`127.0.0.1:9050` SOCKS5h, `:9051` ControlPort) | `/var/lib/tor` (`0700`), `/tor-cookie` (`0750`) | Authorized WAN (`--uid-owner 10016`) |
| `10015:10015` | `sandbox` | `onion-os browser-agent` (`127.0.0.1:6902`), on-demand `Xvfb`, `Firefox ESR`, `noVNC` (`:6901`) | `/sandbox-home` (`0700` volatile `tmpfs`) | Blocked (SOCKS5h `127.0.0.1:9050` only) |
| `10014:10014` | `onion` | `onion-os` (`:8430`), `oniontalk-node` (`:8420`/`:8080`), on-demand `oniontalk-relay-rs` (`:8088`) | `/home/onion` (`tmpfs`), `/data` (`tmpfs`), `/vault` (`0700`) | Blocked (SOCKS5h `:9050` & Control `:9051` only) |

---

## 3. Post-Quantum Cryptographic Storage (`OTPQCV2`)

All persistent files written under `/vault` (`vault.otpqcv2`, `files.otpqcv2`, `relay.otpqcv2`) use authenticated post-quantum hybrid encryption. Operator passphrases are stretched with `Argon2id` (`m = 19,456 KiB`, `t = 2`, `p = 1`) and a 256-bit CSPRNG salt, then expanded via `SHAKE256` into deterministic `NIST FIPS 203 ML-KEM-768` (`Kyber-768`), `X25519`, and `Ed25519` keypairs.

Every write generates a fresh random encapsulation (`ML-KEM-768` shared secret `ss_pqc` || `X25519` ECDH shared secret `ss_ecdh`), derives independent cipher keys via `SHAKE256` with explicit domain separation (`OTPQCV2-VAULT`, `OTPQCV2-FILES-V2`, `OTPQCV2-RELAY-V21`), encrypts the payload with `ChaCha20-Poly1305` (inner) followed by `AES-256-GCM` (outer), and signs the header + ciphertext transcript with `Ed25519`. At runtime, `PR_SET_DUMPABLE=0` and `ulimit -c 0` block core dumps and `ptrace`, `memswap_limit == mem_limit` prevents host swap paging, and `POST /api/system/panic-burn` zeroes active session keys, kills child process groups (`SIGKILL`), revokes active ephemeral `.onion` services (`DEL_ONION`), rotates Tor circuits (`SIGNAL NEWNYM`), and overwrites volatile files with CSPRNG bytes before unlinking.

---

## 4. Loopback HTTP & WebSocket API Summary (`127.0.0.1:8430`)

All state-changing routes enforce `Host` loopback validation (DNS-rebinding guard), canonical `Origin == Host` verification, `HttpOnly; SameSite=Strict` session cookies (`onionos_sid`), and constant-time `X-OnionOS-Token` CSRF tokens.

| Surface | Method & Path | Description |
| :--- | :--- | :--- |
| **Health & Auth** | `GET /api/health` | Runtime liveness, lock state, Tor SOCKS5h reachability, Browser & Relay state |
| **Health & Auth** | `GET /api/auth/status`, `POST /api/auth/unlock`, `POST /api/auth/lock` | `OTPQCV2` vault initialization, Argon2id session unlock, and immediate RAM lock + service teardown |
| **System** | `GET /api/system/telemetry`, `GET /api/system/monitor` | `/proc` RSS telemetry, `CapEff`/`CapBnd`/`NoNewPrivs`/`Netfilter` audit, and process list |
| **System** | `GET\|POST /api/system/settings`, `POST /api/system/panic-burn` | `Onion Mesh` theme & auto-lock persistence; emergency RAM/Vault shred + `DEL_ONION` + `NEWNYM` |
| **Vault & TOTP** | `GET\|POST /api/vault/items`, `DELETE /api/vault/items/{id}` | Encrypted secret CRUD (`totpSecret` never returned in list responses) |
| **Vault & TOTP** | `GET /api/totp/codes`, `POST /api/totp/preview`, `POST /api/qr/svg` | Live RFC 6238 6-digit TOTP codes and offline SVG QR generation |
| **PQC & Forensics** | `POST /api/pqc/{seal,open,generate-secret}` | Hybrid `ML-KEM-768 + X25519` `.otseal` envelopes and CSPRNG secret generator |
| **PQC & Forensics** | `POST /api/forensics/scrub`, `GET /api/forensics/audit` | In-RAM metadata stripping (`JPEG`, `PNG`, `PDF`, `WAV`, `MP3`) and anti-forensic posture audit |
| **Dual-Root Files** | `GET /api/files/{list,read}`, `POST /api/files/{mkdir,write,delete,action}` | Dual-root file manager across volatile `ram:/` (`/home/onion`) and encrypted `vault:/` (`files.otpqcv2`) |
| **OnionShare** | `GET /api/onionshare/status`, `POST /api/onionshare/{start,stop}` | Ephemeral `ADD_ONION NEW:ED25519-V3` file share & anonymous dead-drop upload service |
| **Federated Relay** | `GET /api/relay/status`, `POST /api/relay/{start,stop,voucher}` | On-demand `oniontalk-relay-rs` (`127.0.0.1:8088`, RAM or `/vault/relay.otpqcv2`) & `otnode1:` vouchers |
| **Tor & OSINT** | `GET /api/tor/circuits`, `POST /api/tor/newnym`, `POST /api/osint/{validate-onion,probe}` | Tor circuit map, `SIGNAL NEWNYM`, `.onion` v3 SHA3-256 checksum validator & isolated SOCKS5h probe |
| **Browser & Shell** | `GET /api/browser/status`, `POST /api/browser/{start,stop}`, `GET /api/pty/ws` | On-demand Firefox ESR sandbox lifecycle (`UID 10015`) and multi-tab WebSocket Linux PTY shell |
| **App Proxies** | `ANY /ot/{*path}`, `ANY /sandbox/{*path}` | Authenticated loopback reverse proxies for OnionTalk Web (`:8420`) and noVNC Tor Browser (`:6901`) |
