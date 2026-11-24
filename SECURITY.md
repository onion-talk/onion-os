# Security Policy: OnionOS (`onion-os`)

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` (`main`) | Yes |

## Security Architecture & Invariants

During container bootstrap, `entrypoint.sh` installs fail-closed `iptables` and `ip6tables` `OUTPUT` rules allowing external packets strictly from `--uid-owner 10016` (`oniontor`) before dropping `CAP_NET_ADMIN` and clearing the capability bounding set (`CapBnd=0x0`, `NoNewPrivs=1`). If Netfilter initialization fails, container startup aborts immediately rather than running unfiltered.

Runtime workloads are partitioned across three unprivileged Linux UIDs inside the read-only container: `UID 10016` (`oniontor`) runs the Tor `0.4.9.x` daemon with Equi-X PoW (`pow: yes`); `UID 10015` (`sandbox`) runs the on-demand `Xvfb` (`-nolisten tcp -auth .Xauthority`, `0600`), `Firefox ESR`, `x11vnc` (`-localhost`), and `noVNC` stack with zero filesystem access to `/vault`, `/home/onion`, `/data`, or `/tor-cookie`; and `UID 10014` (`onion`) runs the `onion-os` compositor, `oniontalk-node`, and on-demand `oniontalk-relay-rs` (`127.0.0.1:8088`).

Persistent artifacts under `/vault/*.otpqcv2` use `Argon2id (19 MiB)` + `SHAKE256` key derivation with `NIST FIPS 203 ML-KEM-768` + `X25519` hybrid key encapsulation, Dual-AEAD (`ChaCha20-Poly1305` + `AES-256-GCM`), and `Ed25519` transcript signatures. Ephemeral workspaces reside in `tmpfs` with swap disabled (`memswap_limit == mem_limit`), core dumps disabled (`PR_SET_DUMPABLE=0`), and all web assets served locally under `default-src 'self'` with zero external CDNs or telemetry endpoints.

## Reporting a Vulnerability

Do not open public GitHub issues for undisclosed security vulnerabilities. Instead, report security findings privately through GitHub Private Vulnerability Reporting (`Security -> Advisories -> Report a vulnerability` on `onion-talk/onion-os`) or through the official OnionTalk channels listed at [https://oniontalk.co](https://oniontalk.co). Please include reproduction steps, impact assessment, and the affected component (`core/src/*`, `entrypoint.sh`, `Dockerfile`, or `policies.json`).
