# Contributing to OnionOS (`onion-os`)

OnionOS is an open-source (MIT) single-container amnesic Tor v3 and post-quantum Linux workstation built in Rust (`core/`) and packaged on `debian:bookworm-slim`. Contributions, security reviews, bug reports, and pull requests are welcome.

## 1. Local Development & Testing

### Prerequisites
- **Rust** `1.80+` (`stable` toolchain via `rustup`)
- **Docker Engine** `24+` & **Docker Compose v2** (`docker compose`)

### Running the Rust Compositor & Cryptography Test Suite
All vault (`OTPQCV2` Argon2id + ML-KEM-768 + Dual AEAD), RFC 6238 TOTP, offline SVG QR, metadata scrubbing, OSINT validator, and relay controller tests run natively without Docker:

```bash
cargo check --manifest-path core/Cargo.toml --all-targets
cargo test --manifest-path core/Cargo.toml
```

### Building & Launching the Full Container Locally
```bash
docker compose build onion-os
docker run --rm --entrypoint /usr/local/bin/onion-os eriktonon/onion-os:1.0.0 --self-test
docker compose up -d
```
Once healthy, open `http://127.0.0.1:8430` in your local browser.

## 2. Non-Negotiable Security Invariants

Every pull request is automatically verified by CI (`.github/workflows/ci.yml`) against these rules:
1. **3-UID Isolation & Fail-Closed Netfilter (`entrypoint.sh`)**: Outbound non-loopback packets are restricted to `UID 10016` (`oniontor`). `UID 10014` (`onion`) and `UID 10015` (`sandbox`) run with `CapEff=0x0`, `CapBnd=0x0`, and `NoNewPrivs=1`.
2. **Pure LF Shell Scripts**: `entrypoint.sh` must use Unix `LF` (`\n`) line endings only (`sh -n entrypoint.sh`).
3. **Zero External CDNs (`default-src 'self'`)**: All UI scripts, icons, and stylesheets in `core/static/` must be self-hosted with zero external font, script, or telemetry requests.
4. **Zero Unpatched CVEs (`OSV.dev` Gate)**: Both `core/Cargo.lock` (`crates.io`) and `/var/lib/dpkg/status` (`Debian:12`) are audited against `https://api.osv.dev/v1/querybatch` on every push and pull request.
5. **Immutable Base Digests**: Multi-stage `FROM` directives in `Dockerfile` must pin `@sha256` digests.

## 3. Submitting a Pull Request

1. Fork `https://github.com/onion-talk/onion-os` and create a topic branch from `main` (`feat/<topic>` or `fix/<topic>`).
2. Run `cargo test --manifest-path core/Cargo.toml` and verify `sh -n entrypoint.sh`.
3. Open a Pull Request against `main` describing what changed, why, and how it was tested.
4. For undisclosed security vulnerabilities, follow [SECURITY.md](./SECURITY.md) rather than opening a public issue.

## License

By contributing to `onion-talk/onion-os`, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
