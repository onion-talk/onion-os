# =============================================================================
# OnionOS v1.0.0 — Sovereign Consolidated Single-Container Linux Distribution
# Stage 1: Hardened Native Rust Builder (Full RELRO + NX Stack + Self-Test)
# =============================================================================
FROM rust:slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        binutils \
        cmake \
        build-essential \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY core/Cargo.toml core/Cargo.loc[k] /build/
COPY core/src /build/src

ENV RUSTFLAGS="-C link-arg=-Wl,-z,relro,-z,now -C link-arg=-Wl,-z,noexecstack"

RUN cargo build --release && \
    strip --strip-all /build/target/release/onion-os && \
    /build/target/release/onion-os --self-test && \
    mkdir -p /dist /usr/local/bin && \
    cp /build/target/release/onion-os /usr/local/bin/onion-os && \
    cp /usr/local/bin/onion-os /dist/onion-os && \
    sha256sum /usr/local/bin/onion-os > /dist/manifest.sha256

# =============================================================================
# Stage 2: Embedded OnionTalk P2P Post-Quantum Client (v1.8.1-build74 SHA-256)
# =============================================================================
FROM eriktonon/oniontalk-web:v1.8.1-build74@sha256:c8f81fe7475441e5e8c94a48204c03064b102dec1d726547761d62ac6968d735 AS oniontalk_bin

# =============================================================================
# Stage 3: Embedded OnionTalk Federated Relay Binary (v1.8.1 SHA-256)
# =============================================================================
FROM eriktonon/oniontalk-relay-rs:1.8.1@sha256:8af6943f1ffde9a8ed9d4d1b9a85fe7890b187ad05f81785189e482b7d6ce670 AS oniontalk_relay_bin

# =============================================================================
# Stage 4: Sovereign Debian Bookworm Runtime (Tor 0.4.9.x PoW + 3-UID + Onion Mesh)
# =============================================================================
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime

LABEL org.opencontainers.image.title="OnionOS 1.0.0 (Onion Mesh Sovereign Tor PQC Linux)" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="OnionTalk Project" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/onion-talk/onion-os" \
      org.opencontainers.image.description="Consolidated Amnesic Tor 0.4.9.x Equi-X PoW & Post-Quantum Linux Workstation (Onion Mesh Desktop, 3-UID Isolation, Netfilter Fail-Closed Lock, OnionTalk v1.8.1, On-Demand Federated Relay & OTPQCV2 Vault)"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg && \
    curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
        | gpg --dearmor -o /usr/share/keyrings/deb.torproject.org-keyring.gpg && \
    gpg --show-keys --with-colons /usr/share/keyrings/deb.torproject.org-keyring.gpg \
        | awk -F: '$1 == "pub" { pub_count++; want_fpr = 1; next } want_fpr && $1 == "fpr" { primary_fpr = $10; want_fpr = 0 } END { if (pub_count != 1 || primary_fpr != "A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89") exit 1 }' && \
    chmod 0644 /usr/share/keyrings/deb.torproject.org-keyring.gpg && \
    printf 'deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main\n' \
        > /etc/apt/sources.list.d/tor.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        tor \
        deb.torproject.org-keyring \
        tor-geoipdb \
        firefox-esr \
        xvfb \
        xauth \
        openbox \
        x11vnc \
        novnc \
        websockify \
        tini \
        iptables \
        util-linux \
        adwaita-icon-theme \
        fonts-cantarell \
        fonts-noto-core \
        torsocks \
        qrencode \
        jq \
        file \
        procps \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10016 oniontor && \
    useradd -u 10016 -g 10016 -d /var/lib/tor -s /usr/sbin/nologin oniontor && \
    groupadd -g 10015 sandbox && \
    useradd -u 10015 -g 10015 -d /sandbox-home -s /usr/sbin/nologin sandbox && \
    groupadd -g 10014 onion && \
    useradd -u 10014 -g 10014 -G 10016 -d /home/onion -s /bin/bash onion && \
    mkdir -p \
        /etc/onionos \
        /etc/profile.d \
        /etc/firefox-esr/policies \
        /usr/lib/firefox-esr/distribution \
        /usr/share/onionos/static \
        /usr/share/novnc \
        /var/lib/tor \
        /tor-cookie \
        /data/relay \
        /vault \
        /home/onion \
        /sandbox-home \
        /run/onionos && \
    printf '%s\n' \
        'NAME="OnionOS"' \
        'ID=onionos' \
        'ID_LIKE=debian' \
        'VERSION_ID="1.0.0"' \
        'VERSION="1.0.0 (Onion Mesh Sovereign)"' \
        'PRETTY_NAME="OnionOS 1.0.0 (Onion Mesh Sovereign Tor PQC Linux)"' \
        'HOME_URL="https://oniontalk.co"' > /etc/os-release && \
    printf '%s\n' \
        '==========================================================================' \
        '  OnionOS 1.0.0 — Onion Mesh Sovereign Amnesic Tor v3 & Post-Quantum Linux' \
        '  Tor Stack : Tor 0.4.9.x (Equi-X PoW) | OnionTalk v1.8.1 + Relay 1.8.1' \
        '  Netfilter : OUTPUT locked to lo + UID 10016 (oniontor) | CapBnd=0x0' \
        '  Workspace : /home/onion (RAM tmpfs, zero swap, core dumps disabled)' \
        '  CLI Suite : onion-pqc | onion-clean | onion-osint | gpg | qrencode' \
        '==========================================================================' > /etc/motd && \
    printf '%s\n' \
        'export PS1='\''onion@sovereign:\w\$ '\''' \
        'export ALL_PROXY="socks5h://127.0.0.1:9050"' \
        'export HTTPS_PROXY="socks5h://127.0.0.1:9050"' \
        'export HTTP_PROXY="socks5h://127.0.0.1:9050"' \
        'export NO_PROXY="127.0.0.1,localhost"' \
        'umask 0077' \
        'ulimit -c 0 2>/dev/null || true' > /etc/profile.d/onionos.sh && \
    printf '00000000000000000000000000000001\n' > /etc/machine-id && \
    printf '%s\n' \
        '<!DOCTYPE html>' \
        '<html lang="en"><head><meta charset="utf-8">' \
        '<meta http-equiv="refresh" content="0; url=vnc.html?autoconnect=true&amp;resize=scale&amp;reconnect=true&amp;path=sandbox/websockify">' \
        '<title>OnionOS Tor Browser Sandbox</title></head><body></body></html>' > /usr/share/novnc/index.html && \
    chmod 0444 /etc/os-release /etc/motd /etc/profile.d/onionos.sh /etc/machine-id /usr/share/novnc/index.html && \
    if [ -f /etc/tor/torsocks.conf ]; then \
        sed -i 's/^#*TorAddress.*/TorAddress 127.0.0.1/' /etc/tor/torsocks.conf && \
        sed -i 's/^#*TorPort.*/TorPort 9050/' /etc/tor/torsocks.conf; \
    fi

COPY --from=builder /dist/onion-os /usr/local/bin/onion-os
COPY --from=oniontalk_bin /usr/local/bin/oniontalk-node /usr/local/bin/oniontalk-node
COPY --from=oniontalk_relay_bin /usr/local/bin/oniontalk-relay-rs /usr/local/bin/oniontalk-relay-rs
COPY core/static /usr/share/onionos/static
COPY policies.json /usr/lib/firefox-esr/distribution/policies.json
COPY policies.json /etc/firefox-esr/policies/policies.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && \
    chown root:root \
        /usr/local/bin/onion-os \
        /usr/local/bin/oniontalk-node \
        /usr/local/bin/oniontalk-relay-rs \
        /usr/local/bin/entrypoint.sh \
        /usr/lib/firefox-esr/distribution/policies.json \
        /etc/firefox-esr/policies/policies.json && \
    chmod 0555 \
        /usr/local/bin/onion-os \
        /usr/local/bin/oniontalk-node \
        /usr/local/bin/oniontalk-relay-rs \
        /usr/local/bin/entrypoint.sh && \
    sha256sum \
        /usr/local/bin/onion-os \
        /usr/local/bin/oniontalk-node \
        /usr/local/bin/oniontalk-relay-rs > /etc/onionos/manifest.sha256 && \
    chown root:root /etc/onionos/manifest.sha256 && \
    chmod 0444 \
        /etc/onionos/manifest.sha256 \
        /usr/lib/firefox-esr/distribution/policies.json \
        /etc/firefox-esr/policies/policies.json && \
    ln -sf /usr/local/bin/onion-os /usr/local/bin/onion-pqc && \
    ln -sf /usr/local/bin/onion-os /usr/local/bin/onion-clean && \
    ln -sf /usr/local/bin/onion-os /usr/local/bin/onion-osint && \
    chown -R root:root /usr/share/onionos && \
    find /usr/share/onionos/static -type d -exec chmod 0555 {} + && \
    find /usr/share/onionos/static -type f -exec chmod 0444 {} + && \
    chown -R 10016:10016 /var/lib/tor /tor-cookie && \
    chmod 0700 /var/lib/tor && \
    chmod 0750 /tor-cookie && \
    chown -R 10015:10015 /sandbox-home && \
    chmod 0700 /sandbox-home && \
    chown -R 10014:10014 /data /vault /home/onion && \
    chmod 0700 /data /data/relay /vault /home/onion && \
    chown root:root /run/onionos && \
    chmod 0755 /run/onionos && \
    sha256sum -c /etc/onionos/manifest.sha256 && \
    /usr/local/bin/onion-os --self-test && \
    find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true && \
    rm -f /usr/bin/apt* /usr/bin/dpkg* /bin/su /usr/bin/su /usr/bin/passwd \
          /usr/bin/chsh /usr/bin/chfn /usr/bin/gpasswd /usr/bin/newgrp 2>/dev/null || true && \
    rm -rf /var/cache/apt/* /var/log/* /usr/share/doc/* /usr/share/man/* /usr/share/info/* /root/.gnupg

ENV ENV=/etc/profile.d/onionos.sh \
    BASH_ENV=/etc/profile.d/onionos.sh \
    HOME=/home/onion \
    USER=onion \
    ONIONOS_BIND_ADDR=0.0.0.0 \
    ONIONOS_BIND_PORT=8430 \
    ONIONOS_STATIC_DIR=/usr/share/onionos/static \
    ONIONOS_VAULT_DIR=/vault \
    ONIONOS_HOME_DIR=/home/onion \
    ONIONOS_NETFILTER_FLAG=/run/onionos/netfilter.active \
    ONIONOS_BROWSER_AGENT_URL=http://127.0.0.1:6902 \
    ONIONOS_BROWSER_TOKEN_FILE=/run/onionos/browser.token \
    ONIONOS_RELAY_BIN=/usr/local/bin/oniontalk-relay-rs \
    ONIONOS_RELAY_DATA_DIR=/data/relay \
    ONIONOS_RELAY_BIND_PORT=8088 \
    TOR_SOCKS_ADDR=127.0.0.1:9050 \
    TOR_CONTROL_ADDR=127.0.0.1:9051 \
    TOR_CONTROL_COOKIE_FILE=/tor-cookie/control_auth_cookie \
    TOR_COOKIE_FILE=/tor-cookie/control_auth_cookie \
    ONIONTALK_INTERNAL_URL=http://127.0.0.1:8420 \
    SANDBOX_BROWSER_URL=http://127.0.0.1:6901 \
    ALL_PROXY=socks5h://127.0.0.1:9050 \
    HTTPS_PROXY=socks5h://127.0.0.1:9050 \
    HTTP_PROXY=socks5h://127.0.0.1:9050 \
    NO_PROXY=127.0.0.1,localhost \
    MOZ_NO_REMOTE=1 \
    NO_AT_BRIDGE=1

WORKDIR /home/onion
VOLUME ["/vault"]
EXPOSE 8430

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/onion-os", "--healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
