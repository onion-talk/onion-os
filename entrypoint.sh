#!/bin/sh
set -eu

umask 0077
ulimit -c 0 2>/dev/null || true

sha256sum -c /etc/onionos/manifest.sha256

# 1. Prepare volatile tmpfs & persistent vault directories prior to privilege drop
chmod 1777 /tmp 2>/dev/null || true
mkdir -p \
    /tmp/.X11-unix \
    /var/lib/tor/oniontalk_hs \
    /tor-cookie \
    /data/attachments \
    /data/relay \
    /vault \
    /home/onion/Documents \
    /home/onion/Downloads \
    /home/onion/OnionShare/Dropzone \
    /sandbox-home/.config/openbox \
    /run/onionos
chmod 1777 /tmp/.X11-unix 2>/dev/null || true

chown -R 10016:10016 /var/lib/tor /tor-cookie
chmod 0700 /var/lib/tor /var/lib/tor/oniontalk_hs
chmod 0750 /tor-cookie

cat <<'EOF' > /home/onion/README.txt
OnionOS 1.0.0 — Onion Mesh Sovereign Amnesic Tor & Post-Quantum Workstation
===========================================================================
- Tor 0.4.9.x PoW    : Equi-X anti-DoS defenses + Tor GeoIP telemetry enabled.
- OnionTalk v1.8.2   : P2P Messenger (:8420/:8080) + On-Demand Federated Relay (:8088).
- Netfilter UID Lock : Fail-closed; outbound WAN strictly restricted to UID 10016 (tor).
- 3-UID Isolation    : Tor (10016) | Browser Sandbox (10015) | Compositor & Vault (10014).
- Runtime Privileges : CapEff=0x0, CapBnd=0x0, NoNewPrivs=1 across all runtime daemons.
- Amnesic RAM Home   : /home/onion and /sandbox-home reside in volatile tmpfs (zero swap).
- Persistent Vault   : /vault encrypted via OTPQCV2 (ML-KEM-768 + X25519 + Dual AEAD).

Multicall CLI Utilities:
  onion-pqc {keygen|seal|open}         Post-Quantum hybrid keygen & .otseal envelopes
  onion-clean scrub <in> <out>         MAT2-grade EXIF/XMP/PDF/ID3 metadata scrubber
  onion-osint {validate|probe}         Tor v3 .onion checksum & isolated circuit probe
EOF

cat <<'EOF' > /sandbox-home/.config/openbox/rc.xml
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <applications>
    <application class="*">
      <maximized>true</maximized>
      <decor>no</decor>
    </application>
  </applications>
</openbox_config>
EOF

chown -R 10015:10015 /sandbox-home
chmod 0700 /sandbox-home

chown -R 10014:10014 /data /vault /home/onion
chmod 0700 /data /data/attachments /data/relay /vault /home/onion
chmod 0600 /home/onion/README.txt

# /run/onionos owned by root:root (0755) prevents UID 10014/10015 from unlinking/forging root flags
chown root:root /run/onionos
chmod 0755 /run/onionos
rm -f /run/onionos/netfilter.active /run/onionos/browser.token /tor-cookie/control_auth_cookie 2>/dev/null || true

# Generate 32-byte CSPRNG IPC token shared exclusively between UID 10014 and GID 10015
BROWSER_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "${BROWSER_TOKEN}" > /run/onionos/browser.token
chown 10014:10015 /run/onionos/browser.token
chmod 0640 /run/onionos/browser.token

# 2. Fail-Closed Kernel Netfilter (UID 10016 Tor-only WAN + strict --sport 8430 UI reply)
apply_ipv4_rules() {
    ipt_bin="$1"
    "$ipt_bin" -F OUTPUT &&
    "$ipt_bin" -P OUTPUT DROP &&
    "$ipt_bin" -A OUTPUT -o lo -j ACCEPT &&
    ( "$ipt_bin" -A OUTPUT -p tcp --sport 8430 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      "$ipt_bin" -A OUTPUT -p tcp --sport 8430 -m state --state ESTABLISHED,RELATED -j ACCEPT ) &&
    "$ipt_bin" -A OUTPUT -m owner --uid-owner 10016 -j ACCEPT &&
    "$ipt_bin" -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
}

apply_ipv6_rules() {
    ip6_bin="$1"
    "$ip6_bin" -F OUTPUT &&
    "$ip6_bin" -P OUTPUT DROP &&
    "$ip6_bin" -A OUTPUT -o lo -j ACCEPT &&
    "$ip6_bin" -A OUTPUT -j REJECT
}

IPV4_OK=0
if apply_ipv4_rules iptables 2>/dev/null; then
    IPV4_OK=1
elif command -v iptables-legacy >/dev/null 2>&1 && apply_ipv4_rules iptables-legacy 2>/dev/null; then
    IPV4_OK=1
fi

IPV6_OK=1
if [ -e /proc/net/if_inet6 ]; then
    IPV6_OK=0
    if apply_ipv6_rules ip6tables 2>/dev/null; then
        IPV6_OK=1
    elif command -v ip6tables-legacy >/dev/null 2>&1 && apply_ipv6_rules ip6tables-legacy 2>/dev/null; then
        IPV6_OK=1
    fi
fi

if [ "${IPV4_OK}" -eq 1 ] && [ "${IPV6_OK}" -eq 1 ]; then
    printf 'active\n' > /run/onionos/netfilter.active
    chown root:root /run/onionos/netfilter.active
    chmod 0444 /run/onionos/netfilter.active
else
    if [ "${ONIONOS_ALLOW_UNFILTERED_DEV:-0}" != "1" ]; then
        echo "FATAL: Kernel Netfilter (iptables/ip6tables) failed to initialize (IPV4_OK=${IPV4_OK}, IPV6_OK=${IPV6_OK}). Refusing fail-open startup." >&2
        exit 1
    fi
    echo "WARN: ONIONOS_ALLOW_UNFILTERED_DEV=1 set; starting without Netfilter enforcement." >&2
fi

# 3. Generate hardened Tor 0.4.9.x configuration (Equi-X PoW + GeoIP) & drop privileges to UID 10016
TORRC="/tmp/torrc"
cat <<'EOF' > "${TORRC}"
DataDirectory /var/lib/tor
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth IsolateClientAddr
DNSPort 127.0.0.1:5353
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFile /tor-cookie/control_auth_cookie
CookieAuthFileGroupReadable 1
ClientRejectInternalAddresses 1
AvoidDiskWrites 1
SafeLogging 1
ClientOnly 1
Log notice stderr
EOF

if [ -f /usr/share/tor/geoip ]; then
    printf 'GeoIPFile /usr/share/tor/geoip\n' >> "${TORRC}"
fi
if [ -f /usr/share/tor/geoip6 ]; then
    printf 'GeoIPv6File /usr/share/tor/geoip6\n' >> "${TORRC}"
fi

cat <<'EOF' >> "${TORRC}"
HiddenServiceDir /var/lib/tor/oniontalk_hs
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080
EOF

if tor --list-modules 2>/dev/null | grep -qi "pow: yes"; then
    printf 'HiddenServicePoWDefensesEnabled 1\n' >> "${TORRC}"
fi

chown 10016:10016 "${TORRC}"
chmod 0600 "${TORRC}"

setpriv \
    --reuid=10016 \
    --regid=10016 \
    --clear-groups \
    --inh-caps=-all \
    --bounding-set=-all \
    --no-new-privs \
    tor -f "${TORRC}" &

# Wait up to 5s for Tor control_auth_cookie & ephemeral HiddenService hostname
for _ in $(seq 1 50); do
    if [ -s /tor-cookie/control_auth_cookie ]; then
        break
    fi
    sleep 0.1
done

if [ -f /tor-cookie/control_auth_cookie ]; then
    chown 10016:10016 /tor-cookie/control_auth_cookie 2>/dev/null || true
    chmod 0640 /tor-cookie/control_auth_cookie 2>/dev/null || true
fi

if [ -s /var/lib/tor/oniontalk_hs/hostname ]; then
    cp /var/lib/tor/oniontalk_hs/hostname /data/hostname
    chown 10014:10014 /data/hostname
    chmod 0600 /data/hostname
fi

# 4. Launch isolated Browser Agent under UID 10015:10015 (zero access to /vault, /home/onion or /tor-cookie)
setpriv \
    --reuid=10015 \
    --regid=10015 \
    --clear-groups \
    --inh-caps=-all \
    --bounding-set=-all \
    --no-new-privs \
    env -i \
        PATH=/usr/local/bin:/usr/bin:/bin \
        HOME=/sandbox-home \
        USER=sandbox \
        ONIONOS_BROWSER_TOKEN_FILE=/run/onionos/browser.token \
        /usr/local/bin/onion-os browser-agent >/dev/null 2>&1 &

# 5. Launch embedded OnionTalk P2P Messenger v1.8.2-build75 on 127.0.0.1:8420 (relay :8080) under UID 10014
#    (`--clear-groups` + `env -i`: EXTERNAL_TOR=1 uses SOCKS5 :9050 + /data/hostname, zero access to /tor-cookie or browser.token)
if [ -x /usr/local/bin/oniontalk-node ]; then
    setpriv \
        --reuid=10014 \
        --regid=10014 \
        --clear-groups \
        --inh-caps=-all \
        --bounding-set=-all \
        --no-new-privs \
        env -i \
            PATH=/usr/local/bin:/usr/bin:/bin \
            HOME=/data \
            USER=onion \
            EXTERNAL_TOR=1 \
            PORT=8420 \
            ONIONTALK_WEB_PORT=8420 \
            ONIONTALK_RELAY_PORT=8080 \
            TOR_SOCKS_ADDR=127.0.0.1:9050 \
            TOR_SOCKS_PORT=9050 \
            ONIONTALK_DATA_DIR=/data \
            LOCAL_ONION_HOSTNAME_FILE=/data/hostname \
            /usr/local/bin/oniontalk-node >/dev/null 2>&1 &
fi

# 6. Irreversible capability & UID drop into OnionOS GNOME 47 Compositor (UID 10014, CapBnd=0)
export HOME="/home/onion"
export USER="onion"
export ONIONOS_STATIC_DIR="${ONIONOS_STATIC_DIR:-/usr/share/onionos/static}"
export ONIONOS_BROWSER_AGENT_URL="${ONIONOS_BROWSER_AGENT_URL:-http://127.0.0.1:6902}"
export ONIONOS_BROWSER_TOKEN_FILE="${ONIONOS_BROWSER_TOKEN_FILE:-/run/onionos/browser.token}"
export ONIONOS_RELAY_BIN="${ONIONOS_RELAY_BIN:-/usr/local/bin/oniontalk-relay-rs}"
export ONIONOS_RELAY_DATA_DIR="${ONIONOS_RELAY_DATA_DIR:-/data/relay}"
export ONIONOS_RELAY_BIND_PORT="${ONIONOS_RELAY_BIND_PORT:-8088}"

if [ "$#" -gt 0 ]; then
    exec setpriv \
        --reuid=10014 \
        --regid=10014 \
        --groups=10014,10016 \
        --inh-caps=-all \
        --bounding-set=-all \
        --no-new-privs \
        /usr/local/bin/onion-os "$@"
fi

exec setpriv \
    --reuid=10014 \
    --regid=10014 \
    --groups=10014,10016 \
    --inh-caps=-all \
    --bounding-set=-all \
    --no-new-privs \
    /usr/local/bin/onion-os serve
