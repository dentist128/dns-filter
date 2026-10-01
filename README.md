# DNS Filter

[![CI](https://github.com/dentist128/dns-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/dentist128/dns-filter/actions/workflows/ci.yml)
[![Release](https://github.com/dentist128/dns-filter/actions/workflows/release.yml/badge.svg)](https://github.com/dentist128/dns-filter/actions/workflows/release.yml)
[![GitHub release](https://img.shields.io/github/v/release/dentist128/dns-filter)](https://github.com/dentist128/dns-filter/releases)
[![GHCR image](https://img.shields.io/badge/image-ghcr.io/dns-filter-blue)](https://github.com/dentist128/dns-filter/pkgs/container/dns-filter)

A high-performance DNS proxy service with advanced filtering capabilities for DNS record types. Written in C with support for both IPv4 and IPv6.

## Features

- 🚀 **Lightweight & Fast** - Multi-threaded UDP DNS proxy
- 🔒 **Record Type Filtering** - Filter DNS responses by record type (A, AAAA, MX, NS)
- 🌐 **Dual Stack** - Full IPv4 and IPv6 support
- 🎯 **Pattern Matching** - Wildcard domain patterns for flexible routing
- ⚡ **Include/Exclude Modes** - Precise control over filtered record types
- 🔄 **Multiple Upstream Servers** - Automatic failover between DNS servers
- 🛡️ **Linux Capabilities** - Runs as unprivileged user with CAP_NET_BIND_SERVICE
- 📝 **Debug Mode** - Detailed logging for troubleshooting
- 🐳 **MikroTik Ready** - Distroless ARM64 container image with automated RouterOS deployment and updates

## Use Cases

- Block IPv6 AAAA records for specific domains
- Filter MX records to prevent email enumeration
- Route different domains to different DNS servers
- Create custom DNS filtering policies
- Optimize network by reducing unnecessary DNS record types

## Installation

### Prerequisites

- Linux system with systemd
- GCC compiler
- libcap (for capabilities support)
- make

### Quick Install

```bash
# Clone the repository
git clone https://github.com/dentist128/dns-filter.git
cd dns-filter

# Build and install (requires sudo)
make clean && make build
sudo make systemd-install

# Start the service
sudo make start

# Check status
make status
```

### Manual Build

```bash
# Build only
make build

# The binary will be in bin/dns_filter
```

## Running on MikroTik RouterOS (Container)

DNS Filter ships as a small distroless container image (~4 MB) that runs natively on
MikroTik devices with RouterOS 7.20+. The image is built for three architectures:

| Architecture | Devices | Release asset |
|---|---|---|
| `arm` (armv7, 32-bit) | RB4011, hAP ac², hAP ac³, CRS3xx | `dns-filter-armv7.tar` |
| `arm64` | hAP ax³, RB5009, CCR2116 | `dns-filter-arm64.tar` |
| `x86_64` | CHR | `dns-filter-amd64.tar` |

Check yours with `:put [/system/resource/get cpu-architecture]` (examples below use
`armv7` — substitute your architecture).

Prebuilt artifacts published by CI:
* `dns-filter-<arch>.tar` — image tarballs attached to every [release](https://github.com/dentist128/dns-filter/releases)
* `ghcr.io/dentist128/dns-filter` — multi-arch image in GitHub Container Registry

### Prerequisites

1. MikroTik device with RouterOS 7.20+ on `arm`, `arm64` or `x86_64` architecture
2. The `container` extra package — download it for your exact RouterOS version from
   [mikrotik.com/download](https://mikrotik.com/download) ("Extra packages") and upload it to the router
3. External storage recommended (examples below use `disk1`; adjust to your layout)

### 1. Enable container mode

```rsc
/system/device-mode/update container=yes
```

This requires confirmation with physical access to the device and reboots it.

### 2. Set up networking

```rsc
/interface/veth/add name=veth1
/interface/bridge/add name=containers
/interface/bridge/port/add bridge=containers interface=veth1
/ip/address/add address=172.17.0.1/24 interface=containers
```

RouterOS automatically runs a DHCP server for the veth network — the container will
get `172.17.0.2`. Make sure container traffic is masqueraded (most setups already cover
this with a generic src-nat rule; if not):

```rsc
/ip/firewall/nat/add chain=srcnat src-address=172.17.0.0/24 out-interface=<WAN> action=masquerade comment="containers egress"
```

Then either hand out `172.17.0.2` as the DNS server to your clients (via LAN DHCP or
`/ip/dns/set servers=172.17.0.2` if clients use the router as their DNS), or redirect
all outbound port-53 traffic to the container:

```rsc
/ip/firewall/nat/add chain=dstnat protocol=udp dst-port=53 src-address=192.168.88.0/24 action=dst-nat to-addresses=172.17.0.2 comment="redirect DNS to dns-filter"
```

### 3. Prepare the config mount

```rsc
/container/mounts/add list=MOUNT_DNSFILTER src=disk1/dns-filter/conf dst=/etc/dns-filter
```

The image ships with a default `dns_filter.conf` baked into `/etc/dns-filter`.
**On first start RouterOS copies it out to `disk1/dns-filter/conf/`** — from that
moment the router-side copy is the live config, editable on the router and preserved
across container updates (see below).

### 4. Add the container

**Option A — tarball from GitHub Releases (recommended, no registry auth):**

```rsc
/tool/fetch url=https://github.com/dentist128/dns-filter/releases/latest/download/dns-filter-armv7.tar dst-path=disk1/dns-filter/
/container/add name=dns-filter file=disk1/dns-filter/dns-filter-armv7.tar interface=veth1 root-dir=disk1/dns-filter/image mounts=MOUNT_DNSFILTER start-on-boot=yes logging=yes
```

(For an ARM64 device use `dns-filter-arm64.tar`, for CHR — `dns-filter-amd64.tar`.)

**Option B — pull from GHCR (multi-arch manifest, RouterOS picks the right architecture):**

```rsc
/container/config/set registry-url=https://ghcr.io tmpdir=disk1/tmp
/container/add name=dns-filter remote-image=ghcr.io/dentist128/dns-filter:latest interface=veth1 root-dir=disk1/dns-filter/image mounts=MOUNT_DNSFILTER start-on-boot=yes logging=yes
```

> **Note:** the GHCR package is created private by the first CI push — flip it to
> public in *Package settings → Danger Zone → Change visibility*. The exact
> `registry-url`/`remote-image` combination varies slightly between RouterOS
> versions: if the pull fails, try removing the `ghcr.io/` prefix from
> `remote-image`. If it still refuses to authenticate, use Option A.

### 5. Verify

```rsc
/container/print
```

The first start spends a while in the `extracting` state (image unpacking). Once the
container is `running`, from any LAN host:

```
dig @172.17.0.2 example.com
dig @172.17.0.2 AAAA auto.ru
```

### Replacing the config

The config is read once at process startup — there is no hot-reload (no SIGHUP
handler), so changes are applied with a container restart:

```rsc
/container/stop dns-filter
:while ([/container/print/count-only where name="dns-filter" stopping]) do={:delay 1s}
/container/start dns-filter
```

**Edit on the router:** open `disk1/dns-filter/conf/dns_filter.conf` in Winbox
(*Files*), or push a new one from your machine, then restart as above. The mount
guarantees the file survives container recreation and image updates.

**Fetch from a URL:** the runtime image is distroless (no shell, no curl/wget),
so the download happens on the router side — fetch the config straight into the
mounted directory and restart. This is handy for keeping the config in a gist,
a private HTTP endpoint, or another git repo:

```rsc
/tool/fetch url="https://example.com/dns_filter.conf" dst-path=disk1/dns-filter/conf/dns_filter.conf
```

To sync the config from a URL periodically, put the same fetch + restart into a
scheduled script:

```rsc
/system/script/add name=dns-filter-sync-conf source={
    :local confUrl "https://example.com/dns_filter.conf"
    /tool/fetch url=$confUrl dst-path=disk1/dns-filter/conf/dns_filter.conf
    /container/stop dns-filter
    :while ([/container/print/count-only where name="dns-filter" stopping]) do={:delay 1s}
    /container/start dns-filter
}
/system/scheduler/add name=dns-filter-sync-conf interval=1h on-event="/system/script/run dns-filter-sync-conf"
```

### Automatic updates

Every release publishes a `version.txt` marker alongside the tarball. The update
script compares it with the running version (kept in the container's `comment`
field) and only redownloads when a new release is out:

```rsc
/system/script/add name=dns-filter-update source={
    :local repo "dentist128/dns-filter"
    :local name "dns-filter"
    :local dir  "disk1/dns-filter"

    # temporary fallback resolver while the container is being recreated
    /ip/dns/set servers=1.1.1.1

    /tool/fetch url="https://github.com/$repo/releases/latest/download/version.txt" dst-path="$dir/version.txt"
    :local new [/file/get "$dir/version.txt" contents]
    :local cur [/container/get [find name=$name] comment]

    :if ($new != $cur) do={
        :log info "dns-filter: updating $cur -> $new"
        /tool/fetch url="https://github.com/$repo/releases/latest/download/dns-filter-armv7.tar" dst-path="$dir/dns-filter-armv7.tar"
        /container/stop $name
        :while ([/container/print/count-only where name=$name stopping]) do={:delay 1s}
        /container/remove $name
        :delay 5s
        /container/add name=$name file="$dir/dns-filter-armv7.tar" interface=veth1 \
            root-dir="$dir/image" mounts=MOUNT_DNSFILTER start-on-boot=yes logging=yes comment=$new
        :while ([/container/print/count-only where name=$name extracting]) do={:delay 2s}
        /container/start $name
        :log info "dns-filter: updated to $new"
    }

    # back to the local filter
    /ip/dns/set servers=172.17.0.2
}
/system/scheduler/add name=dns-filter-update interval=24h start-time=04:17:00 on-event="/system/script/run dns-filter-update"
```

For Option B (GHCR) on RouterOS 7.20+ the update is a one-liner — `/container/repull`
re-pulls the image and re-extracts it in place, keeping the container entry, mounts
and config:

```rsc
/container/repull dns-filter
```

To track version tags instead of the mutable `latest` tag, point `remote-image` at
the new tag — the same script pattern applies, replacing the tarball download with
`/container/set [find name="dns-filter"] remote-image=ghcr.io/dentist128/dns-filter:v1.2.3`
(the pull starts automatically; use `latest` with `repull` for the simplest setup).

### RouterOS troubleshooting

* **Container exits with "Failed to create IPv4 socket: Permission denied"** —
  the process could not bind UDP/53. The image runs as root for exactly this
  reason (RouterOS does not grant `CAP_NET_BIND_SERVICE` to non-root
  containers). If you overrode the user (`user=`), remove the override;
  alternatively rebind clients to a translated port.
* **First start is slow** — the image tarball is being extracted; watch the
  `extracting` flag in `/container/print`.
* **Logs** — with `logging=yes` container stdout goes to the system log:
  `/log/print where topics~"container"`.
* **`repull` leaves stray files in the root dir** — known cosmetic 7.20.x bug,
  harmless.
* **`import error: fetch config failed: architecture mismatch`** — the image
  architecture does not match the device. Check the device architecture with
  `:put [/system/resource/get cpu-architecture]` and use the matching tarball
  (`armv7` / `arm64` / `amd64`). For GHCR pulls this should not happen — the
  multi-arch manifest resolves per device.
* **Truncated DNS answers** — the proxy handles UDP payloads up to 512 bytes only
  (no EDNS0/TCP); this is a proxy limitation, not a RouterOS issue.

## Configuration

Edit `/etc/dns-filter/dns_filter.conf` (or `dns_filter.conf` in the source directory):

### Syntax

```
# Enable debug logging
debug

# Default upstream DNS servers
default: 8.8.8.8 8.8.4.4

# Routing rules
rule: <pattern> -> <filter> -> <upstream_servers>
```

### Filter Types

- `*` - All record types (no filtering)
- `ipv4` - Only A records
- `ipv6` - Only AAAA records
- `mx` - Only MX records
- `ns` - Only NS records
- Multiple types: `ipv4 ipv6` - Only A and AAAA records
- Exclusions: `!ipv6` - All except AAAA records
- Multiple exclusions: `!ipv6 !mx` - All except AAAA and MX

**Note:** Cannot mix include and exclude modes (e.g., `ipv4 !ipv6` is invalid)

### Configuration Examples

```conf
# Enable debugging
debug

# Block IPv6 for auto.ru
rule: *auto.ru -> ipv4 -> 8.8.8.8

# Only IPv4 and IPv6 (no MX, NS, etc.)
rule: *example.com -> ipv4 ipv6 -> 8.8.8.8

# Everything except IPv6 for VK
rule: *vk.* -> !ipv6 -> 77.88.8.8

# Everything except IPv6 and MX for Yandex
rule: *yandex.ru -> !ipv6 !mx -> 77.88.8.8

# Only MX records for mail domains
rule: mail.* -> mx -> 8.8.8.8

# All records for .ru domains with multiple servers
rule: *.ru -> * -> 8.8.8.8 1.1.1.1

# IPv6 upstream servers
rule: *.google.com -> * -> 2001:4860:4860::8888

# Default fallback
default: 8.8.8.8 8.8.4.4
```

## Usage

### Service Management

```bash
# Start the service
sudo systemctl start dns-filter

# Stop the service
sudo systemctl stop dns-filter

# Restart the service
sudo systemctl restart dns-filter

# Enable autostart on boot
sudo systemctl enable dns-filter

# Check status
sudo systemctl status dns-filter

# View logs
sudo journalctl -u dns-filter -f
```

### Make Commands

```bash
make build            # Compile the binary
make install          # Install with capabilities
make systemd-install  # Full installation with systemd
make start            # Start the service
make stop             # Stop the service
make restart          # Restart the service
make status           # Show service status
make logs             # Show recent logs
make logs-follow      # Follow logs in real-time
make check-cap        # Check capabilities
make help             # Show all available commands
```

### Testing

```bash
# Test IPv4
dig @127.0.0.1 example.com

# Test IPv6
dig @::1 example.com

# Test with specific record type
dig @127.0.0.1 AAAA example.com

# Check if filtering works
dig @127.0.0.1 A auto.ru      # Should return A records
dig @127.0.0.1 AAAA auto.ru   # Should be filtered (if configured)
```

## Security

### Linux Capabilities

The service uses `CAP_NET_BIND_SERVICE` capability to bind to port 53 without running as root:

```bash
# Check current capabilities
getcap /usr/local/bin/dns_filter

# Should show: cap_net_bind_service+ep
```

### Systemd Hardening

The systemd service includes security features:
- Runs as unprivileged user `dns-filter`
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- Capability bounding set limited to `CAP_NET_BIND_SERVICE`

## Troubleshooting

### Permission Denied on Port 53

```bash
# Ensure capabilities are set
sudo make install
make check-cap

# If systemd-resolved is using port 53
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

### IPv6 Not Working

```bash
# Check if IPv6 socket is bound
sudo ss -tulpn | grep :53

# Should show both 0.0.0.0:53 and [::]:53
```

### Debug Mode

Enable debug mode in config:
```conf
debug
```

Then view detailed logs:
```bash
sudo journalctl -u dns-filter -f
```

## Architecture

```
Client (IPv4/IPv6)
       ↓
DNS Filter (0.0.0.0:53 + [::]:53)
       ↓
  Pattern Matching
       ↓
  Record Type Filtering
       ↓
Upstream DNS Servers
```

## Performance

- Multi-threaded query handling
- Non-blocking I/O with select()
- Minimal memory footprint (~2MB RSS)
- Low latency overhead (<5ms)

## License

This project is licensed under the GNU General Public License v3.0 - see below for details.

```
DNS Filter - A DNS proxy service with record type filtering
Copyright (C) 2026 Markelov Eduard

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

## Author

**Markelov Eduard**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built with standard C libraries
- Uses POSIX threads for concurrency
- Systemd integration for service management

## TODO

- [ ] DNS-over-TLS (DoT) support
- [ ] DNS-over-HTTPS (DoH) support
- [ ] Cache support
- [ ] Statistics endpoint
- [ ] Web UI for configuration
- [ ] Support for DNSSEC

## FAQ

**Q: Can I use this as my primary DNS server?**
A: Yes, configure your system's DNS to `127.0.0.1` after starting the service.

**Q: Does it support DNS caching?**
A: Not yet, but it's on the TODO list.

**Q: Can I filter other record types?**
A: Currently supports A, AAAA, MX, NS. More types can be added easily.

**Q: What about performance impact?**
A: Minimal - the filtering adds less than 5ms latency per query.

**Q: Is it production-ready?**
A: It's stable for personal/small-scale use. Test thoroughly before production deployment.

---

⭐ If you find this project useful, please consider giving it a star on GitHub!
