# DNS Filter

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
