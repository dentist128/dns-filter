# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DNS Filter is a lightweight DNS proxy written in C that filters DNS responses by record type (A, AAAA, MX, NS). It listens on both IPv4 (`0.0.0.0:53`) and IPv6 (`[::]:53`) and forwards queries to upstream servers after applying pattern-matched filtering rules.

## Build Commands

```bash
make build            # Compile the binary to bin/dns_filter
make clean            # Remove the bin/ directory

# Installation (requires sudo)
sudo make systemd-install   # Full install: binary + config + systemd service
sudo make install           # Binary + config + CAP_NET_BIND_SERVICE capability only

# Local debug run (no systemd)
make debug            # Builds and runs locally with debug flag prepended to config

# Service management
make start / stop / restart / status
make logs / logs-follow
make check-cap        # Verify CAP_NET_BIND_SERVICE is set on the binary
```

## Build Configuration

- **Compiler**: `gcc` with `-Wall -Wextra -std=c99 -O2 -pthread -static`
- **Single source file**: `dns_filter.c` → `bin/dns_filter`
- **Static binary**: `-static` flag means the binary has no runtime dependencies
- **Docker**: Multi-stage build — compiles in `debian:12`, copies static binary into `distroless/static-debian12`. Runs as UID 1000, exposes UDP/53. Layout mirrors the systemd install: binary at `/usr/local/bin/dns_filter`, `WORKDIR /etc/dns-filter` with `dns_filter.conf` in it. `/etc/dns-filter` is the bind-mount point for RouterOS (`/container/mounts ... dst=/etc/dns-filter`); on RouterOS the default config gets copied out to the router-side `src` dir on first start.

## CI/CD (GitHub Actions)

- `ci.yml` — matrix over three architectures: amd64 and arm64 natively (`ubuntu-latest`, `ubuntu-24.04-arm` — ARM runners are free for public repos), armv7 via QEMU emulation. Each job: `make build` (native jobs) + `docker buildx build --platform …` + dig smoke test; pushes `:master-<arch>` edge images to GHCR on pushes to master.
- `release.yml` — triggered by pushing a `v*.*.*` tag. Three jobs:
  - `images` — one multi-arch `buildx --push` (amd64+arm64+arm/v7) publishing `X.Y.Z`/`X.Y`/`latest` manifest lists to `ghcr.io/dentist128/dns-filter` (RouterOS resolves the manifest per device, like docker.io).
  - `tarballs` — per-arch `docker save` exports: `dns-filter-armv7.tar`, `dns-filter-arm64.tar`, `dns-filter-amd64.tar` (+ `.sha256`), uploaded as artifacts.
  - `release` — changelog from git log since the previous tag, GitHub Release with all tarballs + `version.txt`, and commits an updated `CHANGELOG.md` back to the default branch (`[skip ci]` marker).
- Release flow: `git tag v1.2.3 && git push origin v1.2.3`.
- Target device is **armv7** (32-bit ARM MikroTik) — the README scripts use `dns-filter-armv7.tar`.
- RouterOS-side update scripts live in README.md ("Automatic updates") — they compare `version.txt` from the latest release against the container's `comment` field.

## Architecture

All logic lives in `dns_filter.c`. Key data structures and flow:

```
TypeFilter  — which record types to include/exclude (ipv4, ipv6, mx, ns, all, exclude flag)
DnsRule     — pattern + TypeFilter + list of upstream server IPs
DnsConfig   — global: array of DnsRule, default servers, debug flag (g_config)
QueryContext — per-query heap struct passed to a detached pthread
```

**Request flow:**
1. `main()` uses `select()` on two sockets (sock4/sock6) with a 1-second timeout loop
2. Each incoming UDP packet is copied into a heap-allocated `QueryContext` and dispatched to a detached `pthread`
3. `handle_query()` extracts the domain name, finds the first matching `DnsRule` by wildcard pattern, forwards the raw DNS packet to an upstream server via `forward_query()`, then calls `filter_dns_response()` to strip unwanted answer records before sending the response back to the client
4. Graceful shutdown via SIGINT/SIGTERM: sets `shutdown_flag`, breaks the select loop, waits 5 seconds for in-flight threads, then `cleanup()` closes sockets

**Config loading**: `load_config()` reads `dns_filter.conf` from the working directory (or `/etc/dns-filter/` when installed). The service's `WorkingDirectory` is `/etc/dns-filter`.

**Pattern matching** (`domain_matches`): supports a single `*` wildcard. Patterns are matched case-insensitively. First matching rule wins.

**Filter logic** (`filter_dns_response`): walks DNS answer RRs in-place, copying only records that pass the filter into a local buffer, then patches the answer count field.

## Configuration Syntax

```
# comment
debug                         # enable debug logging

default: <ip> [<ip> ...]      # fallback upstream servers

rule: <pattern> -> <filter> -> <ip> [<ip> ...]
```

Filter values: `*`, `ipv4`, `ipv6`, `mx`, `ns`, combinations like `ipv4 ipv6`, or exclusions like `!ipv6 !mx`. Cannot mix include and exclude in one filter.

## Testing

```bash
# After starting the service or make debug:
dig @127.0.0.1 example.com
dig @127.0.0.1 AAAA example.com
dig @::1 example.com
```

## Key Constraints

- `BUFFER_SIZE` is 512 bytes — DNS responses larger than 512 bytes (EDNS0/TCP) are not handled
- Max 100 rules (`MAX_RULES`) and 10 upstream servers per rule (`MAX_SERVERS`)
- CNAME records are never filtered (hardcoded pass-through in `should_filter_type`)
- The binary reads config from the **current working directory** (`dns_filter.conf`) unless the process is started from `/etc/dns-filter/`
- `resolve_server()` uses a `static` buffer — not thread-safe if multiple threads resolve hostnames simultaneously; upstream IPs should be numeric addresses in config to avoid this
