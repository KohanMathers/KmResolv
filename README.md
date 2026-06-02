# kmresolv
A self-hosted recursive DNS resolver with ad/tracker filtering, a web dashboard, and an optional Minecraft server.

## Features
- **Recursive resolution** — resolves DNS queries from the root, with configurable depth and EDNS0 support
- **DNSSEC validation** — full chain validation (DNSKEY → DS → RRSIG) from the IANA root KSK; bogus responses return SERVFAIL, secure responses carry the AD bit
- **Per-domain forwarding** — forward specific zones to specific upstreams (e.g. `internal` → your AD DNS), with longest-suffix matching
- **DoT / DoH forwarders** — upstream servers can be plain UDP, `tls://` (DNS-over-TLS), or `https://` (DNS-over-HTTPS)
- **Response cache** — TTL-aware sharded cache with negative caching, background prefetch, configurable min TTL, and an optional max-size cap with soonest-to-expire eviction
- **TCP fallback** — retries truncated UDP responses over TCP automatically
- **Rate limiting** — per-source-IP token bucket to protect against noisy clients and accidental open resolver exposure
- **Access control** — subnet-based allow/deny ACL (first-match-wins) with a configurable default action
- **Filtering** — blacklist or whitelist mode; loads inline domains and remote/local host-format lists (e.g. StevenBlack/hosts); reloads on SIGHUP or on a configurable interval
- **Local records** — define custom DNS records in config (all standard types through RFC 9460, wildcard names supported) for your home network
- **Web dashboard** — query log, stats, block/unblock and record management, cache controls, and a query-rate sparkline; optional HTTPS and basic auth
- **Metrics** — Prometheus-compatible `/metrics` endpoint and a rolling stats history at `/api/stats/history`
- **Minecraft server** — optionally runs a bundled Minestom-based Minecraft server to act as a control room for the same settings managed through the dashboard
- **CLI** — `status`, `flush`, `block`, `unblock`, and `log` subcommands talk to the running daemon over HTTP

## Performance

Benchmarked against 1.1.1.1 with 20 concurrent clients, 500 queries across 43 domains (A, AAAA, MX, TXT). Averages taken over multiple runs with a cold cache between each.

| Metric      | kmresolv (cold) | kmresolv (warm) | 1.1.1.1  |
| ----------- | --------------- | --------------- | -------- |
| Throughput  | ~390 q/s        | ~1.7 k/s        | ~1.7 k/s |
| P50 latency | ~220 µs         | ~300 µs         | 12.0 ms  |
| P95 latency | ~360 ms         | ~1.1 ms         | 14.1 ms  |
| P99 latency | ~870 ms         | ~307 ms         | ~16 ms   |

Burst stress test (50 concurrent clients, 1250 queries):

| Metric      | kmresolv | 1.1.1.1  |
| ----------- | -------- | -------- |
| Throughput  | ~4.7 k/s | ~4.1 k/s |
| P50 latency | ~630 µs  | 11.9 ms  |
| P95 latency | ~2.2 ms  | 13.9 ms  |
| P99 latency | ~270 ms  | ~15.7 ms |

Cold P99 variance is network-dependent — iterative resolution follows real nameserver chains, so a slow authoritative server can push an outlier query to ~800ms (the per-attempt timeout). Warm cache hits are consistently sub-millisecond at P50.

## Install
```bash
curl -fsSL https://raw.githubusercontent.com/kohanmathers/kmresolv/main/install.sh | sudo bash
```
**Fresh install:** fetches the latest release binaries, writes everything to `/etc/kmresolv`, and sets up a systemd service.

**Update:** if kmresolv is already installed the script merges new config keys into your existing `config.yml` without overwriting your changes, merges any service file changes while preserving local overrides, redownloads the binary and Minecraft jar, then performs a `daemon-reload` and service restart.

## Configuration
The default config is installed at `/etc/kmresolv/config.yml`. Edit it and restart the service.
```yaml
server:
  listen: 0.0.0.0
  port: 53
  log_level: info        # debug | info | warn | error
  query_log_file: ""     # path to append JSON-lines query log; empty = disabled

resolver:
  timeout: 3
  attempt_timeout_ms: 800
  max_depth: 10
  edns0: true
  tcp_fallback: true
  dnssec: false          # full chain validation: DNSKEY > DS > RRSIG from IANA root KSK
                         # bogus responses -> SERVFAIL; secure responses carry AD bit
                         # iterative mode only (not forwarder mode)
  rate_limit:
    enabled: true
    qps: 100
    burst: 200
  cache:
    enabled: true
    negative_ttl: 300
    prefetch: true
    min_ttl: 30
    max_size: 0            # max cached entries (0 = unlimited); evicts soonest-to-expire when full
  acl:
    default: allow         # action for clients not matched by any rule: allow | deny
    rules:
      # - subnet: 127.0.0.0/8
      #   action: allow
      # - subnet: 0.0.0.0/0
      #   action: deny
  zones:                             # per-domain forwarding; longest match wins
    - domain: internal               # forward *.internal to your AD/local DNS
      servers:
        - 192.168.1.1
    - domain: corp.example.com
      servers:
        - tls://10.0.0.53
  forwarder:
    enabled: false
    servers:
      - 1.1.1.1                    # plain UDP
      - tls://1.1.1.1              # DNS-over-TLS (port 853)
      - https://1.1.1.1/dns-query  # DNS-over-HTTPS; use IP, not hostname,
                                   # to avoid a circular DNS lookup
    fallback_to_iterative: true

records:
  - name: example.home
    type: A
    ttl: 3600
    value: 192.168.1.50

filtering:
  mode: "off"                  # off | blacklist | whitelist
  inline:
    - ads.example.com
  lists:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    - /etc/kmresolv/custom.list
  reload_interval_hours: 24    # re-fetch lists every N hours; 0 = disabled

dashboard:
  enabled: true
  listen: 0.0.0.0
  port: 8080
  auth:                   # Leave empty to disable auth
    username: "admin"
    password: "changeme"
  tls_cert_file: ""       # Path to PEM cert — enables HTTPS when both are set
  tls_key_file: ""        # Path to PEM key

updater:
  check_enabled: true

minecraft:
  enabled: false
  listen: 0.0.0.0
  port: 25565
  min_ram: 1G
  max_ram: 2G
```

## CLI
```
kmresolv serve [--config path]           start the DNS server
kmresolv status                          show resolver stats
kmresolv flush [--expired|--negative]    flush the cache
kmresolv block <domain>                  add a domain to the blocklist
kmresolv unblock <domain>                remove a domain from the blocklist
kmresolv log [--n 50]                    show recent query log
kmresolv version                         print version
```
All subcommands accept `--host` and `--port` to target a non-default dashboard address.

## Service management
```bash
systemctl status kmresolv
systemctl restart kmresolv
journalctl -u kmresolv -f
```
Send `SIGHUP` to reload filter lists without restarting:
```bash
systemctl kill -s HUP kmresolv
```

## Minecraft server
Set `minecraft.enabled: true` in config and ensure `kmresolv-1.0.0-SNAPSHOT.jar` is in `/etc/kmresolv/`. The Minecraft process is started and managed by the kmresolv daemon; OpenJDK 25 is required. The install script will offer to install it for you.

## Building from source
Requirements: Go 1.24+, Maven 3.9+ (for the Minecraft jar)
```bash
# DNS resolver
go build ./cmd/kmresolv

# Minecraft server jar
cd minecraft-server && mvn clean package
```

## Releases
Releases are triggered by including a version tag in a commit message pushed to `main`:
```
Fix CNAME chain resolution [1.2.3]
```
GitHub Actions will run tests, build binaries for `linux/amd64`, `linux/arm64`, and `linux/armv7`, build the Minecraft jar, and publish a release with all assets.