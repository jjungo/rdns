# rdns

Lightweight recursive DNS server in Rust with caching, upstream forwarding, and configurable static records.

## Features

- Multiple record types (A, AAAA, NS, SOA, MX, CNAME, PTR, TXT)
- TTL-based caching with automatic expiration
- Upstream DNS forwarding to system resolvers
- Performance statistics tracking
- TOML-based configuration
- Async/concurrent query handling

## Quick Start

```bash
cargo run
```

Server listens on `127.0.0.1:9053` by default.

Optional: copy `config.toml.example` to `config.toml` to customize settings or add static records.

## Testing

```bash
dig @127.0.0.1 -p 9053 google.com
dig @127.0.0.1 -p 9053 MX gmail.com
dig @127.0.0.1 -p 9053 AAAA github.com
```

## Configuration

See `config.toml.example` for available options:
- Server listen address/port
- Cache size and cleanup intervals
- Static DNS records
- Statistics output settings

Use a custom config file:
```bash
cargo run -- /path/to/config.toml
```
## How It Works

Three-tier lookup: static records -> cache -> upstream DNS.

Upstream responses are cached with TTL (default 300s). Performance metrics written to `dns_stats.txt` every 60 seconds.

## Dependencies

- **tokio** - Async runtime
- **trust-dns-resolver** - Upstream DNS resolution
- **toml/serde** - Configuration parsing
