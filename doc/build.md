# Building and running

[Back to README](../README.md)

For service installation, see [distros.md](distros.md).

## Quick build

```sh
cargo build --release
sudo ./target/release/dnscacher --config example-config.toml
```

Release builds use fat LTO, one codegen unit, `panic = "abort"` and stripped
symbols (see `[profile.release]` in `Cargo.toml`), so the first build takes
longer but produces a smaller binary.

### Static musl build

The `x86_64-unknown-linux-musl` target works and produces a static-PIE binary.
Install the target and a musl compiler (the `rust-musl` and `musl` packages on
Arch, or `rustup target add x86_64-unknown-linux-musl` plus `musl-tools` on
Debian), then build with the target's self-contained libc:

```sh
CC_x86_64_unknown_linux_musl=musl-gcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=cc \
cargo build --release --target x86_64-unknown-linux-musl
```

`ring` contains C code and needs `musl-gcc`; keeping the host `cc` as the
linker is what produces a fully static binary.  The result is written to
`target/x86_64-unknown-linux-musl/release/dnscacher`.

Port 53 needs root or `CAP_NET_BIND_SERVICE`.  For an unprivileged test run:

```sh
cargo run -- --config example-config.toml --port 5353
dog example.com @127.0.0.1:5353
```

Useful options:

```text
-c, --config <PATH>       configuration file (default /etc/dnscacher.toml)
    --port <PORT>         override [server] port
    --address <IP>        override [server] address (repeatable)
    --check               validate the config and print effective settings
    --purge-cache <DOMAIN> remove a domain and its subdomains from the cache
    --purge-cache-all     remove every cached entry
    --log-level <FILTER>  log filter (default "dnscacher=info,warn")
```

`DNSCACHER_CONFIG`, `DNSCACHER_LOG` and `RUST_LOG` are also read.

### Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
cargo deny check
```

`cargo deny` reads `deny.toml` and checks advisories, licenses, duplicate
versions and crate sources.

### Purging the cache

```sh
sudo dnscacher --purge-cache example.com   # example.com and *.example.com
sudo dnscacher --purge-cache-all
```

The running server owns the in-memory cache, so the commands talk to it over
the Unix socket configured by `[server] control` (`/run/dnscacher/control.sock`
in the packaged config).  A purge also rewrites the snapshot files immediately,
so a later restart does not resurrect the removed entries.

If the server is not running, or no `control` socket is configured, the command
falls back to rewriting `persistent`/`temporary` directly and prints a note.  In
that case a *running* server would keep its in-memory entries; configure the
control socket to avoid that.  Domain matching is label-aware: `example.com`
matches `example.com` and `www.example.com`, but not `notexample.com`.
