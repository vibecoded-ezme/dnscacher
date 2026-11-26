# Services and distribution packages

[Back to README](../README.md)

The source tree installers and the distribution packages are alternatives.
Use one of them; do not install a service package over a source-tree install
that writes the same paths.

## Choosing a service manager

| Init | Package | Enable |
|------|---------|--------|
| systemd | `dnscacher` (Arch, Debian, RPM) | `systemctl enable --now dnscacher` |
| OpenRC | `dnscacher-openrc` (Artix, Alpine) | `rc-update add dnscacher default` |
| dinit | `dnscacher-dinit` (Artix) | `dinitctl enable dnscacher` |
| runit | `dnscacher-runit` (Artix) | symlink into `/run/runit/service` |
| s6 | `dnscacher-s6` (Artix) | `s6 set enable dnscacher` |

The four Artix service packages provide and conflict with `init-dnscacher`, so
install exactly one.  They run the daemon as root, like the source-tree s6
service.  The systemd unit uses `DynamicUser=`, and the Alpine OpenRC package
runs as the `dnscacher` user with `CAP_NET_BIND_SERVICE`.

## Run as a systemd service

The `deploy/` directory contains a hardened unit and a system-wide config.  Get
a release binary and install everything with:

```sh
cargo build --release
sudo deploy/install.sh
```

The script installs:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/dnscacher` | the binary |
| `/etc/dnscacher.toml` | configuration, only written if missing |
| `/etc/systemd/system/dnscacher.service` | the unit |
| `/usr/local/share/doc/dnscacher/` | README and `doc/` files |

It validates the config, reloads systemd, then enables and starts the service.
Pass `--force-config` to replace an existing `/etc/dnscacher.toml`, and
`--no-start` to install without starting.  Running
`sudo deploy/install.sh --build` also builds the release binary first (as root,
so make sure `cargo` is on root's `PATH`).

The unit runs as a `DynamicUser` with only `CAP_NET_BIND_SERVICE`, keeps the
cache under `/var/lib/dnscacher`, and exposes the control socket in
`/run/dnscacher/control.sock` (`RuntimeDirectory=dnscacher`), and stops with
SIGTERM so the cache is saved cleanly.

Useful commands:

```sh
systemctl status dnscacher
journalctl -u dnscacher -f
dog example.com @127.0.0.1
sudo dnscacher --purge-cache example.com
sudo systemctl disable --now dnscacher
```

To use it system-wide, point `/etc/resolv.conf` at `127.0.0.1` through your
network manager rather than editing a managed file.  DoT and DoH hostnames in a
table are resolved to that table's `ipv4`/`ipv6` addresses first, so normal
upstream tables work without touching `/etc/hosts`.  Only hosts that are not
listed in the same table fall back to the system resolver, which may loop if
that resolver is dnscacher itself; add those to `/etc/hosts` or use plain IP
upstreams.

### Uninstall

```sh
sudo deploy/uninstall.sh          # service, binary and documentation
sudo deploy/uninstall.sh --purge  # also remove /etc/dnscacher.toml and the cache
```

### Arch Linux package

`packaging/arch/` builds a normal pacman package from the current working tree:

```sh
./packaging/arch/build-local.sh       # makepkg -si, asks for sudo
```

Then manage it like any other package:

```sh
sudo systemctl enable --now dnscacher
sudo pacman -R dnscacher
```

The package installs `/usr/bin/dnscacher`, `/etc/dnscacher.toml` (a pacman
backup file), the unit in `/usr/lib/systemd/system`, and documentation in
`/usr/share/doc/dnscacher`.  It is not enabled automatically.  A modified
config is kept as `/etc/dnscacher.toml.pacsave` when you remove the package.

`build-local.sh` stages a source tarball under `target/archpkg/` and passes any
arguments to `makepkg`, so `./packaging/arch/build-local.sh -f` builds without
installing.  Don't mix it with `deploy/install.sh` or `deploy/install-s6.sh`:
those scripts install to `/usr/local` and `/etc/systemd/system` or `/etc/s6/sv`,
which would shadow the packaged files.

### Debian package

`packaging/debian/` contains a debhelper source tree plus `build-deb.sh`, which
assembles a binary package without requiring debhelper or dpkg development
tools (it uses `ar`, `tar` and `md5sum`):

```sh
./packaging/debian/build-deb.sh        # target/debian/dnscacher_0.3.0_<arch>.deb
sudo apt install ./target/debian/dnscacher_0.3.0_amd64.deb
sudo systemctl enable --now dnscacher
```

The package installs `/usr/bin/dnscacher`, `/etc/dnscacher.toml` (a conffile),
the unit in `/usr/lib/systemd/system`, and documentation and the license in
`/usr/share/doc/dnscacher`.  It is not enabled automatically, and a modified
configuration is left in place when the package is removed.

To build with the regular Debian tooling instead:

```sh
cp -r packaging/debian debian
dpkg-buildpackage -us -uc -b
```

This needs `build-essential`, `debhelper` and a Rust toolchain (`cargo`,
`rustc`, or `rustup`).  `debian/control` declares the dependencies.

### Fedora, CentOS and RHEL package

`packaging/rpm/` builds a binary RPM with `rpmbuild`:

```sh
sudo dnf install rpm-build file
./packaging/rpm/build-rpm.sh
sudo dnf install target/rpm/RPMS/*/dnscacher-0.3.0-*.rpm
sudo systemctl enable --now dnscacher
```

The build script packages the static-PIE musl binary
(`target/<arch>-unknown-linux-musl/release/dnscacher`, for example
`x86_64-unknown-linux-musl`).  That binary has no glibc version dependency, so
the same RPM runs on Fedora, CentOS Stream and RHEL.  If the musl binary is
missing the script tries to build it; `--host` instead packages
`target/release/dnscacher`, which inherits the build host's glibc requirement
(build on the oldest distribution you need to support).  `--skip-build` reuses
an existing binary and `--release N` sets the RPM release number.  Rebuilding
the musl binary needs the Rust musl target and `musl-gcc` (see
[Static musl build](build.md#static-musl-build)).

The RPM installs `/usr/bin/dnscacher`, `/etc/dnscacher.toml` (marked
`%config(noreplace)`), the unit in `/usr/lib/systemd/system`,
`/usr/share/doc/dnscacher/README.md`, the `doc/` files and
`/usr/share/licenses/dnscacher/LICENSE`.  It is not enabled automatically, and
a modified configuration is preserved on upgrade.  The package is unsigned;
install the local file directly with `dnf` (add `--nogpgcheck` if your
configuration checks local packages) or `rpm -Uvh`.  Remove it with
`sudo dnf remove dnscacher` (or `rpm -e dnscacher`).

Don't mix it with `deploy/install.sh`: that script installs to `/usr/local`
and `/etc/systemd/system`, which would shadow the packaged files.

### Alpine Linux package

`packaging/alpine/` contains an APKBUILD and OpenRC service files, plus a script
that builds installable `.apk` packages from the current tree:

```sh
./packaging/alpine/build-apk.sh
sudo apk add --allow-untrusted target/alpine/dnscacher-0.3.0-r0.apk \
    target/alpine/dnscacher-openrc-0.3.0-r0.apk
sudo rc-update add dnscacher default
sudo rc-service dnscacher start
```

The script packages the static-PIE musl binary, so the package has no runtime
library dependencies.  It creates the packages with `apk mkpkg` from apk-tools 3,
which means the prebuilt files target Alpine 3.23 or newer; on older releases,
build the APKBUILD with `abuild` on the target release.  The packages are
unsigned, hence `--allow-untrusted`.

The main package installs `/usr/bin/dnscacher`, `/etc/dnscacher.toml`,
documentation and the license.  `dnscacher-openrc` adds
`/etc/init.d/dnscacher` and `/etc/conf.d/dnscacher`; install both files
together, or let a repository index pull the OpenRC subpackage through its
`install_if` rule.  The service runs as the `dnscacher` user with only
`CAP_NET_BIND_SERVICE`, stores its cache in `/var/lib/dnscacher`, and logs to
`/var/log/dnscacher.log`.

`build-apk.sh` needs apk-tools 3, a static musl binary, and `unshare -r` when
run as a normal user.  Set `APK=/path/to/apk.static` to use a local apk-tools 3
binary, `--skip-build` to reuse an existing binary, and `--release N` to set the
Alpine `pkgrel`.

For a native build with the APKBUILD, publish a `v0.3.0` tag (or place the
source tarball in `$SRCDEST`), then run `abuild checksum` and `abuild -r` from
`packaging/alpine`.

## Run as an s6 service (Artix Linux)

Artix uses s6-rc through s6-frontend.  The service files live in `deploy/s6/`
and form a two-service pipeline: `dnscacher-srv` runs the daemon and
`dnscacher-log` consumes its output with `s6-log`.  The pipeline bundle is
named `dnscacher`.

Get a release binary and install everything with:

```sh
cargo build --release
sudo deploy/install-s6.sh
```

The script installs:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/dnscacher` | the binary |
| `/etc/dnscacher.toml` | configuration, only written if missing |
| `/etc/s6/sv/dnscacher-srv` | the longrun service |
| `/etc/s6/sv/dnscacher-log` | the `s6-log` consumer |
| `/usr/local/share/doc/dnscacher/` | README and `doc/` files |

It validates the config, syncs the s6-frontend repository, enables the
`dnscacher` bundle in the current service set, commits and installs that set,
and starts the service.  On a first s6-frontend installation it runs
`s6 repository init` if the repository does not exist yet.

s6 has no `DynamicUser=`, so the service runs as root.  It creates
`/var/lib/dnscacher` and `/run/dnscacher` at startup, matching the paths in the
packaged config, and logs to `/var/log/dnscacher/current` (or
`/run/log/dnscacher` while `/var` is not writable yet).

Useful commands:

```sh
s6 live status dnscacher-srv dnscacher-log
sudo s6 live restart dnscacher
tail -F /var/log/dnscacher/current
dog example.com @127.0.0.1
sudo s6 live stop dnscacher
sudo s6 set disable dnscacher && sudo s6 set commit && sudo s6 live install
```

`--no-start` installs the files and syncs the repository without enabling the
service.  `--force-config` replaces an existing `/etc/dnscacher.toml`, and
`--service-dir DIR` installs into a store other than `/etc/s6/sv`.  Do not mix
this with `deploy/install.sh`: the systemd and s6 installers both write
`/usr/local/bin/dnscacher` and `/etc/dnscacher.toml`.

After editing a definition under `/etc/s6/sv`, run `s6 repository sync` before
`s6 set commit` and `s6 live install`, so the repository sees the new files.

### Uninstall

```sh
sudo deploy/uninstall-s6.sh          # service, binary and documentation
sudo deploy/uninstall-s6.sh --purge  # also remove the config, cache and logs
```

### Artix package

`packaging/artix-s6/` builds `dnscacher-s6`, the Artix-style service package.
Install the main package first, then the service package:

```sh
./packaging/arch/build-local.sh -f      # build the dnscacher package
sudo pacman -U target/archpkg/dnscacher-0.3.0-*.pkg.tar.zst
./packaging/artix-s6/build-local.sh -f  # build the service package
sudo pacman -U target/artix-s6pkg/dnscacher-s6-0.3.0-*.pkg.tar.zst
```

The service package installs the two definitions into `/etc/s6/sv` and does not
enable them; use the `s6 set` and `s6 live` commands above.  It provides and
conflicts with `init-dnscacher`, following the other Artix service packages.

## Service logging

Set `DNSCACHER_LOG` or pass `--log-level dnscacher=debug` to log upstream
selection.  `RUST_LOG` takes precedence when both are set.

Systemd: add an override and restart:

```sh
sudo systemctl edit dnscacher
```

```ini
[Service]
Environment=DNSCACHER_LOG=dnscacher=debug
```

s6: write the variable into the service environment directory:

```sh
sudo mkdir -p /etc/s6/sv/dnscacher-srv/env
echo 'dnscacher=debug' | sudo tee /etc/s6/sv/dnscacher-srv/env/DNSCACHER_LOG
sudo s6 set commit && sudo s6 live install && sudo s6 live restart dnscacher-srv
```

OpenRC: set `command_args_extra` in `/etc/conf.d/dnscacher` and restart:

```sh
echo 'command_args_extra="--log-level dnscacher=debug"' | sudo tee -a /etc/conf.d/dnscacher
sudo rc-service dnscacher restart
```

dinit: add an environment file and reference it from the service, then restart:

```sh
echo 'DNSCACHER_LOG=dnscacher=debug' | sudo tee /etc/dnscacher.env
sudo sed -i '/^command =/a env-file = /etc/dnscacher.env' /etc/dinit.d/dnscacher
sudo dinitctl restart dnscacher
```

runit: create `conf` in the service directory; the run script sources it:

```sh
echo 'export DNSCACHER_LOG=dnscacher=debug' | sudo tee /etc/runit/sv/dnscacher/conf
sudo sv restart dnscacher
```

## Artix Linux: OpenRC

Build and install the main package, then the OpenRC service package:

```sh
./packaging/arch/build-local.sh -f
sudo pacman -U target/archpkg/dnscacher-0.3.0-*.pkg.tar.zst
./packaging/artix-openrc/build-local.sh -f
sudo pacman -U target/artix-openrcpkg/dnscacher-openrc-0.3.0-*.pkg.tar.zst
```

The service files are `/etc/init.d/dnscacher` and `/etc/conf.d/dnscacher`.
Enable and start it with:

```sh
sudo rc-update add dnscacher default
sudo rc-service dnscacher start
```

Logs go to `/var/log/dnscacher.log`.  `/etc/conf.d/dnscacher` can override
`cfgfile` and add arguments such as `--log-level` through
`command_args_extra`.  Stop and disable it with `rc-service dnscacher stop` and
`rc-update del dnscacher default`.

## Artix Linux: dinit

Build and install the main package, then the dinit service package:

```sh
./packaging/arch/build-local.sh -f
sudo pacman -U target/archpkg/dnscacher-0.3.0-*.pkg.tar.zst
./packaging/artix-dinit/build-local.sh -f
sudo pacman -U target/artix-dinitpkg/dnscacher-dinit-0.3.0-*.pkg.tar.zst
```

The service definition is `/etc/dinit.d/dnscacher`; it runs
`/usr/lib/dnscacher/dinit-run`, which creates the runtime directories, checks
the configuration and starts the daemon.  Enable and start it with:

```sh
sudo dinitctl enable dnscacher
sudo dinitctl start dnscacher
```

Logs go to `/var/log/dnscacher.log`.  Stop and disable it with
`dinitctl stop dnscacher` and `dinitctl disable dnscacher`.

## Artix Linux: runit

Build and install the main package, then the runit service package:

```sh
./packaging/arch/build-local.sh -f
sudo pacman -U target/archpkg/dnscacher-0.3.0-*.pkg.tar.zst
./packaging/artix-runit/build-local.sh -f
sudo pacman -U target/artix-runitpkg/dnscacher-runit-0.3.0-*.pkg.tar.zst
```

The service directory is `/etc/runit/sv/dnscacher` with `run` and `log/run`.
Enable and start it with:

```sh
sudo ln -s /etc/runit/sv/dnscacher /run/runit/service/
sudo sv start dnscacher
```

Logs go to `/var/log/dnscacher/current`.  Stop and disable it with
`sv stop dnscacher` and `rm /run/runit/service/dnscacher`.
