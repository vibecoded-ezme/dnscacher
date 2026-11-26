%global debug_package %{nil}
%global __strip /bin/true
# gzip payloads are readable by older rpm versions on RHEL/CentOS.
%global _binary_payload w9.gzdio
# Static-PIE binaries have a .gnu.hash section but no dynamic loader; elfdeps
# still adds this otherwise, which would make the package depend on glibc.
%global __requires_exclude ^rtld\\(GNU_HASH\\)$

# These defaults let the spec build without extra --define options.  The
# build-rpm.sh wrapper overrides them from Cargo.toml and uname -m.
%{!?dnscacher_version: %global dnscacher_version 0.3.0}
%{!?dnscacher_release: %global dnscacher_release 1}
%{!?dnscacher_arch: %global dnscacher_arch x86_64}

# systemd-rpm-macros defines this on Fedora and RHEL; keep the spec usable on
# build hosts that only provide rpmbuild.
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

Name:           dnscacher
Version:        %{dnscacher_version}
Release:        %{dnscacher_release}%{?dist}
Summary:        Caching DNS forwarder with UDP, TCP, DoT and DoH support

License:        MIT
URL:            https://github.com/vibecoded-ezme/dnscacher
Packager:       ez-me <66479626+ez-me@users.noreply.github.com>
Source0:        %{name}-%{version}.tar.gz
BuildArch:      %{dnscacher_arch}

Requires:       systemd >= 232
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
dnscacher is a small caching DNS forwarder.  It serves plain DNS over UDP and
TCP as well as DNS over TLS (DoT) and DNS over HTTPS (DoH), forwards misses to
plain, DoT or DoH upstreams, and keeps a persistent cache.

It supports per-domain upstream routing, fixed-lifetime positive and negative
caching, hosts-file records and deny lists, AdGuard-style $dnsrewrite rules,
DNSSEC pass-through modes, and live cache purging through a Unix socket.

%prep
%autosetup -n %{name}-%{version}

%build
# The source tarball contains the already built, stripped binary.  Building the
# crate here would need a full Rust toolchain and network access on the target
# distribution; build-rpm.sh produces the binary before calling rpmbuild.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a usr %{buildroot}/
cp -a etc %{buildroot}/
install -Dm644 README.md %{buildroot}%{_docdir}/dnscacher/README.md
install -Dm644 LICENSE %{buildroot}%{_licensedir}/dnscacher/LICENSE

%files
%{_bindir}/dnscacher
%config(noreplace) %{_sysconfdir}/dnscacher.toml
%{_unitdir}/dnscacher.service
%{_docdir}/dnscacher/README.md
%license %{_licensedir}/dnscacher/LICENSE

%post
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

if [ "$1" -eq 1 ]; then
    cat <<'EOF'
dnscacher is installed but not enabled.

  sudo systemctl enable --now dnscacher
  dog example.com @127.0.0.1

Configuration: /etc/dnscacher.toml (listens on 127.0.0.1:53 by default).
Logs:          journalctl -u dnscacher -f
EOF
else
    cat <<'EOF'
dnscacher was upgraded.  Restart it to use the new binary:

  sudo systemctl restart dnscacher
EOF
fi

%preun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now dnscacher.service >/dev/null 2>&1 || :
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -ge 1 ]; then
        systemctl try-restart dnscacher.service >/dev/null 2>&1 || :
    fi
fi

%changelog
* Thu Nov 26 2026 ez-me <66479626+ez-me@users.noreply.github.com> - 0.3.0-1
- Add s6 service and RPM packaging; drop 32-bit architecture targets

* Thu Nov 26 2026 ez-me <66479626+ez-me@users.noreply.github.com> - 0.2.0-1
- Initial RPM package
