Name:           systemd-resolved-rs
Version:        0.1.0
Release:        1%{?dist}
Summary:        Drop-in network name resolution (Rust)
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/systemd-resolved-rs
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  cargo rust gcc gfortran make
Requires:       systemd polkit

%description
Compatibility-oriented reimplementation of systemd-resolved.

%prep
%autosetup

%build
cargo build --release
make -C nss

%install
install -D -m 755 target/release/systemd-resolved-rs %{buildroot}/usr/lib/systemd/systemd-resolved-rs
install -D -m 755 nss/libnss_resolve.so.2 %{buildroot}/%{_libdir}/libnss_resolve.so.2
install -D -m 644 packaging/systemd/systemd-resolved-rs.service %{buildroot}/usr/lib/systemd/system/systemd-resolved-rs.service
install -D -m 644 packaging/polkit/org.freedesktop.resolve1.policy %{buildroot}/usr/share/polkit-1/actions/org.freedesktop.resolve1.policy
install -D -m 644 packaging/tmpfiles/systemd-resolved-rs.conf %{buildroot}/usr/lib/tmpfiles.d/systemd-resolved-rs.conf

%files
/usr/lib/systemd/systemd-resolved-rs
/%{_libdir}/libnss_resolve.so.2
/usr/lib/systemd/system/systemd-resolved-rs.service
/usr/share/polkit-1/actions/org.freedesktop.resolve1.policy
/usr/lib/tmpfiles.d/systemd-resolved-rs.conf

%changelog
* Fri Aug 07 2026 Builder - 0.1.0-1
- Initial landing package
