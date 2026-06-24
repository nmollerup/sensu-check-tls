# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `check-tls-host`: full TLS host check with hostname verification, certificate chain verification, STARTTLS (SMTP/IMAP), client certificate support, and address override
- `check-tls-crl`: Certificate Revocation List expiry check (minutes threshold); accepts HTTP/HTTPS URL or local file path
- `check-tls-chain`: certificate chain root check combining anchor subject matching (from `check-ssl-anchor.rb`) and issuer DN matching (from `check-ssl-root-issuer.rb`); supports exact match and regexp; RFC2253/ONELINE/COMPAT issuer formats
- `check-tls-hsts-preloadable`: HSTS preloadability check via hstspreload.org API
- `check-tls-hsts-status`: HSTS preload status check with configurable warn/critical thresholds
- `check-tls-qualys`: Qualys SSL Labs grade check with configurable grade thresholds, API polling, ETA-aware sleep, and overall timeout
- `check-tls-keystore`: Java keystore certificate expiry check via `keytool`

### Changed
- `check-tls-cert`: binary renamed from `bin/check-tls` to `bin/check-tls-cert` for consistency with new commands
- `check-tls-cert`: added `--pem` / `-P` flag to check expiry of a local PEM certificate file (no network connection required)
- `check-tls-cert`: added `--pkcs12` / `-C` and `--pass` / `-S` flags to check expiry of a PKCS#12 certificate file using `golang.org/x/crypto/pkcs12`
- `check-tls-cert`: added `--servername` / `-s` flag for explicit TLS SNI override independent of `--hostname`
- `check-tls-cert`: `--timeout` flag is now applied to the TLS connection via `tls.DialWithDialer`
- `check-tls-cert`: expired certificates now report `"cert expired N days ago"` instead of a misleading negative days-remaining value

## [0.1.0] - 2025-11-26

### Fixed
- TLS configuration not being applied during connection - `--trusted-ca-file` and `--insecure-skip-verify` flags now work correctly
- Certificate expiration alert priority - critical threshold is now checked before warning threshold, preventing incorrect alert levels

### Added
- Comprehensive test suite with 92.3% code coverage
- 19 test cases covering input validation, TLS connection handling, and certificate expiration detection
- Test infrastructure for generating test certificates and TLS servers

## [0.0.1] - 2023-10-27

### Added
- Initial release
