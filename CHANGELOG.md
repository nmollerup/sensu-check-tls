# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

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
