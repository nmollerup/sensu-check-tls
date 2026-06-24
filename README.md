![Go Test](https://github.com/nmollerup/sensu-check-tls/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/nmollerup/sensu-check-tls/workflows/goreleaser/badge.svg)

## sensu-check-tls

Go port of [sensu-plugins/sensu-plugins-ssl](https://github.com/sensu-plugins/sensu-plugins-ssl). Provides TLS/SSL certificate monitoring checks as native Go binaries for [Sensu Go](https://sensu.io/).

## Files

- `bin/check-tls-cert` — Check TLS certificate expiry (network, PEM file, or PKCS#12 file)
- `bin/check-tls-host` — Full TLS host check: expiry, hostname verification, chain verification, STARTTLS
- `bin/check-tls-crl` — Check when a Certificate Revocation List (CRL) will expire
- `bin/check-tls-chain` — Check that a certificate chain is anchored to a specific root (subject or issuer)
- `bin/check-tls-hsts-preloadable` — Check if a domain is preloadable for HSTS
- `bin/check-tls-hsts-status` — Check a domain's HSTS preload status
- `bin/check-tls-qualys` — Check TLS grade via the Qualys SSL Labs API
- `bin/check-tls-keystore` — Check certificate expiry in a Java keystore

## Usage

### `bin/check-tls-cert`

Check when a TLS certificate will expire. Supports live TLS connections, local PEM files, and PKCS#12 files.

```
# Check a live TLS endpoint
check-tls-cert --hostname example.com --warning 30 --critical 14

# Connect to a specific IP while still using the hostname for SNI
check-tls-cert --hostname example.com --ip 192.0.2.1 --warning 30 --critical 14

# Check a local PEM certificate file
check-tls-cert --pem /etc/ssl/certs/mycert.pem --warning 30 --critical 14

# Check a PKCS#12 certificate file
check-tls-cert --pkcs12 /etc/ssl/certs/mycert.p12 --pass secretpassword --warning 30 --critical 14

# Use a custom CA bundle and explicit SNI
check-tls-cert --hostname example.com --trusted-ca-file /etc/ssl/ca-bundle.pem \
  --servername override.example.com --warning 30 --critical 14
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--hostname` | | | Hostname to connect to (required for network mode) |
| `--port` | `-p` | `443` | TCP port |
| `--ip` | | | IP address to connect to (overrides DNS; hostname still used for SNI) |
| `--servername` | `-s` | hostname | TLS SNI server name override |
| `--warning` | `-w` | | Days before expiry to warn (required) |
| `--critical` | `-c` | | Days before expiry to go critical (required) |
| `--timeout` | | `15` | Connection timeout in seconds |
| `--pem` | `-P` | | Path to PEM certificate file (no network connection needed) |
| `--pkcs12` | `-C` | | Path to PKCS#12 certificate file (no network connection needed) |
| `--pass` | `-S` | | Passphrase for PKCS#12 private key |
| `--trusted-ca-file` | `-t` | | TLS CA certificate bundle in PEM format |
| `--insecure-skip-verify` | `-i` | `false` | Skip TLS certificate verification (not recommended) |

### `bin/check-tls-host`

Full TLS host certificate check: expiry, hostname verification, certificate chain integrity, and STARTTLS support for SMTP and IMAP.

```
# Basic check
check-tls-host --host example.com

# Custom thresholds and alternate port
check-tls-host --host example.com --port 8443 --warning 30 --critical 14

# Connect to a specific address but verify against the hostname
check-tls-host --host example.com --address 192.0.2.1

# Check an SMTP server with STARTTLS
check-tls-host --host mail.example.com --port 25 --starttls smtp

# Check an IMAP server with STARTTLS
check-tls-host --host mail.example.com --port 143 --starttls imap

# Mutual TLS (client certificate authentication)
check-tls-host --host example.com --client-cert /etc/ssl/client.pem --client-key /etc/ssl/client.key

# Skip hostname and chain verification
check-tls-host --host example.com --skip-hostname-verification --skip-chain-verification
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | `-h` | | Hostname to check (required) |
| `--port` | `-p` | `443` | TCP port |
| `--address` | `-a` | | TCP address to connect to (overrides host for connection; host still used for SNI/verification) |
| `--warning` | `-w` | `14` | Days before expiry to warn |
| `--critical` | `-c` | `7` | Days before expiry to go critical |
| `--client-cert` | | | Path to client certificate (PEM/DER) for mutual TLS |
| `--client-key` | | | Path to client key (PEM/DER) for mutual TLS |
| `--skip-hostname-verification` | | `false` | Disable hostname verification |
| `--skip-chain-verification` | | `false` | Disable certificate chain verification |
| `--starttls` | | | STARTTLS protocol to negotiate before TLS handshake (`smtp` or `imap`) |
| `--timeout` | | `30` | Connection timeout in seconds |

### `bin/check-tls-crl`

Check when a Certificate Revocation List (CRL) will expire. Warning and critical thresholds are in minutes. Accepts a URL (HTTP/HTTPS) or a local file path.

```
# Check a CRL file on disk
check-tls-crl --url /path/to/crl.crl --warning 600 --critical 300

# Check a CRL via HTTP
check-tls-crl --url http://crl.example.com/root.crl --warning 600 --critical 300
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--url` | `-u` | | URL or file path to the CRL (required) |
| `--critical` | `-c` | | Minutes before CRL expiry to go critical (required) |
| `--warning` | `-w` | | Minutes before CRL expiry to warn (required) |

### `bin/check-tls-chain`

Check that the last certificate in a TLS chain matches an expected root anchor subject (`--anchor`) or root issuer DN (`--issuer`). Supports exact string match or regular expression matching.

```
# Check the root anchor subject matches a string
check-tls-chain --host example.com \
  --anchor "CN=ISRG Root X1,O=Internet Security Research Group,C=US"

# Check the root issuer using a regexp
check-tls-chain --host example.com --issuer "Let.s Encrypt" --regexp

# Check issuer in OpenSSL one-line format
check-tls-chain --host example.com \
  --issuer "/O=Internet Security Research Group/CN=ISRG Root X1" \
  --issuer-format ONELINE
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | `-h` | | Host to connect to (required) |
| `--port` | `-p` | `443` | TCP port |
| `--servername` | `-s` | host | TLS SNI server name override |
| `--anchor` | | | Expected subject of the last cert in the chain |
| `--issuer` | `-i` | | Expected issuer DN of the root cert in the chain |
| `--issuer-format` | `-f` | `RFC2253` | Issuer name format: `RFC2253`, `ONELINE`, or `COMPAT` |
| `--regexp` | `-r` | `false` | Treat `--anchor` or `--issuer` value as a regular expression |
| `--timeout` | | `15` | Connection timeout in seconds |

`--anchor` and `--issuer` are mutually exclusive; exactly one must be provided.

### `bin/check-tls-hsts-preloadable`

Check whether a domain is preloadable for HSTS by querying the [hstspreload.org](https://hstspreload.org/) API. Returns CRITICAL if errors are present, WARNING if only warnings are present.

```
check-tls-hsts-preloadable --domain example.com
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--domain` | `-d` | | Domain to check (required) |
| `--api-url` | | `https://hstspreload.org/api/v2/preloadable` | API endpoint URL |

### `bin/check-tls-hsts-status`

Check a domain's HSTS preload status via the [hstspreload.org](https://hstspreload.org/) API. Statuses rank from worst to best: `unknown` → `pending` → `preloaded`.

```
check-tls-hsts-status --domain example.com

# Alert if not yet preloaded
check-tls-hsts-status --domain example.com --critical pending --warn preloaded
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--domain` | `-d` | | Domain to check (required) |
| `--critical` | `-c` | `unknown` | CRITICAL if status is at or below this level |
| `--warn` | `-w` | `pending` | WARNING if status is at or below this level |
| `--api-url` | | `https://hstspreload.org/api/v2/status` | API endpoint URL |

### `bin/check-tls-qualys`

Check a domain's TLS grade using the [Qualys SSL Labs API](https://www.ssllabs.com/). The check polls the API until a result is ready, which typically takes 60–120 seconds on the first run. Set a long Sensu check timeout (300s+).

Grades from best to worst: `A+`, `A`, `A-`, `B`, `C`, `D`, `E`, `F`, `T`, `M`.

```
check-tls-qualys --domain example.com

# Alert if grade falls below A
check-tls-qualys --domain example.com --warn A --critical A-
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--domain` | `-d` | | Domain to check (required) |
| `--warn` | `-w` | `A-` | WARNING if grade is worse than this |
| `--critical` | `-c` | `B` | CRITICAL if grade is worse than this |
| `--num-checks` | `-n` | `24` | Maximum number of API poll attempts |
| `--time-between` | `-t` | `10` | Seconds between polls (API-provided ETA takes precedence if higher) |
| `--timeout` | | `300` | Overall timeout in seconds |
| `--api-url` | | `https://api.ssllabs.com/api/v3/` | Qualys API base URL |

### `bin/check-tls-keystore`

Check when a certificate stored in a Java keystore will expire. Requires `keytool` (JDK) to be available on the system.

```
check-tls-keystore --path /etc/ssl/keystore.jks --alias mycert \
  --password storepassword --warning 30 --critical 14
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--path` | | | Path to the Java keystore file (required) |
| `--alias` | | | Certificate alias in the keystore (required) |
| `--password` | | | Keystore password (required) |
| `--warning` | `-w` | | Days before expiry to warn (required) |
| `--critical` | `-c` | | Days before expiry to go critical (required) |

## Configuration

### Asset registration

Assets are the recommended way to deploy plugins for use with Sensu Go. A Bonsai registration snippet example:

```yaml
---
type: Asset
api_version: core/v2
metadata:
  name: sensu-check-tls
spec:
  url: https://github.com/nmollerup/sensu-check-tls/releases/download/${VERSION}/sensu-check-tls_${VERSION}_linux_amd64.tar.gz
```

### Check definitions

```yaml
---
type: CheckConfig
api_version: core/v2
metadata:
  name: check-tls-cert-example-com
spec:
  command: check-tls-cert --hostname example.com --warning 30 --critical 14
  runtime_assets:
    - sensu-check-tls
  interval: 3600
  publish: true
  handlers:
    - default
  subscriptions:
    - system
```

## Installation from source

```
git clone https://github.com/nmollerup/sensu-check-tls.git
cd sensu-check-tls
go build -o bin/check-tls-cert ./cmd/check-tls-cert
go build -o bin/check-tls-host ./cmd/check-tls-host
go build -o bin/check-tls-crl ./cmd/check-tls-crl
go build -o bin/check-tls-chain ./cmd/check-tls-chain
go build -o bin/check-tls-hsts-preloadable ./cmd/check-tls-hsts-preloadable
go build -o bin/check-tls-hsts-status ./cmd/check-tls-hsts-status
go build -o bin/check-tls-qualys ./cmd/check-tls-qualys
go build -o bin/check-tls-keystore ./cmd/check-tls-keystore
```

## Notes

`check-tls-host` and `check-tls-chain` complement each other well: use `check-tls-host` to verify the chain is intact and the certificate is not expiring, and `check-tls-chain` to confirm the chain is anchored to the expected root CA.

`check-tls-qualys` polls an external API and typically takes 60–120 seconds to complete. Schedule it infrequently and set the Sensu check `timeout` to at least 300 seconds.

`check-tls-keystore` requires `keytool` (part of the JDK) to be installed on the host running the check.
