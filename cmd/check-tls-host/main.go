package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

type Config struct {
	sensu.PluginConfig
	Host                    string
	Port                    int
	Address                 string
	Warning                 int
	Critical                int
	ClientCert              string
	ClientKey               string
	SkipHostnameVerification bool
	SkipChainVerification    bool
	InsecureSkipVerify       bool
	StartTLS                 string
	Timeout                  int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-host",
			Short:    "TLS host certificate check: expiry, hostname, and chain verification",
			Keyspace: "sensu.io/plugins/check-tls-host/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Argument:  "host",
			Shorthand: "h",
			Usage:     "Hostname of the server to check (used for SNI and hostname verification)",
			Value:     &plugin.Host,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "port",
			Shorthand: "p",
			Default:   443,
			Usage:     "Port to connect to",
			Value:     &plugin.Port,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "address",
			Shorthand: "a",
			Default:   "",
			Usage:     "TCP address to connect to (overrides host for connection, host still used for SNI/verification)",
			Value:     &plugin.Address,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "warning",
			Shorthand: "w",
			Default:   14,
			Usage:     "Days before expiry to warn",
			Value:     &plugin.Warning,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "critical",
			Shorthand: "c",
			Default:   7,
			Usage:     "Days before expiry to go critical",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "client-cert",
			Default:  "",
			Usage:    "Path to client certificate (PEM/DER) for mutual TLS",
			Value:    &plugin.ClientCert,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "client-key",
			Default:  "",
			Usage:    "Path to client private key (PEM/DER) for mutual TLS",
			Value:    &plugin.ClientKey,
		},
		&sensu.PluginConfigOption[bool]{
			Argument: "skip-hostname-verification",
			Default:  false,
			Usage:    "Disable hostname verification",
			Value:    &plugin.SkipHostnameVerification,
		},
		&sensu.PluginConfigOption[bool]{
			Argument: "skip-chain-verification",
			Default:  false,
			Usage:    "Disable certificate chain verification",
			Value:    &plugin.SkipChainVerification,
		},
		&sensu.PluginConfigOption[bool]{
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "Skip TLS certificate verification (not recommended)",
			Value:     &plugin.InsecureSkipVerify,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "starttls",
			Default:  "",
			Usage:    "Use STARTTLS for the given protocol before TLS handshake (smtp, imap)",
			Value:    &plugin.StartTLS,
		},
		&sensu.PluginConfigOption[int]{
			Argument: "timeout",
			Default:  30,
			Usage:    "Connection timeout in seconds",
			Value:    &plugin.Timeout,
		},
	}
)

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.Host) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--host is required")
	}
	if plugin.Warning <= plugin.Critical {
		return sensu.CheckStateWarning, fmt.Errorf("--warning must be greater than --critical")
	}
	if plugin.StartTLS != "" && plugin.StartTLS != "smtp" && plugin.StartTLS != "imap" {
		return sensu.CheckStateWarning, fmt.Errorf("--starttls must be 'smtp' or 'imap'")
	}
	return sensu.CheckStateOK, nil
}

func starttlsSMTP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading SMTP banner: %v", err)
	}
	if !strings.HasPrefix(line, "220") {
		return fmt.Errorf("expected SMTP 220 banner, got: %v", strings.TrimSpace(line))
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("sending STARTTLS: %v", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading STARTTLS response: %v", err)
	}
	if !strings.HasPrefix(line, "220") {
		return fmt.Errorf("expected SMTP 220 after STARTTLS, got: %v", strings.TrimSpace(line))
	}
	return nil
}

func starttlsIMAP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading IMAP banner: %v", err)
	}
	if !strings.HasPrefix(line, "* OK") {
		return fmt.Errorf("expected IMAP '* OK' banner, got: %v", strings.TrimSpace(line))
	}
	if _, err := fmt.Fprintf(conn, "a001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("sending STARTTLS: %v", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading STARTTLS response: %v", err)
	}
	if !strings.HasPrefix(line, "a001 OK Begin TLS") {
		return fmt.Errorf("expected IMAP STARTTLS OK, got: %v", strings.TrimSpace(line))
	}
	return nil
}

func executeCheck(event *corev2.Event) (int, error) {
	connectAddr := plugin.Address
	if connectAddr == "" {
		connectAddr = plugin.Host
	}
	dialAddr := net.JoinHostPort(connectAddr, fmt.Sprint(plugin.Port))

	timeout := time.Duration(plugin.Timeout) * time.Second
	tcpConn, err := net.DialTimeout("tcp", dialAddr, timeout)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("connection failed: %v", err)
	}

	switch plugin.StartTLS {
	case "smtp":
		if err := starttlsSMTP(tcpConn); err != nil {
			_ = tcpConn.Close()
			return sensu.CheckStateCritical, err
		}
	case "imap":
		if err := starttlsIMAP(tcpConn); err != nil {
			_ = tcpConn.Close()
			return sensu.CheckStateCritical, err
		}
	}

	tlsCfg := &tls.Config{ServerName: plugin.Host, InsecureSkipVerify: plugin.InsecureSkipVerify} //nolint:gosec

	if plugin.ClientCert != "" && plugin.ClientKey != "" {
		certData, err := os.ReadFile(plugin.ClientCert)
		if err != nil {
			_ = tcpConn.Close()
			return sensu.CheckStateCritical, fmt.Errorf("reading client cert: %v", err)
		}
		keyData, err := os.ReadFile(plugin.ClientKey)
		if err != nil {
			_ = tcpConn.Close()
			return sensu.CheckStateCritical, fmt.Errorf("reading client key: %v", err)
		}
		kp, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			_ = tcpConn.Close()
			return sensu.CheckStateCritical, fmt.Errorf("loading client cert/key: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{kp}
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = tcpConn.Close()
		return sensu.CheckStateCritical, fmt.Errorf("TLS handshake failed: %v", err)
	}
	defer func() { _ = tlsConn.Close() }()

	chain := tlsConn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return sensu.CheckStateCritical, fmt.Errorf("no certificates returned by server")
	}

	if !plugin.SkipHostnameVerification {
		if err := chain[0].VerifyHostname(plugin.Host); err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("%v hostname mismatch: %v", plugin.Host, err)
		}
	}

	if !plugin.SkipChainVerification && len(chain) > 1 {
		for i := 0; i < len(chain)-1; i++ {
			if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
				return sensu.CheckStateCritical, fmt.Errorf("%v invalid certificate chain at position %d: %v", plugin.Host, i, err)
			}
		}
	}

	return checkExpiry(chain[0], plugin.Host)
}

func checkExpiry(cert *x509.Certificate, source string) (int, error) {
	timeNow := time.Now()
	expiresInDays := int(cert.NotAfter.Sub(timeNow).Hours() / 24)

	if expiresInDays < 0 {
		fmt.Printf("critical: %v cert expired %v days ago\n", source, -expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	if timeNow.AddDate(0, 0, plugin.Critical).After(cert.NotAfter) {
		fmt.Printf("critical: %v cert expires in %v days\n", source, expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	if timeNow.AddDate(0, 0, plugin.Warning).After(cert.NotAfter) {
		fmt.Printf("warning: %v cert expires in %v days\n", source, expiresInDays)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("ok: %v cert expires in %v days\n", source, expiresInDays)
	return sensu.CheckStateOK, nil
}
