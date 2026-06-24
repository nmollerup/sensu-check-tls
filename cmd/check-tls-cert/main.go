package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/go-playground/validator/v10"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	Host               string
	IP                 string
	ServerName         string
	TrustedCAFile      string
	PemFile            string
	PKCS12File         string
	PKCS12Pass         string
	InsecureSkipVerify bool
	Port               int
	Timeout            int
	Warning            int
	Critical           int
}

var (
	tlsConfig tls.Config

	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-cert",
			Short:    "TLS expiry check",
			Keyspace: "sensu.io/plugins/http-check/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Path:     "hostname",
			Argument: "hostname",
			Default:  "",
			Usage:    "Hostname to check (required unless --pem or --pkcs12 is set)",
			Value:    &plugin.Host,
		},
		&sensu.PluginConfigOption[string]{
			Path:     "ip",
			Argument: "ip",
			Default:  "",
			Usage:    "IP address to connect to (overrides DNS resolution, hostname still used for TLS SNI)",
			Value:    &plugin.IP,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "servername",
			Argument:  "servername",
			Shorthand: "s",
			Default:   "",
			Usage:     "TLS SNI server name override (defaults to hostname)",
			Value:     &plugin.ServerName,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "insecure-skip-verify",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "Skip TLS certificate verification (not recommended)",
			Value:     &plugin.InsecureSkipVerify,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "trusted-ca-file",
			Argument:  "trusted-ca-file",
			Shorthand: "t",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &plugin.TrustedCAFile,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "pem",
			Argument:  "pem",
			Shorthand: "P",
			Default:   "",
			Usage:     "Path to PEM certificate file to check (no network connection needed)",
			Value:     &plugin.PemFile,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "pkcs12",
			Argument:  "pkcs12",
			Shorthand: "C",
			Default:   "",
			Usage:     "Path to PKCS#12 certificate file to check (no network connection needed)",
			Value:     &plugin.PKCS12File,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "pass",
			Argument:  "pass",
			Shorthand: "S",
			Default:   "",
			Usage:     "Passphrase for PKCS#12 certificate private key",
			Value:     &plugin.PKCS12Pass,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "",
			Argument:  "warning",
			Shorthand: "w",
			Usage:     "Number of days before expiry to warn",
			Value:     &plugin.Warning,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "",
			Argument:  "critical",
			Shorthand: "c",
			Usage:     "Number of days before expiry to go critical",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "",
			Argument:  "port",
			Shorthand: "p",
			Default:   443,
			Usage:     "TCP port to connect to",
			Value:     &plugin.Port,
		},
		&sensu.PluginConfigOption[int]{
			Path:    "",
			Argument: "timeout",
			Default: 15,
			Usage:   "Connection timeout in seconds",
			Value:   &plugin.Timeout,
		},
	}
)

var validate *validator.Validate

func main() {
	validate = validator.New()

	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if plugin.Critical <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--critical is required")
	}
	if plugin.Warning <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--warning is required")
	}
	if plugin.Warning <= plugin.Critical {
		return sensu.CheckStateWarning, fmt.Errorf("--warning must be greater than --critical")
	}

	// File-based modes skip network validation
	if len(plugin.PemFile) > 0 || len(plugin.PKCS12File) > 0 {
		if len(plugin.PKCS12File) > 0 && len(plugin.PKCS12Pass) == 0 {
			return sensu.CheckStateWarning, fmt.Errorf("--pass is required with --pkcs12")
		}
		return sensu.CheckStateOK, nil
	}

	// Network mode
	if len(plugin.Host) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--hostname is required (or use --pem / --pkcs12)")
	}
	err := validate.Var(plugin.Host, "fqdn")
	if err != nil {
		err = validate.Var(plugin.Host, "ip")
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("hostname is not a valid FQDN or IP address")
		}
	}
	if len(plugin.IP) > 0 {
		if err := validate.Var(plugin.IP, "ip"); err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("--ip is not a valid IP address")
		}
	}
	if len(plugin.TrustedCAFile) > 0 {
		caCertPool, err := corev2.LoadCACerts(plugin.TrustedCAFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = plugin.InsecureSkipVerify
	sni := plugin.ServerName
	if sni == "" {
		sni = plugin.Host
	}
	tlsConfig.ServerName = sni

	return sensu.CheckStateOK, nil
}

func parsePemCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func checkExpiry(cert *x509.Certificate, source string) (int, error) {
	timeNow := time.Now()
	expiresInDays := int(cert.NotAfter.Sub(timeNow).Hours() / 24)

	if expiresInDays < 0 {
		fmt.Printf("critical: cert %v expired %v days ago\n", source, -expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	if timeNow.AddDate(0, 0, plugin.Critical).After(cert.NotAfter) {
		fmt.Printf("critical: cert %v expires in %v days\n", source, expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	if timeNow.AddDate(0, 0, plugin.Warning).After(cert.NotAfter) {
		fmt.Printf("warning: cert %v expires in %v days\n", source, expiresInDays)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("ok: cert %v expires in %v days\n", source, expiresInDays)
	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	if len(plugin.PemFile) > 0 {
		data, err := os.ReadFile(plugin.PemFile)
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("cannot read PEM file: %v", err)
		}
		cert, err := parsePemCert(data)
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("cannot parse PEM certificate: %v", err)
		}
		return checkExpiry(cert, plugin.PemFile)
	}

	if len(plugin.PKCS12File) > 0 {
		data, err := os.ReadFile(plugin.PKCS12File)
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("cannot read PKCS#12 file: %v", err)
		}
		_, cert, err := pkcs12.Decode(data, plugin.PKCS12Pass)
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("cannot parse PKCS#12 file: %v", err)
		}
		return checkExpiry(cert, plugin.PKCS12File)
	}

	// Network mode
	var dialAddress string
	if len(plugin.IP) > 0 {
		dialAddress = net.JoinHostPort(plugin.IP, fmt.Sprint(plugin.Port))
	} else {
		dialAddress = net.JoinHostPort(plugin.Host, fmt.Sprint(plugin.Port))
	}

	dialer := &net.Dialer{Timeout: time.Duration(plugin.Timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddress, &tlsConfig)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("%v", err)
	}
	defer func() { _ = conn.Close() }()

	cert := conn.ConnectionState().PeerCertificates[0]
	return checkExpiry(cert, fmt.Sprintf("%v:%v", plugin.Host, plugin.Port))
}
