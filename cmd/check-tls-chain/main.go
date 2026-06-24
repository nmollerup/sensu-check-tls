package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

type Config struct {
	sensu.PluginConfig
	Host         string
	Port         int
	ServerName   string
	Anchor       string
	Issuer       string
	IssuerFormat string
	UseRegexp          bool
	InsecureSkipVerify bool
	Timeout            int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-chain",
			Short:    "Check TLS certificate chain anchor or root issuer",
			Keyspace: "sensu.io/plugins/check-tls-chain/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Argument:  "host",
			Shorthand: "h",
			Usage:     "Host to connect to",
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
			Argument:  "servername",
			Shorthand: "s",
			Default:   "",
			Usage:     "TLS SNI server name override (defaults to host)",
			Value:     &plugin.ServerName,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "anchor",
			Default:  "",
			Usage:    "Expected subject of the last cert in the chain (from check-ssl-anchor)",
			Value:    &plugin.Anchor,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "issuer",
			Shorthand: "i",
			Default:   "",
			Usage:     "Expected issuer DN of the root cert in the chain (from check-ssl-root-issuer)",
			Value:     &plugin.Issuer,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "issuer-format",
			Shorthand: "f",
			Default:   "RFC2253",
			Usage:     "Issuer name format: RFC2253, ONELINE, or COMPAT",
			Value:     &plugin.IssuerFormat,
		},
		&sensu.PluginConfigOption[bool]{
			Argument:  "regexp",
			Shorthand: "r",
			Default:   false,
			Usage:     "Treat --anchor or --issuer value as a regular expression",
			Value:     &plugin.UseRegexp,
		},
		&sensu.PluginConfigOption[bool]{
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "Skip TLS certificate verification (not recommended)",
			Value:     &plugin.InsecureSkipVerify,
		},
		&sensu.PluginConfigOption[int]{
			Argument: "timeout",
			Default:  15,
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
	if len(plugin.Anchor) == 0 && len(plugin.Issuer) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("one of --anchor or --issuer is required")
	}
	if len(plugin.Anchor) > 0 && len(plugin.Issuer) > 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--anchor and --issuer are mutually exclusive")
	}
	if plugin.IssuerFormat != "RFC2253" && plugin.IssuerFormat != "ONELINE" && plugin.IssuerFormat != "COMPAT" {
		return sensu.CheckStateWarning, fmt.Errorf("--issuer-format must be RFC2253, ONELINE, or COMPAT")
	}
	return sensu.CheckStateOK, nil
}

func matchValue(actual, expected string, useRegexp bool) (bool, error) {
	if useRegexp {
		re, err := regexp.Compile(expected)
		if err != nil {
			return false, fmt.Errorf("invalid regexp %q: %v", expected, err)
		}
		return re.MatchString(actual), nil
	}
	return actual == expected, nil
}

// formatName converts a pkix.Name to a string in the requested format.
// RFC2253 uses Go's standard RDNSequence.String() (comma-separated, most specific first).
// ONELINE and COMPAT use OpenSSL-style slash-prefixed format (least specific first).
func formatName(name pkix.Name, format string) string {
	switch format {
	case "ONELINE", "COMPAT":
		return opensslOneline(name)
	default: // RFC2253
		return name.ToRDNSequence().String()
	}
}

// opensslOneline produces a slash-prefixed DN similar to OpenSSL's one-line format:
// /C=US/O=Example/CN=Root CA
func opensslOneline(name pkix.Name) string {
	// Build ordered list of attributes from most general to most specific.
	type kv struct{ key, val string }
	var attrs []kv

	for _, c := range name.Country {
		attrs = append(attrs, kv{"C", c})
	}
	for _, o := range name.Organization {
		attrs = append(attrs, kv{"O", o})
	}
	for _, ou := range name.OrganizationalUnit {
		attrs = append(attrs, kv{"OU", ou})
	}
	for _, l := range name.Locality {
		attrs = append(attrs, kv{"L", l})
	}
	for _, s := range name.Province {
		attrs = append(attrs, kv{"ST", s})
	}
	if name.CommonName != "" {
		attrs = append(attrs, kv{"CN", name.CommonName})
	}

	parts := make([]string, len(attrs))
	for i, a := range attrs {
		parts[i] = a.key + "=" + a.val
	}
	return "/" + strings.Join(parts, "/")
}

func executeCheck(event *corev2.Event) (int, error) {
	sni := plugin.ServerName
	if sni == "" {
		sni = plugin.Host
	}
	dialAddr := net.JoinHostPort(plugin.Host, fmt.Sprint(plugin.Port))
	dialer := &net.Dialer{Timeout: time.Duration(plugin.Timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{ServerName: sni, InsecureSkipVerify: plugin.InsecureSkipVerify}) //nolint:gosec
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("connection failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return sensu.CheckStateCritical, fmt.Errorf("no certificates returned by server")
	}
	root := chain[len(chain)-1]

	if len(plugin.Anchor) > 0 {
		actual := root.Subject.ToRDNSequence().String()
		matched, err := matchValue(actual, plugin.Anchor, plugin.UseRegexp)
		if err != nil {
			return sensu.CheckStateCritical, err
		}
		if matched {
			fmt.Println("ok: root anchor has been found")
			return sensu.CheckStateOK, nil
		}
		fmt.Printf("critical: root anchor did not match %q\nfound %q instead\n", plugin.Anchor, actual)
		return sensu.CheckStateCritical, nil
	}

	actual := formatName(root.Issuer, plugin.IssuerFormat)
	matched, err := matchValue(actual, plugin.Issuer, plugin.UseRegexp)
	if err != nil {
		return sensu.CheckStateCritical, err
	}
	if matched {
		fmt.Println("ok: root certificate has expected issuer name")
		return sensu.CheckStateOK, nil
	}
	fmt.Printf("critical: root issuer did not match %q\nfound %q instead\n", plugin.Issuer, actual)
	return sensu.CheckStateCritical, nil
}

