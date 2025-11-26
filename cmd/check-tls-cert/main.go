package main

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	Host               string
	TrustedCAFile      string
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
			Default:  "http://localhost:80/",
			Usage:    "hostname to check",
			Value:    &plugin.Host,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "insecure-skip-verify",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "Skip TLS certificate verification (not recommended!)",
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
		&sensu.PluginConfigOption[int]{
			Path:      "",
			Argument:  "warning",
			Shorthand: "w",
			Usage:     "Number of days left",
			Value:     &plugin.Warning,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "",
			Argument:  "critical",
			Shorthand: "c",
			Usage:     "Number of days left",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "",
			Argument:  "port",
			Shorthand: "p",
			Default:   443,
			Usage:     "TCP port to connect to, default 443",
			Value:     &plugin.Port,
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
	if len(plugin.Host) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--hostname is required")
	}
	err := validate.Var(plugin.Host, "fqdn")
	if err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("hostname is not a valid FQDN")
	}
	if plugin.Critical <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--critical is required")
	}
	if plugin.Warning <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--warning is required")
	}
	if plugin.Warning <= plugin.Critical {
		return sensu.CheckStateWarning, fmt.Errorf("warning cannot be lower than Critical value")
	}
	if len(plugin.TrustedCAFile) > 0 {
		caCertPool, err := corev2.LoadCACerts(plugin.TrustedCAFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = plugin.InsecureSkipVerify

	return sensu.CheckStateOK, nil
}
func executeCheck(event *corev2.Event) (int, error) {
	fqdn := plugin.Host + ":" + fmt.Sprint(plugin.Port)
	conn, err := tls.Dial("tcp", fqdn, &tlsConfig)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("%v", err)
	}
	defer func() {
		_ = conn.Close()
	} ()

	timeNow := time.Now()

	cert := conn.ConnectionState().PeerCertificates[0]

	// Get expiry time in hours
	expiresInHours := int64(cert.NotAfter.Sub(timeNow).Hours())
	expiresInDays := int(expiresInHours / 24)
	// Check the expiration.
	// Check critical threshold first (more severe)
	if timeNow.AddDate(0, 0, plugin.Critical).After(cert.NotAfter) {
		fmt.Printf("critical: cert expires in %v days", expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	// Then check warning threshold
	if timeNow.AddDate(0, 0, plugin.Warning).After(cert.NotAfter) {
		fmt.Printf("warning: cert expires in %v days", expiresInDays)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("certificate for %v:%v expires in %v days\n", plugin.Host, plugin.Port, expiresInDays)
	return sensu.CheckStateOK, nil
}
