package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

type Config struct {
	sensu.PluginConfig
	URL      string
	Critical int
	Warning  int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-crl",
			Short:    "Check when a Certificate Revocation List (CRL) will expire",
			Keyspace: "sensu.io/plugins/check-tls-crl/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Argument:  "url",
			Shorthand: "u",
			Usage:     "URL or file path to the CRL (http://, https://, or local path)",
			Value:     &plugin.URL,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "critical",
			Shorthand: "c",
			Usage:     "Minutes before CRL expiry to go critical",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "warning",
			Shorthand: "w",
			Usage:     "Minutes before CRL expiry to warn",
			Value:     &plugin.Warning,
		},
	}
)

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.URL) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--url is required")
	}
	if plugin.Critical <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--critical is required")
	}
	if plugin.Warning <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--warning is required")
	}
	if plugin.Warning < plugin.Critical {
		return sensu.CheckStateWarning, fmt.Errorf("--warning cannot be less than --critical")
	}
	return sensu.CheckStateOK, nil
}

func fetchCRL() ([]byte, error) {
	u, err := url.Parse(plugin.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return os.ReadFile(plugin.URL)
	}
	resp, err := http.Get(plugin.URL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("fetching CRL from %v: %v", plugin.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %v fetching %v", resp.Status, plugin.URL)
	}
	return io.ReadAll(resp.Body)
}

func executeCheck(event *corev2.Event) (int, error) {
	data, err := fetchCRL()
	if err != nil {
		return sensu.CheckStateCritical, err
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("cannot parse CRL from %v: %v", plugin.URL, err)
	}

	minutesUntil := int(time.Until(crl.NextUpdate).Minutes())

	if minutesUntil < 0 {
		fmt.Printf("critical: %v - expired %v minutes ago\n", plugin.URL, -minutesUntil)
		return sensu.CheckStateCritical, nil
	}
	if minutesUntil < plugin.Critical {
		fmt.Printf("critical: %v - %v minutes left, next update at %v\n", plugin.URL, minutesUntil, crl.NextUpdate)
		return sensu.CheckStateCritical, nil
	}
	if minutesUntil < plugin.Warning {
		fmt.Printf("warning: %v - %v minutes left, next update at %v\n", plugin.URL, minutesUntil, crl.NextUpdate)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("ok: %v - %v minutes left, next update at %v\n", plugin.URL, minutesUntil, crl.NextUpdate)
	return sensu.CheckStateOK, nil
}
