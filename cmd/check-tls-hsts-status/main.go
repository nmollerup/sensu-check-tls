package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

type Config struct {
	sensu.PluginConfig
	Domain   string
	Critical string
	Warn     string
	APIURL   string
}

// statusRank maps HSTS preload status to a numeric rank (higher = better).
var statusRank = map[string]int{
	"unknown":   0,
	"pending":   1,
	"preloaded": 2,
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-hsts-status",
			Short:    "Check a domain's HSTS preload status via the hstspreload.org API",
			Keyspace: "sensu.io/plugins/check-tls-hsts-status/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Argument:  "domain",
			Shorthand: "d",
			Usage:     "Domain to check",
			Value:     &plugin.Domain,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "critical",
			Shorthand: "c",
			Default:   "unknown",
			Usage:     "CRITICAL if status is at or below this level (unknown, pending, preloaded)",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "warn",
			Shorthand: "w",
			Default:   "pending",
			Usage:     "WARNING if status is at or below this level (unknown, pending, preloaded)",
			Value:     &plugin.Warn,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "api-url",
			Default:  "https://hstspreload.org/api/v2/status",
			Usage:    "API endpoint URL",
			Value:    &plugin.APIURL,
		},
	}
)

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.Domain) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--domain is required")
	}
	if _, ok := statusRank[plugin.Critical]; !ok {
		return sensu.CheckStateWarning, fmt.Errorf("--critical must be one of: unknown, pending, preloaded")
	}
	if _, ok := statusRank[plugin.Warn]; !ok {
		return sensu.CheckStateWarning, fmt.Errorf("--warn must be one of: unknown, pending, preloaded")
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	u, err := url.Parse(plugin.APIURL)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("invalid API URL: %v", err)
	}
	q := u.Query()
	q.Set("domain", plugin.Domain)
	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String()) //nolint:gosec
	if err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("API request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("reading API response: %v", err)
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("parsing API response: %v", err)
	}

	rank, ok := statusRank[result.Status]
	if !ok {
		fmt.Printf("warning: invalid status returned: %v\n", result.Status)
		return sensu.CheckStateWarning, nil
	}

	if rank <= statusRank[plugin.Critical] {
		fmt.Printf("critical: %v HSTS status is %v\n", plugin.Domain, result.Status)
		return sensu.CheckStateCritical, nil
	}
	if rank <= statusRank[plugin.Warn] {
		fmt.Printf("warning: %v HSTS status is %v\n", plugin.Domain, result.Status)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("ok: %v HSTS status is %v\n", plugin.Domain, result.Status)
	return sensu.CheckStateOK, nil
}
