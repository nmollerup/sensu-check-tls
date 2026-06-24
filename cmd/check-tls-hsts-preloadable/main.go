package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

type Config struct {
	sensu.PluginConfig
	Domain string
	APIURL string
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-hsts-preloadable",
			Short:    "Check if a domain is preloadable for HSTS via the hstspreload.org API",
			Keyspace: "sensu.io/plugins/check-tls-hsts-preloadable/config",
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
			Argument: "api-url",
			Default:  "https://hstspreload.org/api/v2/preloadable",
			Usage:    "API endpoint URL",
			Value:    &plugin.APIURL,
		},
	}
)

type preloadableResponse struct {
	Errors   []struct{ Summary string `json:"summary"` } `json:"errors"`
	Warnings []struct{ Summary string `json:"summary"` } `json:"warnings"`
}

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.Domain) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--domain is required")
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

	var result preloadableResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("parsing API response: %v", err)
	}

	if len(result.Errors) > 0 {
		summaries := make([]string, len(result.Errors))
		for i, e := range result.Errors {
			summaries[i] = e.Summary
		}
		fmt.Printf("critical: %v\n", strings.Join(summaries, ", "))
		return sensu.CheckStateCritical, nil
	}
	if len(result.Warnings) > 0 {
		summaries := make([]string, len(result.Warnings))
		for i, w := range result.Warnings {
			summaries[i] = w.Summary
		}
		fmt.Printf("warning: %v\n", strings.Join(summaries, ", "))
		return sensu.CheckStateWarning, nil
	}

	fmt.Printf("ok: %v is preloadable\n", plugin.Domain)
	return sensu.CheckStateOK, nil
}
