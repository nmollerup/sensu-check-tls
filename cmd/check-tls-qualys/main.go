package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// gradeOptions lists Qualys SSL Labs grades from best to worst.
var gradeOptions = []string{"A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"}

func gradeRank(grade string) int {
	for i, g := range gradeOptions {
		if g == grade {
			return i
		}
	}
	return len(gradeOptions) // unknown grade ranks worst
}

type Config struct {
	sensu.PluginConfig
	Domain       string
	APIURL       string
	Warn         string
	Critical     string
	NumChecks    int
	TimeBetween  int
	Timeout      int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-qualys",
			Short:    "Check TLS grade via the Qualys SSL Labs API",
			Keyspace: "sensu.io/plugins/check-tls-qualys/config",
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
			Default:  "https://api.ssllabs.com/api/v3/",
			Usage:    "Qualys SSL Labs API base URL",
			Value:    &plugin.APIURL,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "warn",
			Shorthand: "w",
			Default:   "A-",
			Usage:     "WARNING if grade is worse than this (e.g. A-)",
			Value:     &plugin.Warn,
		},
		&sensu.PluginConfigOption[string]{
			Argument:  "critical",
			Shorthand: "c",
			Default:   "B",
			Usage:     "CRITICAL if grade is worse than this (e.g. B)",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "num-checks",
			Shorthand: "n",
			Default:   24,
			Usage:     "Maximum number of API poll attempts before giving up",
			Value:     &plugin.NumChecks,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "time-between",
			Shorthand: "t",
			Default:   10,
			Usage:     "Seconds to wait between API polls (API-provided ETA takes precedence if higher)",
			Value:     &plugin.TimeBetween,
		},
		&sensu.PluginConfigOption[int]{
			Argument: "timeout",
			Default:  300,
			Usage:    "Overall timeout in seconds for the entire check",
			Value:    &plugin.Timeout,
		},
	}
)

type analyzeResponse struct {
	Status    string `json:"status"`
	Endpoints []struct {
		Grade string `json:"grade"`
		ETA   int    `json:"eta"`
	} `json:"endpoints"`
}

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.Domain) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--domain is required")
	}
	if gradeRank(plugin.Warn) >= len(gradeOptions) {
		return sensu.CheckStateWarning, fmt.Errorf("--warn is not a valid grade (valid: %v)", gradeOptions)
	}
	if gradeRank(plugin.Critical) >= len(gradeOptions) {
		return sensu.CheckStateWarning, fmt.Errorf("--critical is not a valid grade (valid: %v)", gradeOptions)
	}
	return sensu.CheckStateOK, nil
}

func apiRequest(ctx context.Context, startNew bool) (*analyzeResponse, error) {
	params := url.Values{"host": {plugin.Domain}}
	if startNew {
		params.Set("startNew", "on")
	} else {
		params.Set("startNew", "off")
	}

	u := plugin.APIURL + "analyze?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %v", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %v", err)
	}
	var result analyzeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %v", err)
	}
	return &result, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(plugin.Timeout)*time.Second)
	defer cancel()

	var result *analyzeResponse
	var err error

	for step := 1; step <= plugin.NumChecks; step++ {
		result, err = apiRequest(ctx, step == 1)
		if err != nil {
			return sensu.CheckStateWarning, err
		}
		if result.Status == "ERROR" {
			return sensu.CheckStateWarning, fmt.Errorf("qualys API reported ERROR for %v", plugin.Domain)
		}
		if result.Status == "READY" {
			break
		}

		if step == plugin.NumChecks {
			return sensu.CheckStateWarning, fmt.Errorf("timeout waiting for Qualys analysis of %v after %d attempts", plugin.Domain, plugin.NumChecks)
		}

		sleepSecs := plugin.TimeBetween
		if len(result.Endpoints) > 0 && result.Endpoints[0].ETA > plugin.TimeBetween {
			sleepSecs = result.Endpoints[0].ETA
		}
		select {
		case <-ctx.Done():
			return sensu.CheckStateWarning, fmt.Errorf("timeout waiting for Qualys analysis of %v", plugin.Domain)
		case <-time.After(time.Duration(sleepSecs) * time.Second):
		}
	}

	// Find lowest (worst) grade across all endpoints
	worstRank := -1
	worstGrade := ""
	for _, ep := range result.Endpoints {
		if ep.Grade == "" {
			continue
		}
		r := gradeRank(ep.Grade)
		if r > worstRank {
			worstRank = r
			worstGrade = ep.Grade
		}
	}

	if worstGrade == "" {
		fmt.Printf("critical: %v has no rated endpoints\n", plugin.Domain)
		return sensu.CheckStateCritical, nil
	}

	fmt.Printf("%v rated %v\n", plugin.Domain, worstGrade)

	if worstRank > gradeRank(plugin.Critical) {
		fmt.Printf("critical: grade %v is worse than critical threshold %v\n", worstGrade, plugin.Critical)
		return sensu.CheckStateCritical, nil
	}
	if worstRank > gradeRank(plugin.Warn) {
		fmt.Printf("warning: grade %v is worse than warning threshold %v\n", worstGrade, plugin.Warn)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("ok: grade %v meets threshold\n", worstGrade)
	return sensu.CheckStateOK, nil
}
