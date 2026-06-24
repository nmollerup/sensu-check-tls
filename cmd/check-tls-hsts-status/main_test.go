package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// TestCheckArgs validates flag validation.
func TestCheckArgs(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantStatus  int
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing domain",
			config:      Config{Critical: "unknown", Warn: "pending"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--domain is required",
		},
		{
			name:        "invalid critical threshold",
			config:      Config{Domain: "example.com", Critical: "bad", Warn: "pending"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--critical must be one of",
		},
		{
			name:        "invalid warn threshold",
			config:      Config{Domain: "example.com", Critical: "unknown", Warn: "bad"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warn must be one of",
		},
		{
			name:       "valid config defaults",
			config:     Config{Domain: "example.com", Critical: "unknown", Warn: "pending"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "all valid statuses accepted",
			config:     Config{Domain: "example.com", Critical: "unknown", Warn: "preloaded"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin = tt.config
			status, err := checkArgs(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if status != tt.wantStatus {
				t.Errorf("checkArgs() status = %v, want %v", status, tt.wantStatus)
			}
			if tt.wantErr && tt.errContains != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

// TestExecuteCheck tests status threshold logic with a mock API server.
func TestExecuteCheck(t *testing.T) {
	tests := []struct {
		name       string
		apiStatus  string
		critical   string
		warn       string
		wantStatus int
	}{
		// defaults: critical=unknown, warn=pending
		{"preloaded is ok", "preloaded", "unknown", "pending", sensu.CheckStateOK},
		{"pending is warning", "pending", "unknown", "pending", sensu.CheckStateWarning},
		{"unknown is critical", "unknown", "unknown", "pending", sensu.CheckStateCritical},

		// stricter thresholds: warn=preloaded means even preloaded triggers a warning
		{"preloaded warns when warn=preloaded", "preloaded", "pending", "preloaded", sensu.CheckStateWarning},
		{"pending critical when critical=pending", "pending", "pending", "preloaded", sensu.CheckStateCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiStatus := tt.apiStatus
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"status": apiStatus})
			}))
			defer srv.Close()

			plugin = Config{
				Domain:   "example.com",
				Critical: tt.critical,
				Warn:     tt.warn,
				APIURL:   srv.URL,
			}
			status, err := executeCheck(nil)
			if err != nil {
				t.Fatalf("executeCheck() unexpected error: %v", err)
			}
			if status != tt.wantStatus {
				t.Errorf("executeCheck() status = %v, want %v (apiStatus=%q)", status, tt.wantStatus, tt.apiStatus)
			}
		})
	}

	t.Run("unknown API status returns warning", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "invalid_status"})
		}))
		defer srv.Close()

		plugin = Config{Domain: "example.com", Critical: "unknown", Warn: "pending", APIURL: srv.URL}
		status, _ := executeCheck(nil)
		if status != sensu.CheckStateWarning {
			t.Errorf("status = %v, want Warning for unknown API status", status)
		}
	})

	t.Run("API request failure returns warning", func(t *testing.T) {
		plugin = Config{Domain: "example.com", Critical: "unknown", Warn: "pending", APIURL: "http://127.0.0.1:1"}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for unreachable API")
		}
		if status != sensu.CheckStateWarning {
			t.Errorf("status = %v, want Warning", status)
		}
	})
}
