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
			config:      Config{},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--domain is required",
		},
		{
			name:       "valid config",
			config:     Config{Domain: "example.com"},
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

// TestExecuteCheck tests the full check using a mock API server.
func TestExecuteCheck(t *testing.T) {
	tests := []struct {
		name       string
		response   preloadableResponse
		httpStatus int
		wantStatus int
	}{
		{
			name:       "no errors or warnings - ok",
			response:   preloadableResponse{},
			httpStatus: http.StatusOK,
			wantStatus: sensu.CheckStateOK,
		},
		{
			name: "warnings only - warning",
			response: preloadableResponse{
				Warnings: []struct{ Summary string `json:"summary"` }{
					{Summary: "Redirect to www"},
				},
			},
			httpStatus: http.StatusOK,
			wantStatus: sensu.CheckStateWarning,
		},
		{
			name: "errors present - critical",
			response: preloadableResponse{
				Errors: []struct{ Summary string `json:"summary"` }{
					{Summary: "No HTTPS"},
					{Summary: "Missing HSTS header"},
				},
			},
			httpStatus: http.StatusOK,
			wantStatus: sensu.CheckStateCritical,
		},
		{
			name: "both errors and warnings - critical",
			response: preloadableResponse{
				Errors:   []struct{ Summary string `json:"summary"` }{{Summary: "No HTTPS"}},
				Warnings: []struct{ Summary string `json:"summary"` }{{Summary: "Redirect"}},
			},
			httpStatus: http.StatusOK,
			wantStatus: sensu.CheckStateCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("domain") == "" {
					t.Error("API request missing domain query param")
				}
				w.WriteHeader(tt.httpStatus)
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()

			plugin = Config{Domain: "example.com", APIURL: srv.URL}
			status, err := executeCheck(nil)
			if err != nil {
				t.Fatalf("executeCheck() unexpected error: %v", err)
			}
			if status != tt.wantStatus {
				t.Errorf("executeCheck() status = %v, want %v", status, tt.wantStatus)
			}
		})
	}

	t.Run("API request failure returns warning", func(t *testing.T) {
		plugin = Config{Domain: "example.com", APIURL: "http://127.0.0.1:1"}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for unreachable API")
		}
		if status != sensu.CheckStateWarning {
			t.Errorf("status = %v, want Warning", status)
		}
	})
}
