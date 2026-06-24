package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
			config:      Config{Warn: "A-", Critical: "B"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--domain is required",
		},
		{
			name:        "invalid warn grade",
			config:      Config{Domain: "example.com", Warn: "Z", Critical: "B"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warn is not a valid grade",
		},
		{
			name:        "invalid critical grade",
			config:      Config{Domain: "example.com", Warn: "A-", Critical: "Z"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--critical is not a valid grade",
		},
		{
			name:       "valid defaults",
			config:     Config{Domain: "example.com", Warn: "A-", Critical: "B"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "all grades valid",
			config:     Config{Domain: "example.com", Warn: "A+", Critical: "A"},
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

// TestGradeRank verifies grade ordering (lower index = better grade).
func TestGradeRank(t *testing.T) {
	tests := []struct {
		grade    string
		wantRank int
	}{
		{"A+", 0},
		{"A", 1},
		{"A-", 2},
		{"B", 3},
		{"F", 7},
		{"M", 9},
	}

	for _, tt := range tests {
		t.Run(tt.grade, func(t *testing.T) {
			if got := gradeRank(tt.grade); got != tt.wantRank {
				t.Errorf("gradeRank(%q) = %d, want %d", tt.grade, got, tt.wantRank)
			}
		})
	}

	t.Run("unknown grade ranks worst", func(t *testing.T) {
		r := gradeRank("X")
		if r != len(gradeOptions) {
			t.Errorf("gradeRank(unknown) = %d, want %d", r, len(gradeOptions))
		}
	})

	t.Run("A is better than B", func(t *testing.T) {
		if gradeRank("A") >= gradeRank("B") {
			t.Error("expected gradeRank(A) < gradeRank(B)")
		}
	})
}

// TestExecuteCheck tests the polling logic against a mock Qualys API.
func TestExecuteCheck(t *testing.T) {
	t.Run("immediate READY result - ok", func(t *testing.T) {
		srv := newMockQualysServer("READY", "A", 1)
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "B",
			NumChecks:   5,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateOK {
			t.Errorf("status = %v, want OK", status)
		}
	})

	t.Run("grade below warn threshold - warning", func(t *testing.T) {
		srv := newMockQualysServer("READY", "B", 1)
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "C",
			NumChecks:   5,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateWarning {
			t.Errorf("status = %v, want Warning", status)
		}
	})

	t.Run("grade below critical threshold - critical", func(t *testing.T) {
		srv := newMockQualysServer("READY", "F", 1)
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "B",
			NumChecks:   5,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})

	t.Run("polling: IN_PROGRESS then READY", func(t *testing.T) {
		// First call returns IN_PROGRESS, second returns READY
		var callCount atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := callCount.Add(1)
			resp := analyzeResponse{Endpoints: []struct {
				Grade string `json:"grade"`
				ETA   int    `json:"eta"`
			}{{Grade: "A", ETA: 0}}}
			if n == 1 {
				resp.Status = "IN_PROGRESS"
				resp.Endpoints[0].Grade = ""
			} else {
				resp.Status = "READY"
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "B",
			NumChecks:   5,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateOK {
			t.Errorf("status = %v, want OK", status)
		}
		if callCount.Load() < 2 {
			t.Error("expected at least 2 API calls for polling scenario")
		}
	})

	t.Run("max checks exceeded returns warning", func(t *testing.T) {
		srv := newMockQualysServer("IN_PROGRESS", "", 999)
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "B",
			NumChecks:   2,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error when max checks exceeded")
		}
		if status != sensu.CheckStateWarning {
			t.Errorf("status = %v, want Warning", status)
		}
	})

	t.Run("API error status returns warning", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(analyzeResponse{Status: "ERROR"})
		}))
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "B",
			NumChecks:   5,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for API ERROR status")
		}
		if status != sensu.CheckStateWarning {
			t.Errorf("status = %v, want Warning", status)
		}
	})

	t.Run("no rated endpoints returns critical", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(analyzeResponse{
				Status: "READY",
				Endpoints: []struct {
					Grade string `json:"grade"`
					ETA   int    `json:"eta"`
				}{{Grade: ""}},
			})
		}))
		defer srv.Close()

		plugin = Config{
			Domain:      "example.com",
			APIURL:      srv.URL + "/",
			Warn:        "A-",
			Critical:    "B",
			NumChecks:   5,
			TimeBetween: 0,
			Timeout:     30,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() unexpected error: %v", err)
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical for unrated domain", status)
		}
	})
}

// newMockQualysServer creates a test server that always returns the given status and grade.
func newMockQualysServer(status, grade string, _ int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := analyzeResponse{
			Status: status,
			Endpoints: []struct {
				Grade string `json:"grade"`
				ETA   int    `json:"eta"`
			}{{Grade: grade, ETA: 0}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}
