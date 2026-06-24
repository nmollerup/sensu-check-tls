package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
			name:        "missing url",
			config:      Config{Critical: 300, Warning: 600},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--url is required",
		},
		{
			name:        "missing critical",
			config:      Config{URL: "http://example.com/crl", Warning: 600},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--critical is required",
		},
		{
			name:        "missing warning",
			config:      Config{URL: "http://example.com/crl", Critical: 300},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning is required",
		},
		{
			name:        "warning less than critical",
			config:      Config{URL: "http://example.com/crl", Critical: 600, Warning: 300},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning cannot be less than --critical",
		},
		{
			name:       "valid config",
			config:     Config{URL: "http://example.com/crl", Critical: 300, Warning: 600},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "warning equals critical is valid",
			config:     Config{URL: "http://example.com/crl", Critical: 300, Warning: 300},
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
					t.Errorf("checkArgs() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

// TestFetchCRL tests fetching a CRL from a file path and via HTTP.
func TestFetchCRL(t *testing.T) {
	crlData := generateCRL(t, time.Now().Add(24*time.Hour))

	t.Run("from file", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-*.crl")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(crlData)
		_ = f.Close()
		defer func() { _ = os.Remove(f.Name()) }()

		plugin = Config{URL: f.Name()}
		data, err := fetchCRL()
		if err != nil {
			t.Fatalf("fetchCRL() unexpected error: %v", err)
		}
		if len(data) == 0 {
			t.Error("fetchCRL() returned empty data")
		}
	})

	t.Run("from HTTP", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(crlData)
		}))
		defer srv.Close()

		plugin = Config{URL: srv.URL + "/crl"}
		data, err := fetchCRL()
		if err != nil {
			t.Fatalf("fetchCRL() unexpected error: %v", err)
		}
		if len(data) == 0 {
			t.Error("fetchCRL() returned empty data")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		plugin = Config{URL: "/nonexistent/crl.crl"}
		_, err := fetchCRL()
		if err == nil {
			t.Error("fetchCRL() expected error for nonexistent file")
		}
	})

	t.Run("HTTP server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		plugin = Config{URL: srv.URL}
		_, err := fetchCRL()
		if err == nil {
			t.Error("fetchCRL() expected error for HTTP 500")
		}
	})
}

// TestExecuteCheck tests the full check flow with a temp CRL file.
func TestExecuteCheck(t *testing.T) {
	tests := []struct {
		name        string
		minutesLeft int // positive = future, negative = past
		critical    int
		warning     int
		wantStatus  int
	}{
		{"expired", -10, 300, 600, sensu.CheckStateCritical},
		{"within critical", 100, 300, 600, sensu.CheckStateCritical},
		{"within warning", 400, 300, 600, sensu.CheckStateWarning},
		{"ok", 1000, 300, 600, sensu.CheckStateOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextUpdate := time.Now().Add(time.Duration(tt.minutesLeft) * time.Minute)
			crlData := generateCRL(t, nextUpdate)

			f, err := os.CreateTemp("", "test-*.crl")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(crlData)
			_ = f.Close()
			defer func() { _ = os.Remove(f.Name()) }()

			plugin = Config{URL: f.Name(), Critical: tt.critical, Warning: tt.warning}
			status, err := executeCheck(nil)
			if err != nil {
				t.Fatalf("executeCheck() unexpected error: %v", err)
			}
			if status != tt.wantStatus {
				t.Errorf("executeCheck() status = %v, want %v (minutesLeft=%d)", status, tt.wantStatus, tt.minutesLeft)
			}
		})
	}

	t.Run("invalid CRL data returns critical", func(t *testing.T) {
		f, err := os.CreateTemp("", "bad-*.crl")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("not a crl")
		_ = f.Close()
		defer func() { _ = os.Remove(f.Name()) }()

		plugin = Config{URL: f.Name(), Critical: 300, Warning: 600}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for invalid CRL data")
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})
}

// generateCRL creates a minimal DER-encoded CRL with the given NextUpdate time.
// ThisUpdate is set to one hour before NextUpdate so the constraint ThisUpdate <= NextUpdate
// is always satisfied, even when NextUpdate is in the past.
func generateCRL(t *testing.T, nextUpdate time.Time) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	thisUpdate := nextUpdate.Add(-time.Hour)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, priv)
	if err != nil {
		t.Fatal(err)
	}
	return crlDER
}

// suppress unused import warning for pem
var _ = pem.EncodeToMemory
