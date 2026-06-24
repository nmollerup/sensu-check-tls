package main

import (
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
			name:        "missing path",
			config:      Config{Alias: "mycert", Password: "pass", Warning: 30, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--path is required",
		},
		{
			name:        "missing alias",
			config:      Config{Path: "/etc/keystore.jks", Password: "pass", Warning: 30, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--alias is required",
		},
		{
			name:        "missing password",
			config:      Config{Path: "/etc/keystore.jks", Alias: "mycert", Warning: 30, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--password is required",
		},
		{
			name:        "missing critical",
			config:      Config{Path: "/etc/keystore.jks", Alias: "mycert", Password: "pass", Warning: 30},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--critical is required",
		},
		{
			name:        "missing warning",
			config:      Config{Path: "/etc/keystore.jks", Alias: "mycert", Password: "pass", Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning is required",
		},
		{
			name:        "warning less than critical",
			config:      Config{Path: "/etc/keystore.jks", Alias: "mycert", Password: "pass", Warning: 5, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning cannot be less than --critical",
		},
		{
			name:       "valid config",
			config:     Config{Path: "/etc/keystore.jks", Alias: "mycert", Password: "pass", Warning: 30, Critical: 7},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "warning equals critical is valid",
			config:     Config{Path: "/etc/keystore.jks", Alias: "mycert", Password: "pass", Warning: 7, Critical: 7},
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

// TestExtractPEM verifies the PEM extraction helper used to parse keytool output.
func TestExtractPEM(t *testing.T) {
	validPEM := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----"

	t.Run("extracts PEM block from keytool output", func(t *testing.T) {
		keytoolOutput := "Your keystore contains 1 entry\n\n" + validPEM + "\n"
		result := extractPEM(keytoolOutput)
		if result == "" {
			t.Error("extractPEM() returned empty string for valid keytool output")
		}
		if !strings.HasPrefix(result, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("extractPEM() result = %q, want it to start with BEGIN CERTIFICATE", result)
		}
		if !strings.HasSuffix(result, "-----END CERTIFICATE-----") {
			t.Errorf("extractPEM() result = %q, want it to end with END CERTIFICATE", result)
		}
	})

	t.Run("returns empty string when no PEM block present", func(t *testing.T) {
		result := extractPEM("no certificate here")
		if result != "" {
			t.Errorf("extractPEM() = %q, want empty string", result)
		}
	})

	t.Run("returns empty string when only BEGIN present", func(t *testing.T) {
		result := extractPEM("-----BEGIN CERTIFICATE-----\ndata only")
		if result != "" {
			t.Errorf("extractPEM() = %q, want empty string (no END block)", result)
		}
	})

	t.Run("handles PEM-only input", func(t *testing.T) {
		result := extractPEM(validPEM)
		if result == "" {
			t.Error("extractPEM() returned empty string for PEM-only input")
		}
	})
}

// TestExecuteCheckWithoutKeytool verifies graceful failure when keytool is not found.
func TestExecuteCheckWithoutKeytool(t *testing.T) {
	// On systems without keytool, getCertFromKeystore should return an error.
	// On systems with keytool, it will fail to open the nonexistent keystore.
	plugin = Config{
		Path:     "/nonexistent/keystore.jks",
		Alias:    "test",
		Password: "password",
		Warning:  30,
		Critical: 7,
	}
	status, err := executeCheck(nil)
	if err == nil {
		t.Error("expected error for nonexistent keystore")
	}
	if status != sensu.CheckStateCritical {
		t.Errorf("status = %v, want Critical", status)
	}
}
