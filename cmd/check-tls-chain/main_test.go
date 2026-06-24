package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// TestCheckArgs validates flag validation logic.
func TestCheckArgs(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantStatus  int
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing host",
			config:      Config{Anchor: "test"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--host is required",
		},
		{
			name:        "neither anchor nor issuer",
			config:      Config{Host: "example.com"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "one of --anchor or --issuer is required",
		},
		{
			name:        "both anchor and issuer",
			config:      Config{Host: "example.com", Anchor: "a", Issuer: "b", IssuerFormat: "RFC2253"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--anchor and --issuer are mutually exclusive",
		},
		{
			name:        "invalid issuer format",
			config:      Config{Host: "example.com", Issuer: "test", IssuerFormat: "BADFORMAT"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--issuer-format must be RFC2253, ONELINE, or COMPAT",
		},
		{
			name:       "valid anchor config",
			config:     Config{Host: "example.com", Anchor: "CN=Test", IssuerFormat: "RFC2253"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "valid issuer config RFC2253",
			config:     Config{Host: "example.com", Issuer: "CN=Test", IssuerFormat: "RFC2253"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "valid issuer config ONELINE",
			config:     Config{Host: "example.com", Issuer: "/CN=Test", IssuerFormat: "ONELINE"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "valid issuer config COMPAT",
			config:     Config{Host: "example.com", Issuer: "/CN=Test", IssuerFormat: "COMPAT"},
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

// TestMatchValue tests exact and regexp matching.
func TestMatchValue(t *testing.T) {
	tests := []struct {
		name      string
		actual    string
		expected  string
		useRegexp bool
		wantMatch bool
		wantErr   bool
	}{
		{"exact match", "CN=Root CA", "CN=Root CA", false, true, false},
		{"exact mismatch", "CN=Root CA", "CN=Other CA", false, false, false},
		{"regexp match", "CN=Root CA X3", `CN=Root CA X\d`, true, true, false},
		{"regexp no match", "CN=Root CA", `CN=Leaf.*`, true, false, false},
		{"invalid regexp", "test", `[invalid`, true, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := matchValue(tt.actual, tt.expected, tt.useRegexp)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && matched != tt.wantMatch {
				t.Errorf("matchValue() matched = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

// TestOpensslOneline tests the OpenSSL-style DN formatter.
func TestOpensslOneline(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Test Org"},
		OrganizationalUnit: []string{"Engineering"},
		CommonName:         "Root CA",
	}
	result := opensslOneline(name)

	if !strings.HasPrefix(result, "/") {
		t.Errorf("opensslOneline() result %q does not start with /", result)
	}
	if !strings.Contains(result, "C=US") {
		t.Errorf("opensslOneline() result %q missing C=US", result)
	}
	if !strings.Contains(result, "O=Test Org") {
		t.Errorf("opensslOneline() result %q missing O=Test Org", result)
	}
	if !strings.Contains(result, "CN=Root CA") {
		t.Errorf("opensslOneline() result %q missing CN=Root CA", result)
	}
}

// TestFormatName tests that all issuer formats produce non-empty output.
func TestFormatName(t *testing.T) {
	name := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Internet Security Research Group"},
		CommonName:   "ISRG Root X1",
	}

	for _, format := range []string{"RFC2253", "ONELINE", "COMPAT"} {
		t.Run(format, func(t *testing.T) {
			result := formatName(name, format)
			if result == "" {
				t.Errorf("formatName(%q) returned empty string", format)
			}
		})
	}
}

// TestExecuteCheck tests the chain check against a local TLS server.
func TestExecuteCheck(t *testing.T) {
	host, port, serverSubject, cleanup := startChainServer(t)
	defer cleanup()

	t.Run("anchor match", func(t *testing.T) {
		plugin = Config{
			Host:               host,
			Port:               port,
			Anchor:             serverSubject,
			IssuerFormat:       "RFC2253",
			InsecureSkipVerify: true,
			Timeout:            5,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateOK {
			t.Errorf("executeCheck() status = %v, want OK", status)
		}
	})

	t.Run("anchor no match", func(t *testing.T) {
		plugin = Config{
			Host:               host,
			Port:               port,
			Anchor:             "CN=NonExistentCA",
			IssuerFormat:       "RFC2253",
			InsecureSkipVerify: true,
			Timeout:            5,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("executeCheck() status = %v, want Critical", status)
		}
	})

	t.Run("anchor regexp match", func(t *testing.T) {
		plugin = Config{
			Host:               host,
			Port:               port,
			Anchor:             "Test",
			IssuerFormat:       "RFC2253",
			UseRegexp:          true,
			InsecureSkipVerify: true,
			Timeout:            5,
		}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("executeCheck() error: %v", err)
		}
		if status != sensu.CheckStateOK {
			t.Errorf("executeCheck() status = %v, want OK", status)
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		plugin = Config{
			Host:         "127.0.0.1",
			Port:         1,
			Anchor:       "test",
			IssuerFormat: "RFC2253",
			Timeout:      2,
		}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for failed connection")
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})
}

// startChainServer starts a TLS server with a self-signed cert and returns the
// subject string of its certificate for use in anchor tests.
func startChainServer(t *testing.T) (host string, port int, subjectRFC2253 string, cleanup func()) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	subjectRFC2253 = cert.Subject.ToRDNSequence().String()

	tlsCert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
				_ = c.Close()
			}(conn)
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, subjectRFC2253, func() { _ = l.Close() }
}
