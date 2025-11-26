package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// TestCheckArgs tests the argument validation logic
func TestCheckArgs(t *testing.T) {
	// Initialize validator as main() does
	validate = validator.New()

	tests := []struct {
		name        string
		config      Config
		setupFunc   func() (string, func())
		wantStatus  int
		wantErr     bool
		errContains string
	}{
		{
			name: "missing hostname",
			config: Config{
				Host:     "",
				Warning:  30,
				Critical: 7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--hostname is required",
		},
		{
			name: "invalid FQDN",
			config: Config{
				Host:     "not a valid fqdn!",
				Warning:  30,
				Critical: 7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "hostname is not a valid FQDN",
		},
		{
			name: "missing critical threshold",
			config: Config{
				Host:     "example.com",
				Warning:  30,
				Critical: 0,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--critical is required",
		},
		{
			name: "negative critical threshold",
			config: Config{
				Host:     "example.com",
				Warning:  30,
				Critical: -1,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--critical is required",
		},
		{
			name: "missing warning threshold",
			config: Config{
				Host:     "example.com",
				Warning:  0,
				Critical: 7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning is required",
		},
		{
			name: "negative warning threshold",
			config: Config{
				Host:     "example.com",
				Warning:  -1,
				Critical: 7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning is required",
		},
		{
			name: "warning less than critical",
			config: Config{
				Host:     "example.com",
				Warning:  7,
				Critical: 30,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "warning cannot be lower than Critical value",
		},
		{
			name: "warning equal to critical",
			config: Config{
				Host:     "example.com",
				Warning:  7,
				Critical: 7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "warning cannot be lower than Critical value",
		},
		{
			name: "valid configuration without CA file",
			config: Config{
				Host:     "example.com",
				Warning:  30,
				Critical: 7,
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name: "valid configuration with insecure skip verify",
			config: Config{
				Host:               "example.com",
				Warning:            30,
				Critical:           7,
				InsecureSkipVerify: true,
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name: "invalid CA file path",
			config: Config{
				Host:          "example.com",
				Warning:       30,
				Critical:      7,
				TrustedCAFile: "/nonexistent/ca.pem",
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "error loading specified CA file",
		},
		{
			name: "valid CA file",
			config: Config{
				Host:     "example.com",
				Warning:  30,
				Critical: 7,
			},
			setupFunc: func() (string, func()) {
				// Create a temporary CA file
				tmpfile, err := os.CreateTemp("", "ca-*.pem")
				if err != nil {
					t.Fatal(err)
				}

				// Generate a self-signed CA certificate
				priv, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					_ = os.Remove(tmpfile.Name())
					t.Fatal(err)
				}

				template := x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject: pkix.Name{
						Organization: []string{"Test CA"},
					},
					NotBefore:             time.Now(),
					NotAfter:              time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}

				certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
				if err != nil {
					_ = os.Remove(tmpfile.Name())
					t.Fatal(err)
				}

				_ = pem.Encode(tmpfile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
				_ = tmpfile.Close()

				return tmpfile.Name(), func() { _ = os.Remove(tmpfile.Name()) }
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global tlsConfig before each test
			tlsConfig = tls.Config{}

			// Setup if needed
			var cleanup func()
			if tt.setupFunc != nil {
				caFile, cleanupFunc := tt.setupFunc()
				tt.config.TrustedCAFile = caFile
				cleanup = cleanupFunc
				defer cleanup()
			}

			// Set the global plugin variable
			plugin = tt.config
			plugin.PluginConfig = sensu.PluginConfig{
				Name:     "check-tls-cert",
				Short:    "TLS expiry check",
				Keyspace: "sensu.io/plugins/http-check/config",
			}

			status, err := checkArgs(nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if status != tt.wantStatus {
				t.Errorf("checkArgs() status = %v, want %v", status, tt.wantStatus)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("checkArgs() error = %v, should contain %v", err, tt.errContains)
				}
			}

			// Verify tlsConfig was set correctly for successful cases
			if !tt.wantErr {
				if tt.config.InsecureSkipVerify != tlsConfig.InsecureSkipVerify {
					t.Errorf("tlsConfig.InsecureSkipVerify = %v, want %v", tlsConfig.InsecureSkipVerify, tt.config.InsecureSkipVerify)
				}

				if tt.config.TrustedCAFile != "" && tlsConfig.RootCAs == nil {
					t.Error("tlsConfig.RootCAs should be set when TrustedCAFile is provided")
				}
			}
		})
	}
}

// TestExecuteCheck tests the TLS certificate checking logic
func TestExecuteCheck(t *testing.T) {
	// Initialize validator as main() does
	validate = validator.New()

	tests := []struct {
		name        string
		config      Config
		setupFunc   func() (string, int, func())
		wantStatus  int
		wantErr     bool
		errContains string
	}{
		{
			name: "certificate expiring soon - critical",
			config: Config{
				Warning:            30,
				Critical:           7,
				InsecureSkipVerify: true,
			},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 3) // 3 days until expiry
			},
			wantStatus: sensu.CheckStateCritical,
			wantErr:    false,
		},
		{
			name: "certificate expiring soon - warning",
			config: Config{
				Warning:            30,
				Critical:           7,
				InsecureSkipVerify: true,
			},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 15) // 15 days until expiry
			},
			wantStatus: sensu.CheckStateWarning,
			wantErr:    false,
		},
		{
			name: "certificate valid for long time",
			config: Config{
				Warning:            30,
				Critical:           7,
				InsecureSkipVerify: true,
			},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 365) // 1 year until expiry
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name: "connection failure - invalid host",
			config: Config{
				Host:     "invalid.example.test",
				Port:     443,
				Warning:  30,
				Critical: 7,
			},
			wantStatus: sensu.CheckStateCritical,
			wantErr:    true,
		},
		{
			name: "certificate validation with custom CA",
			config: Config{
				Warning:  30,
				Critical: 7,
			},
			setupFunc: func() (string, int, func()) {
				host, port, caFile, cleanup := startTestTLSServerWithCA(t, 365)
				
				// Load the CA into tlsConfig
				caCertPool, err := corev2.LoadCACerts(caFile)
				if err != nil {
					t.Fatal(err)
				}
				tlsConfig.RootCAs = caCertPool
				
				return host, port, cleanup
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name: "insecure skip verify allows self-signed cert",
			config: Config{
				Warning:            30,
				Critical:           7,
				InsecureSkipVerify: true,
			},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 365)
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global tlsConfig before each test
			tlsConfig = tls.Config{}

			var cleanup func()
			if tt.setupFunc != nil {
				host, port, cleanupFunc := tt.setupFunc()
				tt.config.Host = host
				tt.config.Port = port
				cleanup = cleanupFunc
				defer cleanup()
			}

			// Set the global plugin variable
			plugin = tt.config
			plugin.PluginConfig = sensu.PluginConfig{
				Name:     "check-tls-cert",
				Short:    "TLS expiry check",
				Keyspace: "sensu.io/plugins/http-check/config",
			}

			// Set InsecureSkipVerify in tlsConfig as checkArgs() would
			tlsConfig.InsecureSkipVerify = tt.config.InsecureSkipVerify

			status, err := executeCheck(nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if status != tt.wantStatus {
				t.Errorf("executeCheck() status = %v, want %v", status, tt.wantStatus)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("executeCheck() error = %v, should contain %v", err, tt.errContains)
				}
			}
		})
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// startTestTLSServer creates a test TLS server with a certificate expiring in daysUntilExpiry days
func startTestTLSServer(t *testing.T, daysUntilExpiry int) (host string, port int, cleanup func()) {
	// Generate a self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Start TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Accept connections and handle TLS handshake
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Perform TLS handshake
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				// Keep connection open briefly
				time.Sleep(100 * time.Millisecond)
				_ = c.Close()
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = listener.Close() }
}

// startTestTLSServerWithCA creates a test TLS server with a CA-signed certificate
func startTestTLSServerWithCA(t *testing.T, daysUntilExpiry int) (host string, port int, caFile string, cleanup func()) {
	// Generate CA
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Write CA to file
	tmpfile, err := os.CreateTemp("", "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(tmpfile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	_ = tmpfile.Close()

	// Generate server certificate signed by CA
	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost", "localhost.localdomain"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverPriv,
	}

	// Start TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}

	// Accept connections and handle TLS handshake
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Perform TLS handshake
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				// Keep connection open briefly
				time.Sleep(100 * time.Millisecond)
				_ = c.Close()
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return "localhost.localdomain", addr.Port, tmpfile.Name(), func() {
		_ = listener.Close()
		_ = os.Remove(tmpfile.Name())
	}
}

// TestTLSConfigBug tests that the tlsConfig is actually used when calling tls.Dial
// This test verifies that custom CA certificates work correctly
func TestTLSConfigBug(t *testing.T) {
	
	validate = validator.New()

	// Create a test server with a CA-signed certificate
	host, port, caFile, cleanup := startTestTLSServerWithCA(t, 365)
	defer cleanup()

	plugin = Config{
		Host:          host,
		Port:          port,
		Warning:       30,
		Critical:      7,
		TrustedCAFile: caFile,
	}
	plugin.PluginConfig = sensu.PluginConfig{
		Name:     "check-tls-cert",
		Short:    "TLS expiry check",
		Keyspace: "sensu.io/plugins/http-check/config",
	}

	// Initialize tlsConfig with CA
	status, err := checkArgs(nil)
	if err != nil {
		t.Fatalf("checkArgs() failed: %v", err)
	}
	if status != sensu.CheckStateOK {
		t.Fatalf("checkArgs() returned unexpected status: %v", status)
	}

	// This should succeed because the CA is configured
	// But it will fail with current code because executeCheck passes nil to tls.Dial
	status, err = executeCheck(nil)
	if err != nil {
		t.Fatalf("executeCheck() failed: %v (This means the custom CA is not being used!)", err)
	}
	if status != sensu.CheckStateOK {
		t.Fatalf("executeCheck() returned unexpected status: %v", status)
	}
}
