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
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// TestCheckArgs tests the argument validation logic
func TestCheckArgs(t *testing.T) {
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
			errContains: "--warning must be greater than --critical",
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
			errContains: "--warning must be greater than --critical",
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
				tmpfile, err := os.CreateTemp("", "ca-*.pem")
				if err != nil {
					t.Fatal(err)
				}
				priv, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					_ = os.Remove(tmpfile.Name())
					t.Fatal(err)
				}
				template := x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{Organization: []string{"Test CA"}},
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
		// PEM mode: hostname not required
		{
			name: "pem mode skips hostname requirement",
			config: Config{
				PemFile:  "/tmp/test.pem",
				Warning:  30,
				Critical: 7,
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		// PKCS12 mode: pass required
		{
			name: "pkcs12 without pass is rejected",
			config: Config{
				PKCS12File: "/tmp/test.p12",
				Warning:    30,
				Critical:   7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--pass is required",
		},
		{
			name: "pkcs12 with pass skips hostname requirement",
			config: Config{
				PKCS12File: "/tmp/test.p12",
				PKCS12Pass: "password",
				Warning:    30,
				Critical:   7,
			},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name: "invalid ip override",
			config: Config{
				Host:     "example.com",
				IP:       "not-an-ip",
				Warning:  30,
				Critical: 7,
			},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--ip is not a valid IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig = tls.Config{}

			var cleanup func()
			if tt.setupFunc != nil {
				caFile, cleanupFunc := tt.setupFunc()
				tt.config.TrustedCAFile = caFile
				cleanup = cleanupFunc
				defer cleanup()
			}

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
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("checkArgs() error = %q, want it to contain %q", err.Error(), tt.errContains)
				}
			}
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

// TestParsePemCert tests PEM certificate parsing.
func TestParsePemCert(t *testing.T) {
	priv, certDER := generateTestCertDER(t, 30)
	_ = priv

	var buf strings.Builder
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pemData := []byte(buf.String())

	t.Run("valid PEM", func(t *testing.T) {
		cert, err := parsePemCert(pemData)
		if err != nil {
			t.Fatalf("parsePemCert() unexpected error: %v", err)
		}
		if cert == nil {
			t.Fatal("parsePemCert() returned nil cert")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parsePemCert([]byte("not pem data"))
		if err == nil {
			t.Error("parsePemCert() expected error for invalid PEM, got nil")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := parsePemCert([]byte{})
		if err == nil {
			t.Error("parsePemCert() expected error for empty input, got nil")
		}
	})
}

// TestCheckExpiry tests the expiry checking logic with varying certificate lifetimes.
func TestCheckExpiry(t *testing.T) {
	tests := []struct {
		name       string
		days       int
		warning    int
		critical   int
		wantStatus int
	}{
		{"expired", -5, 30, 7, sensu.CheckStateCritical},
		{"within critical", 3, 30, 7, sensu.CheckStateCritical},
		{"within critical boundary", 6, 30, 7, sensu.CheckStateCritical},
		{"within warning", 15, 30, 7, sensu.CheckStateWarning},
		{"within warning boundary", 29, 30, 7, sensu.CheckStateWarning},
		{"ok", 60, 30, 7, sensu.CheckStateOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin = Config{Warning: tt.warning, Critical: tt.critical}

			cert := &x509.Certificate{
				NotAfter: time.Now().Add(time.Duration(tt.days) * 24 * time.Hour),
			}
			status, err := checkExpiry(cert, "test")
			if err != nil {
				t.Fatalf("checkExpiry() unexpected error: %v", err)
			}
			if status != tt.wantStatus {
				t.Errorf("checkExpiry() status = %v, want %v (days=%d)", status, tt.wantStatus, tt.days)
			}
		})
	}
}

// TestExecuteCheck tests TLS connection and expiry checking.
func TestExecuteCheck(t *testing.T) {
	validate = validator.New()

	tests := []struct {
		name       string
		config     Config
		setupFunc  func() (string, int, func())
		wantStatus int
		wantErr    bool
	}{
		{
			name:   "critical expiry",
			config: Config{Warning: 30, Critical: 7, InsecureSkipVerify: true},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 3)
			},
			wantStatus: sensu.CheckStateCritical,
		},
		{
			name:   "warning expiry",
			config: Config{Warning: 30, Critical: 7, InsecureSkipVerify: true},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 15)
			},
			wantStatus: sensu.CheckStateWarning,
		},
		{
			name:   "ok",
			config: Config{Warning: 30, Critical: 7, InsecureSkipVerify: true},
			setupFunc: func() (string, int, func()) {
				return startTestTLSServer(t, 365)
			},
			wantStatus: sensu.CheckStateOK,
		},
		{
			name:       "connection failure",
			config:     Config{Host: "invalid.example.test", Port: 443, Warning: 30, Critical: 7},
			wantStatus: sensu.CheckStateCritical,
			wantErr:    true,
		},
		{
			name:   "custom CA",
			config: Config{Warning: 30, Critical: 7},
			setupFunc: func() (string, int, func()) {
				host, port, caFile, cleanup := startTestTLSServerWithCA(t, 365)
				caCertPool, err := corev2.LoadCACerts(caFile)
				if err != nil {
					t.Fatal(err)
				}
				tlsConfig.RootCAs = caCertPool
				return host, port, cleanup
			},
			wantStatus: sensu.CheckStateOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig = tls.Config{}

			var cleanup func()
			if tt.setupFunc != nil {
				host, port, cleanupFunc := tt.setupFunc()
				tt.config.Host = host
				tt.config.Port = port
				cleanup = cleanupFunc
				defer cleanup()
			}

			plugin = tt.config
			plugin.PluginConfig = sensu.PluginConfig{Name: "check-tls-cert"}
			tlsConfig.InsecureSkipVerify = tt.config.InsecureSkipVerify

			status, err := executeCheck(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("executeCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if status != tt.wantStatus {
				t.Errorf("executeCheck() status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

// TestExecuteCheckWithPEM tests the PEM file code path.
func TestExecuteCheckWithPEM(t *testing.T) {
	t.Run("nonexistent file returns critical", func(t *testing.T) {
		plugin = Config{PemFile: "/nonexistent/cert.pem", Warning: 30, Critical: 7}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for nonexistent PEM file")
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})

	t.Run("valid PEM file ok", func(t *testing.T) {
		path, cleanup := writeTempPEMCert(t, 365)
		defer cleanup()

		plugin = Config{PemFile: path, Warning: 30, Critical: 7}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status != sensu.CheckStateOK {
			t.Errorf("status = %v, want OK", status)
		}
	})

	t.Run("expiring PEM file critical", func(t *testing.T) {
		path, cleanup := writeTempPEMCert(t, 3)
		defer cleanup()

		plugin = Config{PemFile: path, Warning: 30, Critical: 7}
		status, err := executeCheck(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})
}

// TestExecuteCheckWithPKCS12 tests the PKCS12 file code path error cases.
func TestExecuteCheckWithPKCS12(t *testing.T) {
	t.Run("nonexistent file returns critical", func(t *testing.T) {
		plugin = Config{PKCS12File: "/nonexistent/cert.p12", PKCS12Pass: "pass", Warning: 30, Critical: 7}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for nonexistent PKCS12 file")
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})

	t.Run("invalid PKCS12 data returns critical", func(t *testing.T) {
		f, err := os.CreateTemp("", "bad-*.p12")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("not a pkcs12 file")
		_ = f.Close()
		defer func() { _ = os.Remove(f.Name()) }()

		plugin = Config{PKCS12File: f.Name(), PKCS12Pass: "pass", Warning: 30, Critical: 7}
		status, err := executeCheck(nil)
		if err == nil {
			t.Error("expected error for invalid PKCS12 data")
		}
		if status != sensu.CheckStateCritical {
			t.Errorf("status = %v, want Critical", status)
		}
	})
}

// TestTLSConfigBug verifies that custom CA certificates are applied to connections.
func TestTLSConfigBug(t *testing.T) {
	validate = validator.New()

	host, port, caFile, cleanup := startTestTLSServerWithCA(t, 365)
	defer cleanup()

	plugin = Config{
		Host:          host,
		Port:          port,
		Warning:       30,
		Critical:      7,
		TrustedCAFile: caFile,
	}
	plugin.PluginConfig = sensu.PluginConfig{Name: "check-tls-cert"}

	status, err := checkArgs(nil)
	if err != nil {
		t.Fatalf("checkArgs() failed: %v", err)
	}
	if status != sensu.CheckStateOK {
		t.Fatalf("checkArgs() returned unexpected status: %v", status)
	}

	status, err = executeCheck(nil)
	if err != nil {
		t.Fatalf("executeCheck() failed: %v (custom CA not applied)", err)
	}
	if status != sensu.CheckStateOK {
		t.Fatalf("executeCheck() returned unexpected status: %v", status)
	}
}

// --- helpers ---

func generateTestCertDER(t *testing.T, days int) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, certDER
}

func writeTempPEMCert(t *testing.T, days int) (path string, cleanup func()) {
	t.Helper()
	_, certDER := generateTestCertDER(t, days)
	f, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }
}

func startTestTLSServer(t *testing.T, daysUntilExpiry int) (host string, port int, cleanup func()) {
	t.Helper()
	priv, certDER := generateTestCertDER(t, daysUntilExpiry)
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go serveConnections(listener)
	addr := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = listener.Close() }
}

func startTestTLSServerWithCA(t *testing.T, daysUntilExpiry int) (host string, port int, caFile string, cleanup func()) {
	t.Helper()
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
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
	tmpfile, err := os.CreateTemp("", "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(tmpfile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	_ = tmpfile.Close()

	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{serverCertDER}, PrivateKey: serverPriv}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		_ = os.Remove(tmpfile.Name())
		t.Fatal(err)
	}
	go serveConnections(listener)
	addr := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, tmpfile.Name(), func() {
		_ = listener.Close()
		_ = os.Remove(tmpfile.Name())
	}
}

func serveConnections(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			if tlsConn, ok := c.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			time.Sleep(100 * time.Millisecond)
			_ = c.Close()
		}(conn)
	}
}
