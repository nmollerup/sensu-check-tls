package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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
			config:      Config{Warning: 14, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--host is required",
		},
		{
			name:        "warning not greater than critical",
			config:      Config{Host: "example.com", Warning: 7, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning must be greater than --critical",
		},
		{
			name:        "warning less than critical",
			config:      Config{Host: "example.com", Warning: 5, Critical: 7},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--warning must be greater than --critical",
		},
		{
			name:        "invalid starttls protocol",
			config:      Config{Host: "example.com", Warning: 14, Critical: 7, StartTLS: "ftp"},
			wantStatus:  sensu.CheckStateWarning,
			wantErr:     true,
			errContains: "--starttls must be 'smtp' or 'imap'",
		},
		{
			name:       "valid config",
			config:     Config{Host: "example.com", Warning: 14, Critical: 7},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "valid with smtp starttls",
			config:     Config{Host: "example.com", Warning: 14, Critical: 7, StartTLS: "smtp"},
			wantStatus: sensu.CheckStateOK,
			wantErr:    false,
		},
		{
			name:       "valid with imap starttls",
			config:     Config{Host: "example.com", Warning: 14, Critical: 7, StartTLS: "imap"},
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
					t.Errorf("checkArgs() error = %q, want it to contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

// TestCheckExpiry tests the expiry checking function.
func TestCheckExpiry(t *testing.T) {
	tests := []struct {
		name       string
		days       int
		warning    int
		critical   int
		wantStatus int
	}{
		{"already expired", -1, 14, 7, sensu.CheckStateCritical},
		{"within critical", 3, 14, 7, sensu.CheckStateCritical},
		{"within critical boundary", 6, 14, 7, sensu.CheckStateCritical},
		{"within warning", 10, 14, 7, sensu.CheckStateWarning},
		{"within warning boundary", 13, 14, 7, sensu.CheckStateWarning},
		{"ok", 30, 14, 7, sensu.CheckStateOK},
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
				t.Errorf("checkExpiry() status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

// TestStartTLSSMTP tests the SMTP STARTTLS handshake function.
func TestStartTLSSMTP(t *testing.T) {
	t.Run("successful handshake", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close(); _ = client.Close() }()

		go func() {
			// SMTP server side: send banner, read STARTTLS, send 220
			_, _ = fmt.Fprintf(server, "220 mail.example.com ESMTP ready\r\n")
			r := bufio.NewReader(server)
			line, _ := r.ReadString('\n')
			if strings.TrimSpace(line) == "STARTTLS" {
				_, _ = fmt.Fprintf(server, "220 Go ahead\r\n")
			}
		}()

		if err := starttlsSMTP(client); err != nil {
			t.Errorf("starttlsSMTP() unexpected error: %v", err)
		}
	})

	t.Run("bad initial banner", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close(); _ = client.Close() }()

		go func() {
			_, _ = fmt.Fprintf(server, "421 Service not available\r\n")
		}()

		if err := starttlsSMTP(client); err == nil {
			t.Error("starttlsSMTP() expected error for non-220 banner")
		}
	})

	t.Run("bad STARTTLS response", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close(); _ = client.Close() }()

		go func() {
			_, _ = fmt.Fprintf(server, "220 ready\r\n")
			r := bufio.NewReader(server)
			_, _ = r.ReadString('\n')
			_, _ = fmt.Fprintf(server, "454 TLS not available\r\n")
		}()

		if err := starttlsSMTP(client); err == nil {
			t.Error("starttlsSMTP() expected error for non-220 STARTTLS response")
		}
	})
}

// TestStartTLSIMAP tests the IMAP STARTTLS handshake function.
func TestStartTLSIMAP(t *testing.T) {
	t.Run("successful handshake", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close(); _ = client.Close() }()

		go func() {
			_, _ = fmt.Fprintf(server, "* OK Dovecot ready\r\n")
			r := bufio.NewReader(server)
			_, _ = r.ReadString('\n')
			_, _ = fmt.Fprintf(server, "a001 OK Begin TLS negotiation now\r\n")
		}()

		if err := starttlsIMAP(client); err != nil {
			t.Errorf("starttlsIMAP() unexpected error: %v", err)
		}
	})

	t.Run("bad initial banner", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close(); _ = client.Close() }()

		go func() {
			_, _ = fmt.Fprintf(server, "* BYE Server shutting down\r\n")
		}()

		if err := starttlsIMAP(client); err == nil {
			t.Error("starttlsIMAP() expected error for non-OK banner")
		}
	})

	t.Run("bad STARTTLS response", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close(); _ = client.Close() }()

		go func() {
			_, _ = fmt.Fprintf(server, "* OK ready\r\n")
			r := bufio.NewReader(server)
			_, _ = r.ReadString('\n')
			_, _ = fmt.Fprintf(server, "a001 NO TLS not supported\r\n")
		}()

		if err := starttlsIMAP(client); err == nil {
			t.Error("starttlsIMAP() expected error for NO response")
		}
	})
}

// TestExecuteCheck tests end-to-end certificate checking against a local TLS server.
func TestExecuteCheck(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		setupFunc  func(t *testing.T) (string, int, func())
		wantStatus int
		wantErr    bool
	}{
		{
			name:   "ok cert",
			config: Config{Warning: 14, Critical: 7, InsecureSkipVerify: true},
			setupFunc: func(t *testing.T) (string, int, func()) {
				return startTLSServer(t, 365)
			},
			wantStatus: sensu.CheckStateOK,
		},
		{
			name:   "critical expiry",
			config: Config{Warning: 14, Critical: 7, InsecureSkipVerify: true},
			setupFunc: func(t *testing.T) (string, int, func()) {
				return startTLSServer(t, 3)
			},
			wantStatus: sensu.CheckStateCritical,
		},
		{
			name:   "warning expiry",
			config: Config{Warning: 14, Critical: 7, InsecureSkipVerify: true},
			setupFunc: func(t *testing.T) (string, int, func()) {
				return startTLSServer(t, 10)
			},
			wantStatus: sensu.CheckStateWarning,
		},
		{
			name:       "connection failure",
			config:     Config{Host: "127.0.0.1", Port: 1, Warning: 14, Critical: 7},
			wantStatus: sensu.CheckStateCritical,
			wantErr:    true,
		},
		{
			name:   "skip hostname verification",
			config: Config{Warning: 14, Critical: 7, InsecureSkipVerify: true, SkipHostnameVerification: true},
			setupFunc: func(t *testing.T) (string, int, func()) {
				return startTLSServer(t, 365)
			},
			wantStatus: sensu.CheckStateOK,
		},
		{
			name:   "skip chain verification",
			config: Config{Warning: 14, Critical: 7, InsecureSkipVerify: true, SkipChainVerification: true},
			setupFunc: func(t *testing.T) (string, int, func()) {
				return startTLSServer(t, 365)
			},
			wantStatus: sensu.CheckStateOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				host, port, cleanupFn := tt.setupFunc(t)
				tt.config.Host = host
				tt.config.Port = port
				cleanup = cleanupFn
				defer cleanup()
			}

			plugin = tt.config
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

// --- helpers ---

func generateCert(t *testing.T, days int) (certDER []byte, priv *rsa.PrivateKey) {
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
	certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, priv
}

func startTLSServer(t *testing.T, days int) (host string, port int, cleanup func()) {
	t.Helper()
	certDER, priv := generateCert(t, days)
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
	return "127.0.0.1", addr.Port, func() { _ = l.Close() }
}

