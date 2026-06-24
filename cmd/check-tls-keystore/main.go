package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
	"time"

	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

type Config struct {
	sensu.PluginConfig
	Path     string
	Alias    string
	Password string
	Warning  int
	Critical int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-tls-keystore",
			Short:    "Check certificate expiry in a Java keystore",
			Keyspace: "sensu.io/plugins/check-tls-keystore/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Argument: "path",
			Usage:    "Path to the Java keystore file",
			Value:    &plugin.Path,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "alias",
			Usage:    "Certificate alias in the keystore",
			Value:    &plugin.Alias,
		},
		&sensu.PluginConfigOption[string]{
			Argument: "password",
			Usage:    "Keystore password",
			Value:    &plugin.Password,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "warning",
			Shorthand: "w",
			Usage:     "Days before expiry to warn",
			Value:     &plugin.Warning,
		},
		&sensu.PluginConfigOption[int]{
			Argument:  "critical",
			Shorthand: "c",
			Usage:     "Days before expiry to go critical",
			Value:     &plugin.Critical,
		},
	}
)

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.Path) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--path is required")
	}
	if len(plugin.Alias) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--alias is required")
	}
	if len(plugin.Password) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--password is required")
	}
	if plugin.Critical <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--critical is required")
	}
	if plugin.Warning <= 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--warning is required")
	}
	if plugin.Warning < plugin.Critical {
		return sensu.CheckStateWarning, fmt.Errorf("--warning cannot be less than --critical")
	}
	return sensu.CheckStateOK, nil
}

func getCertFromKeystore() (*x509.Certificate, error) {
	// Export the cert in PEM format via keytool, then pipe to openssl x509 to get DER/PEM.
	// We use exec.Command with explicit args to avoid shell injection.
	keytool := exec.Command("keytool",
		"-keystore", plugin.Path,
		"-export",
		"-alias", plugin.Alias,
		"-storepass", plugin.Password,
		"-rfc",
	)
	keytoolOut, err := keytool.Output()
	if err != nil {
		return nil, fmt.Errorf("keytool failed: %v", err)
	}

	// keytool -rfc outputs PEM. Decode it directly without needing openssl.
	// Strip any non-PEM lines (e.g. "Certificate stored in file...")
	pemData := extractPEM(string(keytoolOut))
	if pemData == "" {
		return nil, fmt.Errorf("keytool output contained no PEM certificate block")
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM from keytool output")
	}
	return x509.ParseCertificate(block.Bytes)
}

// extractPEM returns just the PEM certificate block from keytool output.
func extractPEM(output string) string {
	start := strings.Index(output, "-----BEGIN CERTIFICATE-----")
	end := strings.Index(output, "-----END CERTIFICATE-----")
	if start == -1 || end == -1 {
		return ""
	}
	return output[start : end+len("-----END CERTIFICATE-----")]
}

func executeCheck(event *corev2.Event) (int, error) {
	cert, err := getCertFromKeystore()
	if err != nil {
		return sensu.CheckStateCritical, err
	}

	timeNow := time.Now()
	expiresInDays := int(cert.NotAfter.Sub(timeNow).Hours() / 24)

	if expiresInDays < 0 {
		fmt.Printf("critical: cert for alias %q expired %v days ago\n", plugin.Alias, -expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	if timeNow.AddDate(0, 0, plugin.Critical).After(cert.NotAfter) {
		fmt.Printf("critical: cert for alias %q expires in %v days\n", plugin.Alias, expiresInDays)
		return sensu.CheckStateCritical, nil
	}
	if timeNow.AddDate(0, 0, plugin.Warning).After(cert.NotAfter) {
		fmt.Printf("warning: cert for alias %q expires in %v days\n", plugin.Alias, expiresInDays)
		return sensu.CheckStateWarning, nil
	}
	fmt.Printf("ok: cert for alias %q expires in %v days\n", plugin.Alias, expiresInDays)
	return sensu.CheckStateOK, nil
}
