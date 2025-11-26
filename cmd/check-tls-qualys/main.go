package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultAPIURL  = "https://api.ssllabs.com/api/v3/analyze"
	defaultTimeout = 300
)

type SSLCheckResponse struct {
	Status    string `json:"status"`
	Endpoints []struct {
		Grade string `json:"grade"`
	} `json:"endpoints"`
}

func main() {
	domain := os.Args[1]
	apiURL := defaultAPIURL
	timeout := defaultTimeout

	// Simplified for demonstration purposes
	// You would need to implement command line parsing and error handling

	grade := checkSSLGrade(domain, apiURL, timeout)
	fmt.Printf("Domain: %s, Grade: %s\n", domain, grade)
}

func checkSSLGrade(domain, apiURL string, timeout int) string {
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s?host=%s&startNew=on", apiURL, domain), nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return ""
	}

	var sslCheckResponse SSLCheckResponse
	err = json.Unmarshal(body, &sslCheckResponse)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return ""
	}

	// Simplified logic for demonstration purposes
	// You would need to implement the full logic for checking grades and handling different states
	if len(sslCheckResponse.Endpoints) > 0 {
		return sslCheckResponse.Endpoints[0].Grade
	}

	return ""
}
