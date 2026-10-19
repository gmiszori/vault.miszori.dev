package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type request struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type result struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func probe() result {
	var input request
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return result{Error: err.Error()}
	}
	roots := x509.NewCertPool()
	if len(os.Args) > 1 {
		certificate, err := os.ReadFile(os.Args[1])
		if err != nil {
			return result{Error: err.Error()}
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return result{Error: "invalid test CA certificate"}
		}
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS12,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(input.Method, input.URL, strings.NewReader(input.Body))
	if err != nil {
		return result{Error: err.Error()}
	}
	for name, value := range input.Headers {
		req.Header.Set(name, value)
	}
	response, err := client.Do(req)
	if err != nil {
		return result{Error: err.Error()}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return result{Error: err.Error()}
	}
	return result{Status: response.StatusCode, Headers: response.Header, Body: string(body)}
}

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(probe()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
