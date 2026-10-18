package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func healthCheck(endpoint string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy status: %d", response.StatusCode)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("unhealthy response")
	}
	return nil
}
