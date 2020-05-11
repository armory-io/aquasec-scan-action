package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	username := flag.String("username", "", "aquasec username")
	password := flag.String("password", "", "aquasec password")
	url := flag.String("url", "", "aquasec url")
	registry := flag.String("registry", "", "image registry")
	image := flag.String("image", "", "image to scan")
	flag.Parse()

	log.Printf("attempting to log into aquasec \n")
	scanner, err := NewAquasecScanner(*url, *username, *password)
	if err != nil {
		log.Fatalf("failed to create a new aquasec scanner: %v+", err)
	}

	// trigger a scan
	log.Printf("starting image scan for %s %s", *registry, *image)
	if err := scanner.StartScan(*registry, *image); err != nil {
		log.Fatalf("failed to start image scan: %v", err)
	}

	// wait for scan to complete
	log.Println("image scan started. waiting for it to complete.")
	if err := scanner.WaitForScan(*registry, *image); err != nil {
		log.Fatalf("failed to wait for scan")
	}

	status, resp, err := scanner.GetScanResult(*registry, *image)
	if err != nil {
		log.Fatalf("failed to get scan result: %v", err)
	}

	if !status.Disallowed {
		log.Println("image successfully scanned and clear of issues.")
		return
	}

	log.Println("image failed security scan.")
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		log.Fatalf("unable to unmarshal scan status: %v", err)
	}
	indented, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(indented))
	os.Exit(500)

}

type Aquasec interface {
	StartScan(registry, image string) error
	WaitForScan(registry, image string) error
	GetScanStatus(registry, image string) (string, error)
	GetScanResult(registry, image string) (*ScanResult, string, error)
}

type AquasecScanner struct {
	authToken string
	baseUrl   string
}

type ScanResult struct {
	Disallowed bool `json:"disallowed"`
	Inputs     json.RawMessage
}

type ScanStartOutput struct {
	Status string `json:"status"`
}

func (a *AquasecScanner) StartScan(registry, image string) error {
	scanUrl := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan", a.baseUrl, registry, image)
	resp, err := a.authenticatedRequest(http.MethodPost, scanUrl, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var output ScanStartOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return err
	}

	if output.Status != "Sent To Scan" {
		fmt.Println(output)
		return errors.New("failed to start image scan")
	}

	return nil
}

func (a *AquasecScanner) WaitForScan(registry, image string) error {
	for {
		status, err := a.GetScanStatus(registry, image)
		if err != nil {
			return err
		}
		if status == "Scanned" || status == "Failed" {
			return nil
		}
		log.Printf("scan status is %s. continuing to wait for scan to complete.", status)
		time.Sleep(30 * time.Second)
	}

}

func (a *AquasecScanner) GetScanStatus(registry, image string) (string, error) {
	targetUrl := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/status", a.baseUrl, registry, image)
	resp, err := a.authenticatedRequest(http.MethodGet, targetUrl, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var output ScanStartOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return "", err
	}
	return output.Status, nil
}

func (a *AquasecScanner) GetScanResult(registry, image string) (*ScanResult, string, error) {
	targetUrl := fmt.Sprintf("%s/api/v1/scanner/registry/%s/image/%s/scan_result", a.baseUrl, registry, image)
	resp, err := a.authenticatedRequest(http.MethodGet, targetUrl, nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var output ScanResult
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(b, &output); err != nil {
		return nil, "", err
	}

	return &output, string(b), nil
}

func (a *AquasecScanner) authenticatedRequest(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.authToken))
	client := &http.Client{}
	return client.Do(req)
}

type AuthResponse struct {
	Token string `json:"token"`
}

func NewAquasecScanner(baseUrl, username, password string) (Aquasec, error) {
	a := AquasecScanner{baseUrl: baseUrl}
	tokenUrl := fmt.Sprintf("%s/api/v1/login", baseUrl)
	tokenInput := map[string]string{
		"id":       username,
		"password": password,
	}
	b, err := json.Marshal(tokenInput)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(tokenUrl, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var output AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, err
	}
	a.authToken = output.Token
	return &a, nil
}
