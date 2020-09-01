package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/google/go-github/v32/github"
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

	reportVulns := true
	if v := os.Getenv("INPUT_REPORTVULNS"); v == "false" {
		log.Println("reportVulns is false. skipping PR comment.")
		reportVulns = false
	}

	// if true, we'll use scan data to create a comment on the commit
	// that triggered the execution
	if reportVulns {
		log.Println("reporting critical and high CVE count as comment on commit.")
		scanData, _, err := scanner.GetScanData(*registry, *image)
		if err != nil {
			log.Fatalf("failed to get scan data for image: %s", err.Error())
		}
		commentBody, err := generateReportComment(*registry, *image, *url, scanData)
		if err != nil {
			log.Fatalf("failed to generate comment body: %s", err.Error())
		}

		repo := strings.Split(os.Getenv("GITHUB_REPOSITORY"), "/")
		sha := os.Getenv("GITHUB_SHA")
		if sha == "" || os.Getenv("GITHUB_REPOSITORY") == "" {
			log.Println("github repository and sha are required for reporting CVE counts but are empty. skipping.")
		}
		if err := createCommitComment(commentBody, repo[0], repo[1], sha); err != nil {
			log.Fatalf("failed to create report comment: %s", err.Error())
		}
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

var noIssuesFoundTemplate = `Security Scan Results
Image {{ .Image }} is free of critical & high CVEs.`

var defaultCommentTemplate = `:warning: Security Scan Results :warning:
Found {{ .Scan.CriticalVulns }} Critical Vulnerabilities
Found {{ .Scan.HighVulns }} High Vulnerabilities

See [scan details]({{ .AquasecHtmlImageUrl }}) for more information.
`

func createCommitComment(body []byte, owner, repo, sha string) error {
	client := createGithubClient()

	input := &github.RepositoryComment{
		Body: github.String(string(body)),
	}

	if _, _, err := client.Repositories.CreateComment(context.Background(), owner, repo, sha, input); err != nil {
		return err
	}
	return nil
}

func createGithubClient() *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)

	return github.NewClient(tc)
}

func generateReportComment(registry, image, baseUrl string, sd *ScanData) ([]byte, error) {
	// use predefined template or user defined template
	commentTemplate := defaultCommentTemplate
	if v := os.Getenv("INPUT_COMMENTTEMPLATE"); v != "" {
		commentTemplate = v
	}

	// if we don't have any critical of high CVEs, fallback to the
	// no issue template.
	// TODO: make this template configurable in the future
	if total := sd.CriticalVulns + sd.HighVulns; total == 0 {
		commentTemplate = noIssuesFoundTemplate
	}

	tmpl, err := template.New("comment").Parse(commentTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	splitImage := strings.SplitN(image, ":", 2)
	encodedImage := strings.Replace(image, "/", "%2F", -1)
	imageUrl := fmt.Sprintf("%s/#/images/%s/%s", baseUrl, registry, encodedImage)
	type templateInput struct {
		Registry            string
		Image               string
		AquasecBaseUrl      string
		Scan                ScanData
		ImageName           string
		ImageTag            string
		AquasecHtmlImageUrl string
	}
	if err := tmpl.Execute(&b, templateInput{
		Registry:            registry,
		Image:               image,
		Scan:                *sd,
		AquasecBaseUrl:      baseUrl,
		ImageName:           splitImage[0],
		ImageTag:            splitImage[1],
		AquasecHtmlImageUrl: imageUrl,
	}); err != nil {
		return nil, err
	}

	return b.Bytes(), err
}

type Aquasec interface {
	StartScan(registry, image string) error
	WaitForScan(registry, image string) error
	GetScanStatus(registry, image string) (string, error)
	GetScanResult(registry, image string) (*ScanResult, string, error)
	GetScanData(registry, image string) (*ScanData, string, error)
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

type ScanData struct {
	CriticalVulns int `json:"crit_vulns"`
	HighVulns     int `json:"high_vulns"`
	MediumVulns   int `json:"med_vulns"`
	LowVulns      int `json:"low_vulns"`
}

func (a *AquasecScanner) GetScanData(registry, image string) (*ScanData, string, error) {
	encodedImage := strings.Replace(image, ":", "/", 1)
	targetUrl := fmt.Sprintf("%s/api/v2/images/%s/%s", a.baseUrl, registry, encodedImage)
	resp, err := a.authenticatedRequest(http.MethodGet, targetUrl, nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var output ScanData
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(b, &output); err != nil {
		return nil, "", err
	}

	return &output, string(b), nil
}

type AquasecAPIError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func (a AquasecAPIError) Error() string {
	return fmt.Sprintf("aquasec error (%b): %s", a.Code, a.Message)
}

func deserializeError(reader io.Reader) error {
	var aerr AquasecAPIError
	if err := json.NewDecoder(reader).Decode(&aerr); err != nil {
		return err
	}
	return aerr
}

func (a *AquasecScanner) authenticatedRequest(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.authToken))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 && resp.StatusCode <= 599 {
		defer resp.Body.Close()
		return nil, deserializeError(resp.Body)
	}
	return resp, err
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

	if resp.StatusCode == 401 {
		return nil, deserializeError(resp.Body)
	}

	var output AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, err
	}
	a.authToken = output.Token
	return &a, nil
}
