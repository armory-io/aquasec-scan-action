package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-github/v32/github"
)

type ActionContext struct {
	PayloadBytes []byte
	EventName    string
	SHA          string
	Ref          string
	FullRepo     string
	Owner, Repo  string
}

var ErrNoPayload = errors.New("github event payload data could not be found")

func GetActionContext() (*ActionContext, error) {
	ac := &ActionContext{
		PayloadBytes: nil,
		EventName:    os.Getenv("GITHUB_EVENT_NAME"),
		SHA:          os.Getenv("GITHUB_SHA"),
		Ref:          os.Getenv("GITHUB_REF"),
		FullRepo:     os.Getenv("GITHUB_REPOSITORY"),
	}

	if ac.FullRepo != "" {
		splitRepo := strings.Split(ac.FullRepo, "/")
		ac.Owner = splitRepo[0]
		ac.Repo = splitRepo[1]
	}

	actionPayload, err := parseActionPayload(os.Getenv("GITHUB_EVENT_PATH"))
	if err != nil {
		return ac, err
	}

	ac.PayloadBytes = actionPayload
	return ac, nil
}

type ErrWrongEventType struct {
	t string
}

func (e ErrWrongEventType) Error() string {
	return fmt.Sprintf("incorrect type %s for event payload", e.t)
}

func PullRequestEvent(ac *ActionContext) (*github.PullRequestEvent, error) {
	if ac.EventName != "pull_request" {
		return nil, ErrWrongEventType{ac.EventName}
	}

	var prEvent github.PullRequestEvent
	if err := json.NewDecoder(bytes.NewReader(ac.PayloadBytes)).Decode(&prEvent); err != nil {
		return nil, err
	}

	return &prEvent, nil
}

func parseActionPayload(payloadPath string) ([]byte, error) {
	if payloadPath == "" {
		return nil, ErrNoPayload
	}

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		return nil, ErrNoPayload
	}

	b, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return nil, err
	}
	return b, nil
}
