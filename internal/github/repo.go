package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// User is the (subset of) response from GET /user.
type User struct {
	Login string `json:"login"`
}

// GetUser fetches the authenticated user's login.
func GetUser(ctx context.Context, token string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("github: build user req: %w", err)
	}
	setAuthHeaders(req, token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: user request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: user HTTP %d: %s", resp.StatusCode, body)
	}
	var u User
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("github: user parse: %w", err)
	}
	if u.Login == "" {
		return nil, errors.New("github: empty login in user response")
	}
	return &u, nil
}

// Repo is the (subset of) response from repo create / get.
type Repo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}

// EnsureRepo returns the repo if it exists, or creates a new public repo
// named `name` on the authenticated user. Idempotent.
func EnsureRepo(ctx context.Context, token, owner, name string) (*Repo, error) {
	r, err := getRepo(ctx, token, owner, name)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, errRepoNotFound) {
		return nil, err
	}
	return createRepo(ctx, token, name)
}

var errRepoNotFound = errors.New("github: repo not found")

func getRepo(ctx context.Context, token, owner, name string) (*Repo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("github: build get-repo req: %w", err)
	}
	setAuthHeaders(req, token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: get-repo: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, errRepoNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: get-repo HTTP %d: %s", resp.StatusCode, body)
	}
	var r Repo
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("github: get-repo parse: %w", err)
	}
	return &r, nil
}

func createRepo(ctx context.Context, token, name string) (*Repo, error) {
	body, err := json.Marshal(map[string]any{
		"name":        name,
		"description": "tapid-managed OIDC JWKS — public, do not edit by hand",
		"private":     false,
		"auto_init":   true, // creates initial commit so we have a default branch
	})
	if err != nil {
		return nil, fmt.Errorf("github: marshal create-repo: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/user/repos", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("github: build create-repo req: %w", err)
	}
	setAuthHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: create-repo: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("github: create-repo HTTP %d: %s", resp.StatusCode, respBody)
	}
	var r Repo
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("github: create-repo parse: %w", err)
	}
	return &r, nil
}

// PutFile creates or updates a file in a repo via the Contents API.
// Content is base64-encoded for transport per the API contract.
// commitMsg is the commit message attached to the change.
//
// This is idempotent: if the file exists, the current sha is fetched first
// (PUT requires sha for updates).
func PutFile(ctx context.Context, token, owner, repo, branch, path, content, commitMsg string) error {
	sha, err := fileSHA(ctx, token, owner, repo, branch, path)
	if err != nil && !errors.Is(err, errFileNotFound) {
		return err
	}

	body := map[string]any{
		"message": commitMsg,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"branch":  branch,
	}
	if sha != "" {
		body["sha"] = sha
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("github: marshal put-file: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("github: build put-file req: %w", err)
	}
	setAuthHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github: put-file: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("github: put-file %s HTTP %d: %s", path, resp.StatusCode, respBody)
	}
	return nil
}

var errFileNotFound = errors.New("github: file not found")

func fileSHA(ctx context.Context, token, owner, repo, branch, path string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repo, path, branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("github: build file-sha req: %w", err)
	}
	setAuthHeaders(req, token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: file-sha: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", errFileNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: file-sha HTTP %d: %s", resp.StatusCode, body)
	}
	var meta struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("github: file-sha parse: %w", err)
	}
	return meta.SHA, nil
}

// RawRepoURL returns the stable raw URL for a file in a repo on a branch.
// Path must NOT have a leading slash.
//
//	https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>
func RawRepoURL(owner, repo, branch, path string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, path)
}

// IssuerBaseURL returns the issuer URL for a device hosted in a tapid-jwks repo.
// Infisical and other strict OIDC verifiers append /.well-known/openid-configuration
// to this base, so the base must be a real path prefix where that file exists.
//
//	https://raw.githubusercontent.com/<owner>/<repo>/<branch>/devices/<device_id>
func IssuerBaseURL(owner, repo, branch, deviceID string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/devices/%s", owner, repo, branch, deviceID)
}

func setAuthHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}
