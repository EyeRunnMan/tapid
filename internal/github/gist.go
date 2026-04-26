package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// File is a single gist file payload.
type File struct {
	Filename string `json:"filename,omitempty"`
	Content  string `json:"content"`
}

// gistRequest is the body for create/update.
type gistRequest struct {
	Description string          `json:"description,omitempty"`
	Public      bool            `json:"public"`
	Files       map[string]File `json:"files"`
}

// Gist is the (subset of) response from the GitHub Gists API.
type Gist struct {
	ID      string          `json:"id"`
	HTMLURL string          `json:"html_url"`
	Owner   struct {
		Login string `json:"login"`
	} `json:"owner"`
	Files map[string]struct {
		Filename string `json:"filename"`
		RawURL   string `json:"raw_url"`
	} `json:"files"`
}

// CreateGist creates a public gist with the given files. Returns the gist
// metadata including the owner login (needed to build the stable raw URL).
func CreateGist(ctx context.Context, token, description string, files map[string]string) (*Gist, error) {
	return doGist(ctx, http.MethodPost, "https://api.github.com/gists", token, description, files)
}

// UpdateGist replaces the contents of an existing gist's files (by filename).
func UpdateGist(ctx context.Context, token, gistID string, files map[string]string) (*Gist, error) {
	url := "https://api.github.com/gists/" + gistID
	return doGist(ctx, http.MethodPatch, url, token, "", files)
}

func doGist(ctx context.Context, method, url, token, description string, files map[string]string) (*Gist, error) {
	if token == "" {
		return nil, fmt.Errorf("github: empty access token")
	}

	gf := make(map[string]File, len(files))
	for name, content := range files {
		gf[name] = File{Content: content}
	}
	body, err := json.Marshal(gistRequest{
		Description: description,
		Public:      true,
		Files:       gf,
	})
	if err != nil {
		return nil, fmt.Errorf("github: marshal gist: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("github: build gist req: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: gist request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("github: gist HTTP %d: %s", resp.StatusCode, respBody)
	}

	var g Gist
	if err := json.Unmarshal(respBody, &g); err != nil {
		return nil, fmt.Errorf("github: gist parse: %w", err)
	}
	return &g, nil
}

// RawURL returns the stable "latest revision" raw URL for a file in a gist.
//
//	https://gist.githubusercontent.com/<user>/<gist_id>/raw/<filename>
//
// This URL serves the latest content; revision-pinned URLs include a commit
// hash before the filename and are not what we want for JWKS.
func RawURL(ownerLogin, gistID, filename string) string {
	return "https://gist.githubusercontent.com/" + ownerLogin + "/" + gistID + "/raw/" + filename
}
