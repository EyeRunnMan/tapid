// Package github implements just the OAuth device flow + Gist API surface
// tapid needs. No third-party SDK on purpose — keeps the supply chain small
// and the auth flow auditable end-to-end.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	deviceCodeURL = "https://github.com/login/device/code"
	tokenURL      = "https://github.com/login/oauth/access_token"
)

// DeviceCode is the response from POST /login/device/code.
type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// AccessToken is the (subset of) response from polling for the access token.
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// StartDeviceFlow requests a device code from GitHub. clientID is the OAuth App
// client ID; scopes is a space-separated list (e.g. "gist").
func StartDeviceFlow(ctx context.Context, clientID, scopes string) (*DeviceCode, error) {
	if clientID == "" {
		return nil, errors.New("github: empty client_id")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", scopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceCodeURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("github: build device-code req: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: device-code request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: device-code HTTP %d: %s", resp.StatusCode, body)
	}
	var dc DeviceCode
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, fmt.Errorf("github: device-code parse: %w (body=%s)", err, body)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return nil, fmt.Errorf("github: device-code missing fields: %s", body)
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	return &dc, nil
}

// PollForToken polls the OAuth token endpoint until the user approves, the
// device code expires, or ctx is cancelled. Implements the polling rules from
// the OAuth 2.0 Device Authorization Grant (RFC 8628 §3.5):
//   - "authorization_pending" → wait interval, retry
//   - "slow_down"             → increase interval by 5s
//   - "access_denied"         → user said no
//   - "expired_token"         → device code TTL hit
//   - access_token present    → done
func PollForToken(ctx context.Context, clientID string, dc *DeviceCode) (*AccessToken, error) {
	interval := time.Duration(dc.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, errors.New("github: device code expired before user approved")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("device_code", dc.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
			strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("github: build token req: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: token poll: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var raw struct {
			AccessToken      string `json:"access_token"`
			TokenType        string `json:"token_type"`
			Scope            string `json:"scope"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("github: token parse: %w (body=%s)", err, body)
		}

		switch raw.Error {
		case "":
			if raw.AccessToken == "" {
				return nil, fmt.Errorf("github: empty access_token in response: %s", body)
			}
			return &AccessToken{
				AccessToken: raw.AccessToken,
				TokenType:   raw.TokenType,
				Scope:       raw.Scope,
			}, nil
		case "authorization_pending":
			// keep polling at current interval
		case "slow_down":
			interval += 5 * time.Second
		case "expired_token":
			return nil, errors.New("github: device code expired")
		case "access_denied":
			return nil, errors.New("github: user denied authorization")
		case "unsupported_grant_type":
			return nil, errors.New("github: device flow not enabled on this OAuth App " +
				"(Settings → Developer settings → OAuth Apps → toggle 'Enable Device Flow')")
		default:
			return nil, fmt.Errorf("github: oauth error %s: %s", raw.Error, raw.ErrorDescription)
		}
	}
}

var httpClient = &http.Client{Timeout: 30 * time.Second}
