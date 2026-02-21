package auth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubOAuth2AuthorizeURL(t *testing.T) {
	provider, err := NewGitHub(NewGitHubOptions{
		ClientID:     "cid",
		ClientSecret: "secret",
	})
	require.NoError(t, err)

	authURL, err := provider.OAuth2AuthorizeURL("state-1", "https://app.example.com/callback")
	require.NoError(t, err)

	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/login/oauth/authorize", u.Scheme+"://"+u.Host+u.Path)
	q := u.Query()
	assert.Equal(t, "cid", q.Get("client_id"))
	assert.Equal(t, "https://app.example.com/callback", q.Get("redirect_uri"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "user", q.Get("scope"))
	assert.Equal(t, "state-1", q.Get("state"))
}

func TestGitHubOAuth2ExchangeCodeAndRetrieveProfile(t *testing.T) {
	provider, err := NewGitHub(NewGitHubOptions{ClientID: "cid", ClientSecret: "secret"})
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://github.com/login/oauth/access_token":
				if req.Method != http.MethodPost {
					return nil, assert.AnError
				}
				if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					return nil, assert.AnError
				}
				body, rErr := io.ReadAll(req.Body)
				if rErr != nil {
					return nil, rErr
				}
				vals, rErr := url.ParseQuery(string(body))
				if rErr != nil {
					return nil, rErr
				}
				if vals.Get("code") != "abc" {
					return nil, assert.AnError
				}
				if vals.Get("client_id") != "cid" {
					return nil, assert.AnError
				}
				if vals.Get("client_secret") != "secret" {
					return nil, assert.AnError
				}
				if vals.Get("redirect_uri") != "https://app.example.com/callback" {
					return nil, assert.AnError
				}
				if vals.Get("grant_type") != "authorization_code" {
					return nil, assert.AnError
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1","expires_in":120,"scope":"user read:org"}`)),
				}, nil
			case githubGraphQLEndpoint:
				if req.Header.Get("Authorization") != "token token-1" {
					return nil, assert.AnError
				}
				body, rErr := io.ReadAll(req.Body)
				if rErr != nil {
					return nil, rErr
				}
				if !strings.Contains(string(body), "viewer") {
					return nil, assert.AnError
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"data":{"viewer":{"id":"123","login":"octocat","avatarUrl":"https://example.com/avatar.png","name":"The Octocat"}}}`)),
				}, nil
			default:
				return nil, assert.AnError
			}
		}),
	}

	at, err := provider.OAuth2ExchangeCode(t.Context(), "state-1", "abc", "https://app.example.com/callback")
	require.NoError(t, err)
	assert.Equal(t, "token-1", at.AccessToken)
	assert.Equal(t, []string{"user", "read:org"}, at.Scopes)

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), at)
	require.NoError(t, err)
	assert.Equal(t, "octocat", profile.ID)
	assert.Equal(t, "The Octocat", profile.Name.FullName)
	assert.Equal(t, "123", profile.AdditionalClaims[githubClaimGitHubUserID])
}
