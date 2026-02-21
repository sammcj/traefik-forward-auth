package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenIDConnectOAuth2AuthorizeURLIncludesPKCE(t *testing.T) {
	provider, err := newOpenIDConnectInternal(
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			PKCEKey:      []byte("01234567890123456789012345678901"),
		},
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
		},
	)
	require.NoError(t, err)

	authURL, err := provider.OAuth2AuthorizeURL("state", "https://app.example.com/callback")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("code_challenge"))
}

func TestOpenIDConnectExchangeCodeAndRetrieveProfileFromUserInfo(t *testing.T) {
	provider, err := newOpenIDConnectInternal(
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
		},
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://idp.example.com/token":
				body, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					return nil, readErr
				}
				vals, parseErr := url.ParseQuery(string(body))
				if parseErr != nil {
					return nil, parseErr
				}
				if vals.Get("code") != "code-1" {
					return nil, assert.AnError
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"access-1","expires_in":3600}`)),
				}, nil
			case "https://idp.example.com/userinfo":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"sub":"user-1","name":"User One","email":"user1@example.com"}`)),
				}, nil
			default:
				return nil, assert.AnError
			}
		}),
	}

	at, err := provider.OAuth2ExchangeCode(t.Context(), "state", "code-1", "https://app.example.com/callback")
	require.NoError(t, err)
	profile, err := provider.OAuth2RetrieveProfile(t.Context(), at)
	require.NoError(t, err)
	assert.Equal(t, "user-1", profile.ID)
}

func TestOpenIDConnectRetrieveProfileFromIDToken(t *testing.T) {
	provider, err := newOpenIDConnectInternal("openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
		},
	)
	require.NoError(t, err)

	claims := map[string]any{"iss": "https://issuer.example.com", "aud": "cid", "sub": "sub-1", "name": "Name"}
	idToken, err := buildUnsignedJWT(claims)
	require.NoError(t, err)

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{AccessToken: "access", IDToken: idToken})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", profile.ID)
}

func TestFetchOIDCEndpoints(t *testing.T) {
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example.com/auth","token_endpoint":"https://idp.example.com/token","userinfo_endpoint":"https://idp.example.com/userinfo"}`))
		}),
	)
	defer ts.Close()

	endpoints, err := fetchOIDCEndpoints(t.Context(), ts.URL, ts.Client(), 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/auth", endpoints.Authorization)
	assert.Equal(t, "https://idp.example.com/token", endpoints.Token)
	assert.Equal(t, "https://idp.example.com/userinfo", endpoints.UserInfo)
}
