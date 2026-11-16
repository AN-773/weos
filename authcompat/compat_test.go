// Package authcompat proves that a real medai-accounts token verifies with the
// other verifiers our Go services use, at the versions they pin:
//   - go-oidc v3.10.0 (learning, tutor, IAM: WeOS's discovery mode),
//   - MicahParks/keyfunc v1.9.0 + golang-jwt v4.5.0 (notification-service).
//
// It is its own module so these test-only dependencies stay out of WeOS's
// go.mod. The fixture is ../rest/testdata/accounts-golden.
package authcompat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/coreos/go-oidc/v3/oidc"
	jwtv4 "github.com/golang-jwt/jwt/v4"
)

const fixtureDir = "../rest/testdata/accounts-golden/"

type golden struct {
	Issuer    string                 `json:"issuer"`
	Audience  string                 `json:"audience"`
	UserID    string                 `json:"userId"`
	AccountID string                 `json:"accountId"`
	Claims    map[string]interface{} `json:"claims"`
	token     string
	jwks      []byte
}

func load(t *testing.T) golden {
	t.Helper()
	var g golden
	raw, err := os.ReadFile(fixtureDir + "expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	tok, err := os.ReadFile(fixtureDir + "token.jwt")
	if err != nil {
		t.Fatal(err)
	}
	g.token = strings.TrimSpace(string(tok))
	if g.jwks, err = os.ReadFile(fixtureDir + "jwks.json"); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g golden) at() time.Time { return time.Unix(int64(g.Claims["iat"].(float64))+60, 0) }

func jwksServer(t *testing.T, body []byte) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

// The claims WeOS reads with plain string casts must be strings.
func assertWeOSStrings(t *testing.T, claims map[string]interface{}, g golden) {
	t.Helper()
	want := map[string]string{
		"sub":                                 "/users/" + g.UserID,
		"azp":                                 g.Audience,
		"https://iam.weos.io/v1/user":         "/users/" + g.UserID,
		"https://iam.weos.io/v1/roles":        "user",
		"https://iam.weos.io/v1/account":      "/accounts/" + g.AccountID,
		"https://iam.weos.io/v1/tenant":       "/tenants/medai",
		"https://iam.weos.io/v1/tenant_role":  "user",
		"https://iam.weos.io/v1/subscription": "inactive",
	}
	for name, value := range want {
		got, ok := claims[name].(string)
		if !ok || got != value {
			t.Errorf("claim %s = %#v, want string %q", name, claims[name], value)
		}
	}
}

func TestGoldenToken_GoOIDC(t *testing.T) {
	g := load(t)
	server := jwksServer(t, g.jwks)
	ctx := context.Background()
	verifier := oidc.NewVerifier(g.Issuer, oidc.NewRemoteKeySet(ctx, server.URL), &oidc.Config{
		ClientID:             g.Audience,
		SupportedSigningAlgs: []string{oidc.RS256},
		Now:                  g.at,
	})
	token, err := verifier.Verify(ctx, g.token)
	if err != nil {
		t.Fatalf("go-oidc refused the accounts token: %s", err)
	}
	if token.Issuer != g.Issuer || token.Subject != "/users/"+g.UserID || len(token.Audience) != 1 || token.Audience[0] != g.Audience {
		t.Fatalf("unexpected token fields: %#v", token)
	}
	claims := map[string]interface{}{}
	if err = token.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	assertWeOSStrings(t, claims, g)

	// And go-oidc refuses it with another issuer or audience.
	for name, cfg := range map[string]struct{ iss, aud string }{
		"issuer":   {"https://msa-api-iam.azurewebsites.net", g.Audience},
		"audience": {g.Issuer, "someone-else"},
	} {
		v := oidc.NewVerifier(cfg.iss, oidc.NewRemoteKeySet(ctx, server.URL), &oidc.Config{ClientID: cfg.aud, SupportedSigningAlgs: []string{oidc.RS256}, Now: g.at})
		if _, err = v.Verify(ctx, g.token); err == nil {
			t.Errorf("go-oidc accepted the token with a wrong %s", name)
		}
	}
}

// Mirrors notification-service application/auth.go (keyfunc.Get, RS256 only,
// issuer compared by hand).
func TestGoldenToken_Keyfunc(t *testing.T) {
	g := load(t)
	server := jwksServer(t, g.jwks)
	jwks, err := keyfunc.Get(server.URL, keyfunc.Options{
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute,
		RefreshTimeout:    10 * time.Second,
		RefreshUnknownKID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer jwks.EndBackground()

	saved := jwtv4.TimeFunc
	jwtv4.TimeFunc = g.at
	defer func() { jwtv4.TimeFunc = saved }()

	claims := jwtv4.MapClaims{}
	if _, err = jwtv4.ParseWithClaims(g.token, claims, jwks.Keyfunc, jwtv4.WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("keyfunc/jwt v4 refused the accounts token: %s", err)
	}
	if iss, _ := claims["iss"].(string); iss != g.Issuer {
		t.Fatalf("iss = %q", iss)
	}
	if !claims.VerifyAudience(g.Audience, true) {
		t.Fatal("aud does not contain the audience")
	}
	assertWeOSStrings(t, claims, g)

	// Expired once the 15 minutes are over.
	jwtv4.TimeFunc = func() time.Time { return g.at().Add(time.Hour) }
	if _, err = jwtv4.ParseWithClaims(g.token, jwtv4.MapClaims{}, jwks.Keyfunc, jwtv4.WithValidMethods([]string{"RS256"})); err == nil {
		t.Fatal("expired token accepted")
	}
}
