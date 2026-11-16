package rest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/context"
)

// The security scheme exactly as learning (medai-test-service api.yaml) declares it.
const learningSchemeYAML = `
openapi: 3.0.3
info: {title: t, version: "1"}
paths: {}
components:
  securitySchemes:
    OpenIdConnect:
      type: openIdConnect
      openIdConnectUrl: %s
      x-jwt-map:
        user: sub
        role: https://iam.weos.io/v1/roles
        application: azp
        account: https://iam.weos.io/v1/account
        tenant: https://iam.weos.io/v1/tenant
        tenant_role: https://iam.weos.io/v1/tenant_role
        subscription: https://iam.weos.io/v1/subscription
security:
  - OpenIdConnect: []
`

const (
	accountsIssuer = "https://auth.medicalstudent.ai"
	// iamIssuer stands for IAM's BASE_URL+BASE_PATH (LEGACY_IAM_ISSUER).
	iamIssuer = "https://msa-api-iam.azurewebsites.net"
)

type golden struct {
	Issuer    string                 `json:"issuer"`
	Audience  string                 `json:"audience"`
	UserID    string                 `json:"userId"`
	AccountID string                 `json:"accountId"`
	Claims    map[string]interface{} `json:"claims"`
	token     string
	jwks      []byte
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	var g golden
	raw, err := os.ReadFile("testdata/accounts-golden/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile("testdata/accounts-golden/token.jwt")
	if err != nil {
		t.Fatal(err)
	}
	g.token = strings.TrimSpace(string(token))
	if g.jwks, err = os.ReadFile("testdata/accounts-golden/jwks.json"); err != nil {
		t.Fatal(err)
	}
	return g
}

// goldenTime is a moment inside the golden token's 15-minute life.
func (g golden) time() time.Time {
	return time.Unix(int64(g.Claims["iat"].(float64))+60, 0)
}

type testKey struct {
	kid string
	key *rsa.PrivateKey
}

var (
	keyCache   = map[string]testKey{}
	keyCacheMu sync.Mutex
)

func newKey(t *testing.T, kid string) testKey {
	t.Helper()
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if k, ok := keyCache[kid]; ok {
		return k
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := testKey{kid: kid, key: key}
	keyCache[kid] = k
	return k
}

func (k testKey) jwk() map[string]interface{} {
	m := map[string]interface{}{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(k.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.key.E)).Bytes()),
	}
	if k.kid != "" {
		m["kid"] = k.kid
	}
	return m
}

func (k testKey) jwkJSON(t *testing.T) string {
	raw, err := json.Marshal(k.jwk())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (k testKey) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if k.kid != "" {
		token.Header["kid"] = k.kid
	}
	s, err := token.SignedString(k.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// claimsFor is the IAM/accounts claim contract for one user (PARITY-core).
func claimsFor(issuer, audience, userID, accountID string, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                                 issuer,
		"sub":                                 "/users/" + userID,
		"aud":                                 []string{audience},
		"exp":                                 now.Add(15 * time.Minute).Unix(),
		"iat":                                 now.Unix(),
		"session":                             "3MCplOyxdChDBtQqmsck0DUVdzh",
		"scope":                               "openid profile email",
		"azp":                                 audience,
		"https://iam.weos.io/v1/roles":        "user",
		"https://iam.weos.io/v1/account":      "/accounts/" + accountID,
		"https://iam.weos.io/v1/tenant":       "/tenants/medai",
		"https://iam.weos.io/v1/tenant_role":  "user",
		"https://iam.weos.io/v1/user":         "/users/" + userID,
		"https://iam.weos.io/v1/subscription": "inactive",
		"https://iam.weos.io/v1/email":        "golden.user@example.com",
	}
}

type jwksServer struct {
	*httptest.Server
	mu      sync.Mutex
	body    []byte
	status  int
	gate    chan struct{} // when set, responses wait until it is closed
	fetches atomic.Int32
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	s := &jwksServer{body: body, status: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		s.mu.Lock()
		gate := s.gate
		s.mu.Unlock()
		if gate != nil {
			<-gate
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) set(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

// slow makes the server hold every response until the returned release is
// called (release is idempotent and also runs at cleanup, before Close).
func (s *jwksServer) slow(t *testing.T) (release func()) {
	gate := make(chan struct{})
	s.mu.Lock()
	s.gate = gate
	s.mu.Unlock()
	var once sync.Once
	release = func() {
		once.Do(func() {
			s.mu.Lock()
			s.gate = nil
			s.mu.Unlock()
			close(gate)
		})
	}
	t.Cleanup(release)
	return release
}

// remoteOf is the JWKS cache of one issuer of a trusted-issuer validator.
func remoteOf(t *testing.T, validator *OpenIDConnect, issuer string) *remoteKeySet {
	t.Helper()
	state, ok := validator.trusted.issuers[issuer]
	if !ok || state.remote == nil {
		t.Fatalf("no JWKS issuer %q", issuer)
	}
	return state.remote
}

func jwksOf(t *testing.T, keys ...testKey) []byte {
	var list []map[string]interface{}
	for _, k := range keys {
		list = append(list, k.jwk())
	}
	raw, err := json.Marshal(map[string]interface{}{"keys": list})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// newValidator builds the OpenIDConnect validator from learning's scheme, the
// way NewSecurityConfiguration does (FromSchema reads the environment).
func newValidator(t *testing.T, discoveryURL string, now func() time.Time) *OpenIDConnect {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData([]byte(fmt.Sprintf(learningSchemeYAML, discoveryURL)))
	if err != nil {
		t.Fatal(err)
	}
	o := &OpenIDConnect{now: now}
	if _, err = o.FromSchema(context.Background(), doc.Components.SecuritySchemes["OpenIdConnect"].Value, http.DefaultClient); err != nil {
		t.Fatalf("FromSchema: %s", err)
	}
	return o
}

type requestValues struct {
	status         int
	userID         interface{}
	role           interface{}
	accountID      interface{}
	applicationID  interface{}
	subscriptionID interface{}
	authorization  interface{}
}

// serve runs one request through WeOS's SecurityMiddleware and records the
// context values the next handler sees.
func serve(t *testing.T, validator Validator, token string) requestValues {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData([]byte(fmt.Sprintf(learningSchemeYAML, "http://unused.invalid")))
	if err != nil {
		t.Fatal(err)
	}
	model, err := casbinmodel.NewModelFromString(`[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
`)
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := casbin.NewEnforcer(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = enforcer.AddPolicy("user", "/*", "GET"); err != nil {
		t.Fatal(err)
	}
	mw := SecurityMiddleware(&MiddlewareParams{
		Logger:                nil,
		Schema:                doc,
		APIConfig:             &APIConfig{},
		SecuritySchemes:       map[string]Validator{"OpenIdConnect": validator},
		AuthorizationEnforcer: enforcer,
	})
	var got requestValues
	handler := mw(func(c echo.Context) error {
		ctx := c.Request().Context()
		got.userID = ctx.Value(USER_ID)
		got.role = ctx.Value(ROLE)
		got.accountID = ctx.Value(ACCOUNT_ID)
		got.applicationID = ctx.Value(APPLICATION_ID)
		got.subscriptionID = ctx.Value(SUBSCRIPTION_ID)
		got.authorization = ctx.Value(AUTHORIZATION_HEADER)
		return c.NoContent(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/questions", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	if err = handler(echo.New().NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	got.status = rec.Code
	return got
}

func clearIssuerEnv(t *testing.T) {
	for _, name := range []string{EnvJWTIssuer, EnvJWTJWKSURL, EnvJWTAudience, EnvLegacyIAMJWK, EnvLegacyIAMIssuer, EnvLegacyIAMAudience} {
		t.Setenv(name, "")
	}
}

// The golden token is a real medai-accounts token (testdata/accounts-golden,
// made by generate-golden.int.test.ts with accounts' own test harness).
func TestTrustedIssuers_GoldenAccountsTokenMatchesIAMToken(t *testing.T) {
	g := loadGolden(t)
	accounts := newJWKSServer(t, g.jwks)
	iam := newKey(t, "iam-test-key")
	c := &clock{t: g.time()}

	clearIssuerEnv(t)
	t.Setenv(EnvJWTIssuer, g.Issuer)
	t.Setenv(EnvJWTJWKSURL, accounts.URL+"/oauth2/certs")
	t.Setenv(EnvJWTAudience, g.Audience)
	t.Setenv(EnvLegacyIAMJWK, iam.jwkJSON(t))
	t.Setenv(EnvLegacyIAMIssuer, iamIssuer)
	t.Setenv(EnvLegacyIAMAudience, g.Audience)
	validator := newValidator(t, "http://iam-discovery-not-used.invalid", c.now)
	if validator.trusted == nil {
		t.Fatal("expected trusted-issuer mode")
	}

	fromAccounts := serve(t, validator, g.token)
	if fromAccounts.status != http.StatusOK {
		t.Fatalf("golden accounts token: status %d", fromAccounts.status)
	}
	want := requestValues{
		status:         http.StatusOK,
		userID:         "/users/" + g.UserID,
		role:           "user",
		accountID:      "/accounts/" + g.AccountID,
		applicationID:  g.Audience,
		subscriptionID: "inactive",
		authorization:  "Bearer " + g.token,
	}
	if fromAccounts != want {
		t.Fatalf("accounts token context:\n got %#v\nwant %#v", fromAccounts, want)
	}

	// The same user's token as IAM mints it, signed with the (test) pinned IAM key.
	iamToken := iam.sign(t, claimsFor(iamIssuer, g.Audience, g.UserID, g.AccountID, c.now()))
	fromIAM := serve(t, validator, iamToken)
	fromIAM.authorization, fromAccounts.authorization = nil, nil
	if fromIAM != fromAccounts {
		t.Fatalf("IAM vs accounts context values differ:\n iam      %#v\n accounts %#v", fromIAM, fromAccounts)
	}
	if n := accounts.fetches.Load(); n != 1 {
		t.Fatalf("expected one JWKS fetch, got %d", n)
	}
}

func TestTrustedIssuers_Refusals(t *testing.T) {
	g := loadGolden(t)
	accountsKey := newKey(t, "accounts-test-key")
	iam := newKey(t, "iam-test-key")
	other := newKey(t, "other-test-key")
	accounts := newJWKSServer(t, jwksOf(t, accountsKey))
	start := time.Now()
	c := &clock{t: start}

	validator := &OpenIDConnect{now: c.now, userIDClaim: "sub", roleClaim: "https://iam.weos.io/v1/roles",
		accountClaim: "https://iam.weos.io/v1/account", applicationClaim: "azp", subscriptionClaim: "https://iam.weos.io/v1/subscription"}
	if err := validator.WithTrustedIssuers([]TrustedIssuer{
		{Issuer: accountsIssuer, JWKSURL: accounts.URL, Audiences: []string{g.Audience}},
		{Issuer: iamIssuer, PinnedKeys: []PublicJWK{{KeyID: iam.kid, Key: &iam.key.PublicKey}}, Audiences: []string{g.Audience}},
	}); err != nil {
		t.Fatal(err)
	}

	good := claimsFor(accountsIssuer, g.Audience, g.UserID, g.AccountID, start)
	with := func(base jwt.MapClaims, key string, value interface{}) jwt.MapClaims {
		out := jwt.MapClaims{}
		for k, v := range base {
			out[k] = v
		}
		if value == nil {
			delete(out, key)
		} else {
			out[key] = value
		}
		return out
	}

	// Sanity: the well-formed tokens pass.
	for name, token := range map[string]string{
		"accounts": accountsKey.sign(t, good),
		"iam":      iam.sign(t, with(good, "iss", iamIssuer)),
	} {
		if got := serve(t, validator, token); got.status != http.StatusOK {
			t.Fatalf("%s token refused: %d", name, got.status)
		}
	}

	hs256 := func(claims jwt.MapClaims) string {
		// Classic confusion attack: HMAC keyed with the issuer's public key bytes.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token.Header["kid"] = accountsKey.kid
		s, err := token.SignedString(accountsKey.key.N.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	none := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		s, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	hs256Mac := func(claims jwt.MapClaims) string {
		// Same attack, hand-built so the header claims RS-style kid but alg HS256.
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"accounts-test-key"}`))
		body, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(body)
		mac := hmac.New(sha256.New, []byte(accountsKey.jwkJSON(t)))
		mac.Write([]byte(header + "." + payload))
		return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	unknownKid := newKey(t, "accounts-unknown-kid")

	cases := map[string]string{
		"wrong issuer":                     accountsKey.sign(t, with(good, "iss", "https://evil.example.com")),
		"no issuer":                        accountsKey.sign(t, with(good, "iss", nil)),
		"wrong audience":                   accountsKey.sign(t, with(good, "aud", []string{"someone-else"})),
		"no audience":                      accountsKey.sign(t, with(good, "aud", nil)),
		"expired":                          accountsKey.sign(t, with(good, "exp", start.Add(-time.Minute).Unix())),
		"no exp":                           accountsKey.sign(t, with(good, "exp", nil)),
		"not yet valid":                    accountsKey.sign(t, with(good, "nbf", start.Add(time.Hour).Unix())),
		"HS256 keyed with public modulus":  hs256(good),
		"HS256 keyed with public JWK":      hs256Mac(good),
		"alg none":                         none(good),
		"legacy IAM key, accounts issuer":  iam.sign(t, good),
		"accounts key, legacy issuer":      accountsKey.sign(t, with(good, "iss", iamIssuer)),
		"legacy IAM token, wrong audience": iam.sign(t, with(with(good, "iss", iamIssuer), "aud", []string{"m2m-audience"})),
		"untrusted key, accounts kid":      testKey{kid: accountsKey.kid, key: other.key}.sign(t, good),
		"unknown kid":                      unknownKid.sign(t, good),
		"machine token (no user claim)":    accountsKey.sign(t, with(good, "https://iam.weos.io/v1/user", nil)),
		"user claim differs from sub":      accountsKey.sign(t, with(good, "https://iam.weos.io/v1/user", "/users/someone-else")),
		"no sub":                           accountsKey.sign(t, with(good, "sub", nil)),
		"user claim not a string":          accountsKey.sign(t, with(good, "https://iam.weos.io/v1/user", 42)),
		"legacy IAM machine token":         iam.sign(t, with(with(good, "iss", iamIssuer), "https://iam.weos.io/v1/user", nil)),
		"garbage":                          "not.a.jwt",
		"empty":                            "",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			got := serve(t, validator, token)
			if got.status != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", got.status)
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			result, err := validator.Validate(echo.New().NewContext(req, httptest.NewRecorder()))
			if result == nil || result.Valid || err == nil {
				t.Fatalf("expected an invalid result with an error, got %#v, %v", result, err)
			}
		})
	}
}

func TestTrustedIssuers_JWKSCaching(t *testing.T) {
	g := loadGolden(t)
	k1 := newKey(t, "rotation-1")
	k2 := newKey(t, "rotation-2")
	server := newJWKSServer(t, jwksOf(t, k1))
	c := &clock{t: time.Now()}
	validator := &OpenIDConnect{now: c.now, userIDClaim: "sub", roleClaim: "https://iam.weos.io/v1/roles"}
	if err := validator.WithTrustedIssuers([]TrustedIssuer{{Issuer: accountsIssuer, JWKSURL: server.URL, Audiences: []string{g.Audience}}}); err != nil {
		t.Fatal(err)
	}
	if n := server.fetches.Load(); n != 0 {
		t.Fatalf("keys must be fetched lazily, not at boot (fetches %d)", n)
	}
	validate := func(token string) bool {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		result, _ := validator.Validate(echo.New().NewContext(req, httptest.NewRecorder()))
		return result.Valid
	}
	tok := func(k testKey) string {
		return k.sign(t, claimsFor(accountsIssuer, g.Audience, g.UserID, g.AccountID, c.now()))
	}

	for i := 0; i < 20; i++ {
		if !validate(tok(k1)) {
			t.Fatal("k1 token refused")
		}
	}
	if n := server.fetches.Load(); n != 1 {
		t.Fatalf("20 requests should fetch the JWKS once, fetched %d", n)
	}

	// Right after a fetch, an unknown kid does not refetch (minimum interval).
	if validate(tok(k2)) {
		t.Fatal("k2 is not published yet")
	}
	if n := server.fetches.Load(); n != 1 {
		t.Fatalf("an unknown kid right after a fetch must not refetch, fetched %d", n)
	}

	// After the interval, an unknown kid triggers one refresh; more unknown kids
	// within the next interval do not hit the issuer again.
	c.add(jwksMinRefreshInterval + time.Second)
	for i := 0; i < 10; i++ {
		if validate(tok(k2)) {
			t.Fatal("k2 is not published yet")
		}
	}
	if n := server.fetches.Load(); n != 2 {
		t.Fatalf("unknown kids should refresh once per interval, fetched %d", n)
	}

	// Key rotation: k2 published; after the minimum interval the unknown kid is picked up.
	server.set(http.StatusOK, jwksOf(t, k1, k2))
	if validate(tok(k2)) {
		t.Fatal("refresh should still be rate-limited")
	}
	c.add(jwksMinRefreshInterval + time.Second)
	if !validate(tok(k2)) {
		t.Fatal("k2 should be accepted after the refresh")
	}
	if n := server.fetches.Load(); n != 3 {
		t.Fatalf("expected 3 fetches, got %d", n)
	}

	// Issuer down: cached keys keep working after they go stale.
	remote := remoteOf(t, validator, accountsIssuer)
	server.set(http.StatusServiceUnavailable, []byte(`{}`))
	c.add(jwksMaxAge + time.Second)
	if !validate(tok(k1)) || !validate(tok(k2)) {
		t.Fatal("cached keys must keep working while the JWKS is unreachable")
	}
	remote.background.Wait()
	if !validate(tok(k1)) || !validate(tok(k2)) {
		t.Fatal("cached keys must keep working after the refresh failed")
	}
	if n := server.fetches.Load(); n != 4 {
		t.Fatalf("stale cache should try one refresh, fetched %d", n)
	}

	// A key removed from the JWKS stops working once the next refresh has run.
	server.set(http.StatusOK, jwksOf(t, k2))
	c.add(jwksMaxAge + time.Second)
	if !validate(tok(k1)) {
		t.Fatal("the cached k1 is served while the background refresh runs")
	}
	remote.background.Wait()
	if validate(tok(k1)) {
		t.Fatal("k1 was removed from the JWKS and must be refused")
	}
	if !validate(tok(k2)) {
		t.Fatal("k2 still published")
	}
}

// A slow JWKS host never delays a request whose kid is cached: the stale cache
// serves while one background refresh runs. An unknown kid waits for one
// refetch per interval, and a failed refresh keeps the cached keys.
func TestTrustedIssuers_StaleCacheRefreshesInBackground(t *testing.T) {
	g := loadGolden(t)
	k1 := newKey(t, "rotation-1")
	k2 := newKey(t, "rotation-2")
	k3 := newKey(t, "rotation-3")
	server := newJWKSServer(t, jwksOf(t, k1))
	c := &clock{t: time.Now()}
	validator := &OpenIDConnect{now: c.now, userIDClaim: "sub", roleClaim: "https://iam.weos.io/v1/roles"}
	if err := validator.WithTrustedIssuers([]TrustedIssuer{{Issuer: accountsIssuer, JWKSURL: server.URL, Audiences: []string{g.Audience}}}); err != nil {
		t.Fatal(err)
	}
	remote := remoteOf(t, validator, accountsIssuer)
	validate := func(token string) bool {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		result, _ := validator.Validate(echo.New().NewContext(req, httptest.NewRecorder()))
		return result.Valid
	}
	tok := func(k testKey) string {
		return k.sign(t, claimsFor(accountsIssuer, g.Audience, g.UserID, g.AccountID, c.now()))
	}
	if !validate(tok(k1)) {
		t.Fatal("k1 token refused")
	}

	// Stale cache, JWKS host hanging: concurrent requests with the cached kid
	// return at once and start a single background fetch.
	release := server.slow(t)
	c.add(jwksMaxAge + time.Second)
	token := tok(k1)
	var wg sync.WaitGroup
	var refused atomic.Int32
	start := time.Now()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !validate(token) {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("requests with a cached kid waited for the JWKS host (%s)", elapsed)
	}
	if refused.Load() != 0 {
		t.Fatalf("%d requests with a cached kid refused", refused.Load())
	}
	release()
	remote.background.Wait()
	if n := server.fetches.Load(); n != 2 {
		t.Fatalf("a stale cache should start one background refresh, fetched %d", n)
	}

	// Unknown kid: one synchronous refetch, then none within the interval.
	server.set(http.StatusOK, jwksOf(t, k1, k2))
	c.add(jwksMinRefreshInterval + time.Second)
	if !validate(tok(k2)) {
		t.Fatal("k2 should be fetched for its unknown kid")
	}
	for i := 0; i < 5; i++ {
		if validate(tok(k3)) {
			t.Fatal("k3 is not published")
		}
	}
	if n := server.fetches.Load(); n != 3 {
		t.Fatalf("an unknown kid should refetch once per interval, fetched %d", n)
	}

	// Refresh fails: cached keys keep working, retried once per interval.
	server.set(http.StatusServiceUnavailable, []byte(`{}`))
	c.add(jwksMaxAge + time.Second)
	for round := 0; round < 2; round++ {
		for i := 0; i < 5; i++ {
			if !validate(tok(k1)) || !validate(tok(k2)) {
				t.Fatal("cached keys must keep working while the refresh fails")
			}
		}
		remote.background.Wait()
		if n, want := server.fetches.Load(), int32(4+round); n != want {
			t.Fatalf("failed refresh round %d: fetched %d, want %d", round, n, want)
		}
		c.add(jwksMinRefreshInterval + time.Second)
	}
}

func TestTrustedIssuersFromEnv(t *testing.T) {
	iam := newKey(t, "iam-test-key")
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	issuers, err := TrustedIssuersFromEnv(env(nil))
	if err != nil || issuers != nil {
		t.Fatalf("no config must mean no trusted issuers, got %v, %v", issuers, err)
	}

	issuers, err = TrustedIssuersFromEnv(env(map[string]string{
		EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://auth.medicalstudent.ai/oauth2/certs", EnvJWTAudience: "aud-1, aud-2",
		EnvLegacyIAMJWK: iam.jwkJSON(t), EnvLegacyIAMIssuer: iamIssuer, EnvLegacyIAMAudience: "iam-client-id",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(issuers) != 2 || issuers[0].Issuer != accountsIssuer || issuers[1].Issuer != iamIssuer {
		t.Fatalf("unexpected issuers %#v", issuers)
	}
	if strings.Join(issuers[0].Audiences, "|") != "aud-1|aud-2" || strings.Join(issuers[1].Audiences, "|") != "iam-client-id" {
		t.Fatalf("audiences: %#v %#v", issuers[0].Audiences, issuers[1].Audiences)
	}
	if issuers[1].PinnedKeys[0].KeyID != iam.kid || issuers[1].PinnedKeys[0].Key.N.Cmp(iam.key.N) != 0 {
		t.Fatal("pinned key not parsed")
	}

	// Accounts only (after the overlap): the IAM issuer is gone by config.
	issuers, err = TrustedIssuersFromEnv(env(map[string]string{EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://x/certs", EnvJWTAudience: "a"}))
	if err != nil || len(issuers) != 1 {
		t.Fatalf("accounts only: %v %v", issuers, err)
	}

	privateJWK, _ := json.Marshal(map[string]string{"kty": "RSA", "n": "AQAB", "e": "AQAB", "d": "c2VjcmV0LXByaXZhdGUtcGFydA"})
	bad := map[string]map[string]string{
		"issuer without JWKS":       {EnvJWTIssuer: accountsIssuer, EnvJWTAudience: "a"},
		"JWKS without issuer":       {EnvJWTJWKSURL: "https://x/certs", EnvJWTAudience: "a"},
		"issuer without audience":   {EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://x/certs"},
		"legacy key alone":          {EnvLegacyIAMJWK: iam.jwkJSON(t)},
		"legacy without issuer":     {EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://x/certs", EnvJWTAudience: "a", EnvLegacyIAMJWK: iam.jwkJSON(t), EnvLegacyIAMAudience: "a"},
		"legacy without audience":   {EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://x/certs", EnvJWTAudience: "a", EnvLegacyIAMJWK: iam.jwkJSON(t), EnvLegacyIAMIssuer: iamIssuer},
		"legacy issuer == issuer":   {EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://x/certs", EnvJWTAudience: "a", EnvLegacyIAMJWK: iam.jwkJSON(t), EnvLegacyIAMIssuer: accountsIssuer, EnvLegacyIAMAudience: "a"},
		"legacy issuer without key": {EnvJWTIssuer: accountsIssuer, EnvJWTJWKSURL: "https://x/certs", EnvJWTAudience: "a", EnvLegacyIAMIssuer: iamIssuer},
		"private JWK":               {EnvLegacyIAMJWK: string(privateJWK), EnvLegacyIAMIssuer: iamIssuer, EnvLegacyIAMAudience: "a"},
		"not JSON":                  {EnvLegacyIAMJWK: "-----BEGIN PUBLIC KEY-----", EnvLegacyIAMIssuer: iamIssuer, EnvLegacyIAMAudience: "a"},
		"audience alone":            {EnvJWTAudience: "a"},
	}
	for name, vars := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := TrustedIssuersFromEnv(env(vars))
			if err == nil {
				t.Fatal("expected an error")
			}
			if jwkValue := vars[EnvLegacyIAMJWK]; jwkValue != "" && strings.Contains(err.Error(), jwkValue) {
				t.Fatal("the error must not echo the JWK value")
			}
			if strings.Contains(err.Error(), "c2VjcmV0") {
				t.Fatal("the error must not echo key material")
			}
		})
	}

	// FromSchema fails (boot fails) on a bad config instead of running unprotected.
	clearIssuerEnv(t)
	t.Setenv(EnvJWTIssuer, accountsIssuer)
	doc, err := openapi3.NewLoader().LoadFromData([]byte(fmt.Sprintf(learningSchemeYAML, "http://x")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = new(OpenIDConnect).FromSchema(context.Background(), doc.Components.SecuritySchemes["OpenIdConnect"].Value, http.DefaultClient); err == nil {
		t.Fatal("FromSchema must refuse an incomplete trusted-issuer config")
	}

	// The legacy IAM issuer and audience have no defaults: boot names each missing one.
	clearIssuerEnv(t)
	t.Setenv(EnvJWTIssuer, accountsIssuer)
	t.Setenv(EnvJWTJWKSURL, "https://x/certs")
	t.Setenv(EnvJWTAudience, "a")
	t.Setenv(EnvLegacyIAMJWK, iam.jwkJSON(t))
	_, err = new(OpenIDConnect).FromSchema(context.Background(), doc.Components.SecuritySchemes["OpenIdConnect"].Value, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), EnvLegacyIAMIssuer+" is required") || !strings.Contains(err.Error(), EnvLegacyIAMAudience+" is required") {
		t.Fatalf("FromSchema must name the missing legacy IAM settings, got %v", err)
	}
}

// With none of the new variables set, the validator behaves as before: it
// fetches the discovery document on every request and checks neither iss nor aud.
func TestTrustedIssuers_NoConfigKeepsDiscoveryBehaviour(t *testing.T) {
	g := loadGolden(t)
	key := newKey(t, "discovery-key")
	var discoveryFetches atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryFetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                "https://msa-api-iam.azurewebsites.net",
			"jwks_uri":                              server.URL + "/oauth2/certs",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/oauth2/certs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwksOf(t, key))
	})

	clearIssuerEnv(t)
	validator := newValidator(t, server.URL+"/.well-known/openid-configuration", nil)
	if validator.trusted != nil {
		t.Fatal("no config must keep the discovery-document mode")
	}
	// Any issuer and audience pass, as today.
	token := key.sign(t, claimsFor("https://anything.example.com", "any-audience", g.UserID, g.AccountID, time.Now()))
	for i := 0; i < 2; i++ {
		got := serve(t, validator, token)
		if got.status != http.StatusOK || got.userID != "/users/"+g.UserID || got.applicationID != "any-audience" || got.subscriptionID != "inactive" {
			t.Fatalf("discovery mode: %#v", got)
		}
	}
	if n := discoveryFetches.Load(); n != 2 {
		t.Fatalf("discovery mode fetches the document per request (today's behaviour); got %d", n)
	}
}

func TestTrustedIssuers_ConcurrentFirstRequestsFetchOnce(t *testing.T) {
	g := loadGolden(t)
	k := newKey(t, "concurrent")
	server := newJWKSServer(t, jwksOf(t, k))
	validator := &OpenIDConnect{userIDClaim: "sub", roleClaim: "https://iam.weos.io/v1/roles"}
	if err := validator.WithTrustedIssuers([]TrustedIssuer{{Issuer: accountsIssuer, JWKSURL: server.URL, Audiences: []string{g.Audience}}}); err != nil {
		t.Fatal(err)
	}
	token := k.sign(t, claimsFor(accountsIssuer, g.Audience, g.UserID, g.AccountID, time.Now()))
	var wg sync.WaitGroup
	var refused atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			if result, _ := validator.Validate(echo.New().NewContext(req, httptest.NewRecorder())); !result.Valid {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if refused.Load() != 0 {
		t.Fatalf("%d concurrent requests refused", refused.Load())
	}
	if n := server.fetches.Load(); n != 1 {
		t.Fatalf("50 concurrent first requests should fetch once, fetched %d", n)
	}
}
