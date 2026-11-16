package rest

// Trusted issuers: verifying tokens from a configured list of issuers, each
// with its own key source, instead of fetching one discovery document on every
// request.
//
// Without configuration (none of the environment variables below set) the
// OpenIDConnect validator keeps its original behaviour: it fetches the scheme's
// openIdConnectUrl on every request and does not check iss or aud. Set any of
// them and the validator switches to trusted-issuer mode for every
// openIdConnect scheme:
//
//	JWT_ISSUER           exact `iss` of the primary issuer (e.g. https://auth.medicalstudent.ai)
//	JWT_JWKS_URL         JWKS of that issuer (e.g. https://auth.medicalstudent.ai/oauth2/certs)
//	JWT_AUDIENCE         `aud` the token must contain (comma-separated for several)
//	LEGACY_IAM_JWK       pinned RSA public JWK of the old IAM issuer; unset = old IAM tokens refused
//	LEGACY_IAM_ISSUER    `iss` accepted with that key: IAM's BASE_URL+BASE_PATH, exactly as IAM
//	                     puts it in its tokens. Required when LEGACY_IAM_JWK is set (no default).
//	LEGACY_IAM_AUDIENCE  `aud` for old IAM tokens: IAM's WEOS_CLIENT_ID (comma-separated for
//	                     several). Required when LEGACY_IAM_JWK is set (no default).
//
// In trusted-issuer mode a token is accepted only when its `iss` is one of the
// configured issuers, its signature verifies with THAT issuer's keys (a key is
// never accepted with another issuer), alg is RS256, `exp` is present and in
// the future, and `aud` contains one of that issuer's audiences. Claims are
// then mapped exactly as before (x-jwt-map, string casts).
//
// JWKS keys are fetched lazily (the service boots when the issuer is down) and
// cached. A token whose `kid` is cached is always served from the cache: once
// the cache is older than jwksMaxAge, one background refresh starts and the
// request does not wait for it. Only a token with an unknown `kid` (or the
// very first token) waits for a fetch. Fetches of either kind happen at most
// once per jwksMinRefreshInterval. When a refresh fails the keys already
// cached keep working.

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// EnvJWTIssuer is the exact `iss` of the primary token issuer.
	EnvJWTIssuer = "JWT_ISSUER"
	// EnvJWTJWKSURL is the JWKS URL of the primary token issuer.
	EnvJWTJWKSURL = "JWT_JWKS_URL"
	// EnvJWTAudience is the audience (comma-separated list) tokens must carry.
	EnvJWTAudience = "JWT_AUDIENCE"
	// EnvLegacyIAMJWK is the pinned public JWK of the old IAM issuer.
	EnvLegacyIAMJWK = "LEGACY_IAM_JWK"
	// EnvLegacyIAMIssuer is the `iss` accepted with the pinned IAM key (IAM's
	// BASE_URL+BASE_PATH). Required with EnvLegacyIAMJWK.
	EnvLegacyIAMIssuer = "LEGACY_IAM_ISSUER"
	// EnvLegacyIAMAudience is the audience of old IAM tokens (IAM's
	// WEOS_CLIENT_ID). Required with EnvLegacyIAMJWK.
	EnvLegacyIAMAudience = "LEGACY_IAM_AUDIENCE"

	jwksMaxAge             = 10 * time.Minute
	jwksMinRefreshInterval = 30 * time.Second
	jwksFetchTimeout       = 10 * time.Second
	jwksMaxBodyBytes       = 1 << 20
	tokenLeeway            = 5 * time.Second
	minRSAKeyBits          = 2048
)

// TrustedIssuer is one issuer a validator accepts tokens from.
type TrustedIssuer struct {
	// Issuer is compared with `iss` exactly.
	Issuer string
	// Audiences: the token's `aud` must contain at least one. Required.
	Audiences []string
	// JWKSURL is the issuer's key set (set this or PinnedKeys, not both).
	JWKSURL string
	// PinnedKeys are fixed public keys (e.g. the old IAM key during the overlap).
	PinnedKeys []PublicJWK
}

// PublicJWK is an RSA public key with its optional key id.
type PublicJWK struct {
	KeyID string
	Key   *rsa.PublicKey
}

// TrustedIssuersFromEnv reads the trusted-issuer configuration. It returns
// (nil, nil) when none of the variables is set, which keeps the original
// discovery-document behaviour.
func TrustedIssuersFromEnv(getenv func(string) string) ([]TrustedIssuer, error) {
	get := func(name string) string { return strings.TrimSpace(getenv(name)) }
	issuer, jwksURL, audience := get(EnvJWTIssuer), get(EnvJWTJWKSURL), get(EnvJWTAudience)
	legacyJWK, legacyIssuer, legacyAudience := get(EnvLegacyIAMJWK), get(EnvLegacyIAMIssuer), get(EnvLegacyIAMAudience)

	if issuer == "" && jwksURL == "" && audience == "" && legacyJWK == "" && legacyIssuer == "" && legacyAudience == "" {
		return nil, nil
	}

	var problems []string
	var issuers []TrustedIssuer
	if issuer != "" || jwksURL != "" {
		if issuer == "" {
			problems = append(problems, EnvJWTIssuer+" is required when "+EnvJWTJWKSURL+" is set")
		}
		if jwksURL == "" {
			problems = append(problems, EnvJWTJWKSURL+" is required when "+EnvJWTIssuer+" is set")
		}
		if audience == "" {
			problems = append(problems, EnvJWTAudience+" is required when "+EnvJWTIssuer+" is set")
		}
		issuers = append(issuers, TrustedIssuer{Issuer: issuer, JWKSURL: jwksURL, Audiences: splitList(audience)})
	}
	if legacyJWK != "" {
		// No defaults: IAM's issuer and audience differ per environment, and a
		// guessed value either refuses every IAM token or accepts the wrong ones.
		if legacyIssuer == "" {
			problems = append(problems, EnvLegacyIAMIssuer+" is required when "+EnvLegacyIAMJWK+" is set (IAM's BASE_URL+BASE_PATH, the `iss` of its tokens)")
		}
		if legacyAudience == "" {
			problems = append(problems, EnvLegacyIAMAudience+" is required when "+EnvLegacyIAMJWK+" is set (IAM's WEOS_CLIENT_ID, the `aud` of its tokens)")
		}
		if legacyIssuer != "" && legacyIssuer == issuer {
			problems = append(problems, EnvLegacyIAMIssuer+" must differ from "+EnvJWTIssuer+" (the IAM key is accepted only with IAM's issuer)")
		}
		key, err := ParsePublicJWK([]byte(legacyJWK))
		if err != nil {
			// Never echo the value: name the variable only.
			problems = append(problems, EnvLegacyIAMJWK+": "+err.Error())
		}
		issuers = append(issuers, TrustedIssuer{Issuer: legacyIssuer, PinnedKeys: []PublicJWK{key}, Audiences: splitList(legacyAudience)})
	} else if legacyIssuer != "" || legacyAudience != "" {
		problems = append(problems, EnvLegacyIAMIssuer+"/"+EnvLegacyIAMAudience+" are set but "+EnvLegacyIAMJWK+" is not")
	}
	if len(issuers) == 0 && len(problems) == 0 {
		problems = append(problems, EnvJWTAudience+" is set but neither "+EnvJWTIssuer+" nor "+EnvLegacyIAMJWK+" is")
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("trusted issuer configuration: %s", strings.Join(problems, "; "))
	}
	return issuers, nil
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

type jwkJSON struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
}

// ParsePublicJWK parses one RSA public JWK (kty RSA, alg RS256 if present,
// use sig if present, at least 2048 bits). A JWK carrying a private part is
// refused, so a private key is never accepted as config by mistake.
func ParsePublicJWK(raw []byte) (PublicJWK, error) {
	var k jwkJSON
	if err := json.Unmarshal(raw, &k); err != nil {
		return PublicJWK{}, errors.New("not a JSON JWK")
	}
	return k.publicKey()
}

func (k jwkJSON) publicKey() (PublicJWK, error) {
	if k.Kty != "RSA" {
		return PublicJWK{}, errors.New("kty must be RSA")
	}
	if k.D != "" {
		return PublicJWK{}, errors.New("must be a public key (has a private part)")
	}
	if k.Alg != "" && k.Alg != "RS256" {
		return PublicJWK{}, errors.New("alg must be RS256")
	}
	if k.Use != "" && k.Use != "sig" {
		return PublicJWK{}, errors.New("use must be sig")
	}
	n, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
	if err != nil || len(n) == 0 {
		return PublicJWK{}, errors.New("bad modulus")
	}
	e, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
	if err != nil || len(e) == 0 || len(e) > 4 {
		return PublicJWK{}, errors.New("bad exponent")
	}
	exponent := int(new(big.Int).SetBytes(e).Int64())
	if exponent < 3 || exponent%2 == 0 {
		return PublicJWK{}, errors.New("bad exponent")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	if key.N.BitLen() < minRSAKeyBits {
		return PublicJWK{}, fmt.Errorf("RSA key shorter than %d bits", minRSAKeyBits)
	}
	return PublicJWK{KeyID: k.Kid, Key: key}, nil
}

// remoteKeySet caches one issuer's JWKS.
type remoteKeySet struct {
	url        string
	httpClient *http.Client
	now        func() time.Time

	fetchMu sync.Mutex // one fetch at a time

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	noKidKeys   []*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
	refreshing  bool // a background refresh is running

	// background tracks background refreshes (tests wait on it).
	background sync.WaitGroup
}

// keysFor returns the keys to try for a token with this kid. A cached kid is
// served at once; when the cache is older than jwksMaxAge a background refresh
// starts (single-flight). Only an unknown kid waits for a fetch. Fetches are
// never more often than jwksMinRefreshInterval.
func (s *remoteKeySet) keysFor(ctx context.Context, kid string) ([]*rsa.PublicKey, error) {
	keys, fresh := s.lookup(kid)
	if len(keys) > 0 {
		if !fresh {
			s.refreshInBackground()
		}
		return keys, nil
	}
	refreshErr := s.refresh(ctx)
	if keys, _ = s.lookup(kid); len(keys) > 0 {
		return keys, nil // stale keys still serve when the refresh failed
	}
	if refreshErr != nil {
		return nil, fmt.Errorf("no key for kid %q: %w", kid, refreshErr)
	}
	return nil, fmt.Errorf("no key for kid %q", kid)
}

func (s *remoteKeySet) lookup(kid string) ([]*rsa.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fresh := !s.fetchedAt.IsZero() && s.now().Sub(s.fetchedAt) < jwksMaxAge
	if kid != "" {
		if key, ok := s.keys[kid]; ok {
			return []*rsa.PublicKey{key}, fresh
		}
		return nil, fresh
	}
	// A token without a kid may be checked against every key in the set.
	all := make([]*rsa.PublicKey, 0, len(s.keys)+len(s.noKidKeys))
	for _, key := range s.keys {
		all = append(all, key)
	}
	return append(all, s.noKidKeys...), fresh
}

var errJWKSRateLimited = errors.New("jwks refreshed recently")

// refreshInBackground starts one refresh unless one is already running or the
// last attempt was within jwksMinRefreshInterval. It never blocks the caller.
// The fetch is detached from the request (which may end first) and bounded by
// jwksFetchTimeout. A failure leaves the cached keys in place.
func (s *remoteKeySet) refreshInBackground() {
	s.mu.Lock()
	if s.refreshing || (!s.lastAttempt.IsZero() && s.now().Sub(s.lastAttempt) < jwksMinRefreshInterval) {
		s.mu.Unlock()
		return
	}
	s.refreshing = true
	s.background.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.background.Done()
		defer func() {
			s.mu.Lock()
			s.refreshing = false
			s.mu.Unlock()
		}()
		_ = s.refresh(context.Background())
	}()
}

func (s *remoteKeySet) refresh(ctx context.Context) error {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	s.mu.RLock()
	last := s.lastAttempt
	s.mu.RUnlock()
	if !last.IsZero() && s.now().Sub(last) < jwksMinRefreshInterval {
		return errJWKSRateLimited
	}
	s.mu.Lock()
	s.lastAttempt = s.now()
	s.mu.Unlock()

	keys, noKid, err := s.fetch(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys, s.noKidKeys, s.fetchedAt = keys, noKid, s.now()
	s.mu.Unlock()
	return nil
}

func (s *remoteKeySet) fetch(ctx context.Context) (map[string]*rsa.PublicKey, []*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("jwks read: %w", err)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err = json.Unmarshal(body, &set); err != nil {
		return nil, nil, fmt.Errorf("jwks decode: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	var noKid []*rsa.PublicKey
	for _, raw := range set.Keys {
		var k jwkJSON
		if json.Unmarshal(raw, &k) != nil {
			continue
		}
		parsed, err := k.publicKey()
		if err != nil {
			continue // skip keys we would never accept (EC, HS, short RSA, enc)
		}
		if parsed.KeyID == "" {
			noKid = append(noKid, parsed.Key)
		} else {
			keys[parsed.KeyID] = parsed.Key
		}
	}
	if len(keys) == 0 && len(noKid) == 0 {
		return nil, nil, errors.New("jwks has no usable RS256 keys")
	}
	return keys, noKid, nil
}

type issuerState struct {
	TrustedIssuer
	remote *remoteKeySet
}

func (s *issuerState) keysFor(ctx context.Context, kid string) ([]*rsa.PublicKey, error) {
	if s.remote != nil {
		return s.remote.keysFor(ctx, kid)
	}
	var keys []*rsa.PublicKey
	for _, pinned := range s.PinnedKeys {
		// A kid that names a different pinned key is not tried against this one.
		if kid != "" && pinned.KeyID != "" && pinned.KeyID != kid {
			continue
		}
		keys = append(keys, pinned.Key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no pinned key for kid %q", kid)
	}
	return keys, nil
}

// trustedIssuerVerifier verifies a token against a list of trusted issuers.
type trustedIssuerVerifier struct {
	issuers map[string]*issuerState
	now     func() time.Time
}

func newTrustedIssuerVerifier(issuers []TrustedIssuer, httpClient *http.Client, now func() time.Time) (*trustedIssuerVerifier, error) {
	if now == nil {
		now = time.Now
	}
	v := &trustedIssuerVerifier{issuers: make(map[string]*issuerState), now: now}
	for _, issuer := range issuers {
		if issuer.Issuer == "" {
			return nil, errors.New("trusted issuer without an issuer")
		}
		if _, dup := v.issuers[issuer.Issuer]; dup {
			return nil, fmt.Errorf("issuer %q configured twice", issuer.Issuer)
		}
		if len(issuer.Audiences) == 0 {
			return nil, fmt.Errorf("issuer %q has no audience", issuer.Issuer)
		}
		if (issuer.JWKSURL == "") == (len(issuer.PinnedKeys) == 0) {
			return nil, fmt.Errorf("issuer %q needs exactly one key source (JWKS URL or pinned keys)", issuer.Issuer)
		}
		state := &issuerState{TrustedIssuer: issuer}
		if issuer.JWKSURL != "" {
			state.remote = &remoteKeySet{url: issuer.JWKSURL, httpClient: httpClient, now: now}
		}
		v.issuers[issuer.Issuer] = state
	}
	if len(v.issuers) == 0 {
		return nil, errors.New("no trusted issuers")
	}
	return v, nil
}

// verify checks the token and returns its verified payload (the raw JSON).
func (v *trustedIssuerVerifier) verify(ctx context.Context, tokenString string) (payload []byte, err error) {
	var issuer *issuerState
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(tokenLeeway),
		jwt.WithTimeFunc(v.now),
	)
	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		iss, err := token.Claims.GetIssuer()
		if err != nil {
			return nil, err
		}
		state, ok := v.issuers[iss]
		if !ok {
			return nil, fmt.Errorf("untrusted issuer %q", iss)
		}
		kid, _ := token.Header["kid"].(string)
		keys, err := state.keysFor(ctx, kid)
		if err != nil {
			return nil, err
		}
		issuer = state
		set := jwt.VerificationKeySet{}
		for _, key := range keys {
			set.Keys = append(set.Keys, key)
		}
		return set, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid || issuer == nil {
		return nil, errors.New("invalid token")
	}
	audiences, err := token.Claims.GetAudience()
	if err != nil {
		return nil, err
	}
	if !containsAny(audiences, issuer.Audiences) {
		return nil, fmt.Errorf("token audience not accepted for issuer %q", issuer.Issuer)
	}
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

func containsAny(have []string, want []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}
