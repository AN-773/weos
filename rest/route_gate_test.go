package rest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"golang.org/x/net/context"
)

// --- Helpers ---------------------------------------------------------------

// captureLog is a Log that records Infof/Warnf/Errorf lines.
type captureLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLog) add(level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(format, args...))
}
func (l *captureLog) Debugf(format string, args ...interface{}) {}
func (l *captureLog) Infof(format string, args ...interface{})  { l.add("INFO", format, args...) }
func (l *captureLog) Warnf(format string, args ...interface{})  { l.add("WARN", format, args...) }
func (l *captureLog) Printf(format string, args ...interface{}) { l.add("PRINT", format, args...) }
func (l *captureLog) Errorf(format string, args ...interface{}) { l.add("ERROR", format, args...) }
func (l *captureLog) Fatalf(format string, args ...interface{}) { l.add("FATAL", format, args...) }
func (l *captureLog) Panicf(format string, args ...interface{}) { l.add("PANIC", format, args...) }
func (l *captureLog) Debug(args ...interface{})                 {}
func (l *captureLog) Info(args ...interface{})                  { l.add("INFO", "%s", fmt.Sprint(args...)) }
func (l *captureLog) Warn(args ...interface{})                  { l.add("WARN", "%s", fmt.Sprint(args...)) }
func (l *captureLog) Print(args ...interface{})                 { l.add("PRINT", "%s", fmt.Sprint(args...)) }
func (l *captureLog) Error(args ...interface{})                 { l.add("ERROR", "%s", fmt.Sprint(args...)) }
func (l *captureLog) Fatal(args ...interface{})                 { l.add("FATAL", "%s", fmt.Sprint(args...)) }
func (l *captureLog) Panic(args ...interface{})                 { l.add("PANIC", "%s", fmt.Sprint(args...)) }

func (l *captureLog) matching(prefix string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, line := range l.lines {
		if strings.Contains(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

// enforceCounter is a casbin logger that counts Enforce calls (casbin calls
// LogEnforce once per Enforce, whether or not logging is enabled).
type enforceCounter struct {
	mu sync.Mutex
	n  int
}

func (c *enforceCounter) EnableLog(bool)  {}
func (c *enforceCounter) IsEnabled() bool { return false }
func (c *enforceCounter) LogModel([][]string) {
}
func (c *enforceCounter) LogEnforce(string, []interface{}, bool, [][]string) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}
func (c *enforceCounter) LogRole([]string)                {}
func (c *enforceCounter) LogPolicy(map[string][][]string) {}
func (c *enforceCounter) LogError(error, ...string)       {}
func (c *enforceCounter) count() int                      { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func newCountingEnforcer(t *testing.T) (*casbin.Enforcer, *enforceCounter) {
	t.Helper()
	m, err := casbinmodel.NewModelFromString(casbinRESTModel)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	counter := &enforceCounter{}
	e.SetLogger(counter)
	return e, counter
}

// fakeValidator maps "Bearer <name>" to a fixed result; anything else is invalid.
type fakeValidator map[string]*ValidationResult

func (f fakeValidator) Validate(ctxt echo.Context) (*ValidationResult, error) {
	name := strings.TrimPrefix(ctxt.Request().Header.Get("Authorization"), "Bearer ")
	if result, ok := f[name]; ok {
		copied := *result
		copied.Valid = true
		copied.Token = name
		return &copied, nil
	}
	return &ValidationResult{Valid: false}, fmt.Errorf("unknown token")
}

func (f fakeValidator) FromSchema(context.Context, *openapi3.SecurityScheme, *http.Client) (Validator, error) {
	return f, nil
}

func user(id, role, tenant, tenantRole string) *ValidationResult {
	return &ValidationResult{UserID: "/users/" + id, Subject: "/users/" + id, User: "/users/" + id, Role: role, Tenant: tenant, TenantRole: tenantRole}
}

func withClaim(r *ValidationResult, claim string) *ValidationResult {
	r.Permissions, r.PermissionsClaimPresent = claim, true
	return r
}

func catalogueFile(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("route_gate_permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func loadDoc(t *testing.T, yaml string) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// gateDoc: casbin (x-auth) and gate declarations that agree on some routes and
// disagree on others, so the matrix shows who decides.
const gateDoc = `
openapi: 3.0.3
info: {title: t, version: "1"}
components:
  securitySchemes:
    OpenIdConnect:
      type: openIdConnect
      openIdConnectUrl: http://unused.invalid
security:
  - OpenIdConnect: []
paths:
  /public:
    get:
      operationId: getPublic
      x-access: public
      security: []
      responses: {"200": {description: ok}}
  /me:
    get:
      operationId: getMe
      x-access: signed-in
      x-auth:
        allow:
          roles: [Administrator, user]
      responses: {"200": {description: ok}}
  /generate:
    post:
      operationId: generate
      x-permission: content:generate
      x-auth:
        allow:
          roles: [Administrator]
      responses: {"200": {description: ok}}
  /global/{id}:
    put:
      operationId: editGlobal
      x-permission: catalog:edit-global
      x-auth:
        allow:
          roles: [Administrator]
      responses: {"200": {description: ok}}
  /legacy:
    get:
      operationId: legacyUndeclared
      x-auth:
        allow:
          roles: [user]
      responses: {"200": {description: ok}}
  /open-undeclared:
    get:
      operationId: openUndeclared
      security: []
      responses: {"200": {description: ok}}
`

var gateUsers = fakeValidator{
	// An accounts learner: claim present and empty.
	"learner": withClaim(user("l1", "user", "/tenants/medai", "user"), ""),
	// An accounts university admin: the admin bundle in the claim.
	"accounts-admin": withClaim(user("a1", "user", "/tenants/uni-1", "admin"), "catalog:edit,content:generate,content:review"),
	// An accounts token whose claim is "" although tenant_role says admin: no permissions, never the fallback.
	"accounts-empty": withClaim(user("a2", "user", "/tenants/uni-1", "admin"), ""),
	// An IAM token (no claim) for a university admin: the legacy admin bundle.
	"iam-admin": user("i1", "user", "/tenants/uni-1", "admin"),
	// An IAM token for MedAI staff: the legacy staff bundle.
	"iam-staff": user("i2", "Administrator", "", ""),
	// An IAM token for an Administrator who is a university user: not staff.
	"iam-admin-uni-user": user("i3", "Administrator", "/tenants/uni-1", "user"),
	// Superadmin as accounts mints it: v1/permissions "*" (the claim decides).
	"superadmin": withClaim(user("s1", "superadmin", "/tenants/medai", "user"), "*"),
	// v1/roles superadmin but v1/permissions "": the claim decides, none.
	"superadmin-role-empty-claim": withClaim(user("s2", "superadmin", "/tenants/medai", "user"), ""),
	// An IAM superadmin (no claim): legacy, exact role.
	"iam-superadmin": user("s3", "superadmin", "", ""),
	// A valid token that is not a user (sub differs from v1/user).
	"machine": {UserID: "svc", Subject: "svc", Role: "Administrator"},
}

type gateServer struct {
	echo     *echo.Echo
	counter  *enforceCounter
	enforcer *casbin.Enforcer
	boot     *captureLog
	reqLog   *bytes.Buffer
}

func newGateServer(t *testing.T, doc *openapi3.T, gate *RouteGate) (*gateServer, error) {
	t.Helper()
	enforcer, counter := newCountingEnforcer(t)
	e := echo.New()
	reqLog := &bytes.Buffer{}
	e.Logger.SetOutput(reqLog)
	e.Logger.SetLevel(log.DEBUG)
	boot := &captureLog{}
	if gate != nil {
		gate.onDisagree = func(line string) { reqLog.WriteString(line + "\n") }
	}
	err := RouteInitializer(RouteParams{
		Config:                doc,
		APIConfig:             testAPIConfig(),
		Echo:                  e,
		Logger:                boot,
		Controllers:           []map[string]Controller{{"ok": okController}},
		AuthorizationEnforcer: enforcer,
		SecuritySchemes:       map[string]Validator{"OpenIdConnect": gateUsers},
		RouteGate:             gate,
	})
	return &gateServer{echo: e, counter: counter, enforcer: enforcer, boot: boot, reqLog: reqLog}, err
}

func testAPIConfig() *APIConfig {
	return &APIConfig{ServiceConfig: &ServiceConfig{Log: &LogConfig{Level: "error"}}}
}

func okController(*ControllerParams) echo.HandlerFunc {
	return func(c echo.Context) error { return c.NoContent(http.StatusOK) }
}

func (s *gateServer) do(method, path, token string) int {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.echo.ServeHTTP(rec, req)
	return rec.Code
}

func withControllers(doc string) string {
	// every operation answers 200 from the test controller
	return strings.ReplaceAll(doc, "      responses:", "      x-controller: ok\n      responses:")
}

func gateFor(t *testing.T, doc *openapi3.T, mode RouteGateMode, strict bool) *RouteGate {
	t.Helper()
	gate, err := NewRouteGate(doc, mode, strict, DefaultPermissionCatalogue())
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

// --- Catalogue and claim helpers ------------------------------------------

func TestPermissionCatalogue_LegacyMatchesAccounts(t *testing.T) {
	c := DefaultPermissionCatalogue()
	join := func(list []string) string { return strings.Join(sortedCopy(list), ",") }
	owner, admin, staff := join(c.roles["owner"]), join(c.roles["admin"]), join(c.staff)
	if owner == "" || admin == "" || staff == "" || strings.Contains(admin, "roles:manage") || !strings.Contains(owner, "roles:manage") || !strings.Contains(staff, "tutor:prompts") {
		t.Fatalf("unexpected bundles: owner %q admin %q staff %q", owner, admin, staff)
	}
	const uni = "/tenants/uni-1"
	// The table of accounts' src/auth/permissions.test.ts (legacyPermissions).
	cases := []struct {
		name, roles, tenant, tenantRole, want string
	}{
		{"MedAI learner", "user", "/tenants/medai", "user", ""},
		{"MedAI learner, IAM token (empty tenant and role)", "user", "", "", ""},
		{"university owner", "user", uni, "owner", owner},
		{"university admin", "user", uni, "admin", admin},
		{"university user", "user", uni, "user", ""},
		{"staff Administrator (MedAI tenant)", "Administrator", "/tenants/medai", "user", staff},
		{"staff Administrator (IAM: no tenant)", "Administrator", "", "", staff},
		{"staff Administrator (bare tenant id)", "Administrator", "medai", "user", staff},
		{"Administrator who is a university user: not staff", "Administrator", uni, "user", ""},
		{"Administrator who is a university admin: admin bundle", "Administrator", uni, "admin", admin},
		{"superadmin", "superadmin", "/tenants/medai", "user", "*"},
		{"superadmin in a university", "superadmin", uni, "user", "*"},
		{"unknown tenant role", "user", uni, "Owner", ""},
		{"role spelled differently fails closed", "Superadmin", "", "", ""},
		{"administrator lower-case fails closed", "administrator", "", "", ""},
		{"nothing", "", "", "", ""},
		{"prototype-ish tenant role", "user", uni, "__proto__", ""},
		// The tenant is normalised as learning's tenantctx.NormalizeID does.
		{"staff Administrator (tenant URL with host)", "Administrator", "https://iam.example.test/tenants/medai", "user", staff},
		{"staff Administrator (/v1/tenants/medai)", "Administrator", "/v1/tenants/medai", "user", staff},
		{"staff Administrator (host and /v1)", "Administrator", "https://iam.example.test/v1/tenants/medai", "user", staff},
		{"staff Administrator (spaces)", "Administrator", " /tenants/medai ", "user", staff},
		{"university admin (tenant URL with host)", "user", "https://iam.example.test/tenants/uni-1", "admin", admin},
		{"Administrator in a university (tenant URL): not staff", "Administrator", "https://iam.example.test/v1/tenants/uni-1", "user", ""},
		{"junk tenant fails closed: not MedAI", "Administrator", "uni-1", "user", ""},
		{"host only fails closed: not MedAI", "Administrator", "https://iam.example.test", "user", ""},
		{"superadmin needs the exact role, no list", "superadmin,user", "", "", ""},
		{"superadmin padded is not superadmin", " superadmin", "", "", ""},
	}
	for _, tc := range cases {
		if got := join(c.LegacyPermissions(tc.roles, tc.tenant, tc.tenantRole)); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestPermissionCatalogue_LegacyTenantBasePath(t *testing.T) {
	c := DefaultPermissionCatalogue()
	t.Setenv("BASE_PATH", "/learning")
	staff := strings.Join(sortedCopy(c.staff), ",")
	for _, tenant := range []string{"/learning/tenants/medai", "https://iam.example.test/learning/tenants/medai", "/learning/v1/tenants/medai", "", "medai", "/tenants/medai"} {
		if got := strings.Join(sortedCopy(c.LegacyPermissions("Administrator", tenant, "user")), ","); got != staff {
			t.Errorf("tenant %q: got %q, want the staff bundle", tenant, got)
		}
	}
	if got := c.LegacyPermissions("Administrator", "/learning/tenants/uni-1", "user"); len(got) != 0 {
		t.Errorf("a university under BASE_PATH is not MedAI: %v", got)
	}
}

func TestEffectivePermissions_ClaimDecidesAndLegacyIssuer(t *testing.T) {
	c := DefaultPermissionCatalogue()
	join := func(list []string) string { return strings.Join(list, ",") }
	cases := []struct {
		name   string
		result *ValidationResult
		want   string
	}{
		{"superadmin role with an empty claim: the claim decides (none)", withClaim(user("1", "superadmin", "/tenants/medai", "user"), ""), ""},
		{"superadmin role with a workspace claim: the claim decides", withClaim(user("1", "superadmin", "/tenants/uni-1", "admin"), "content:generate"), "content:generate"},
		{"accounts superadmin claim", withClaim(user("1", "user", "/tenants/medai", "user"), "*"), "*"},
		{"no claim, role superadmin: legacy *", user("1", "superadmin", "", ""), "*"},
		{"no claim, role list holding superadmin: legacy is exact, none", user("1", "user,superadmin", "", ""), ""},
		{"no claim, role Superadmin: legacy is case-sensitive, none", user("1", "Superadmin", "", ""), ""},
	}
	legacy := withClaim(user("1", "user", "/tenants/uni-1", "user"), "*")
	legacy.LegacyIssuer = true
	cases = append(cases, struct {
		name   string
		result *ValidationResult
		want   string
	}{"legacy IAM issuer: a planted claim is ignored, legacy mapping", legacy, ""})
	legacyAdmin := withClaim(user("1", "user", "/tenants/uni-1", "admin"), "")
	legacyAdmin.LegacyIssuer = true
	cases = append(cases, struct {
		name   string
		result *ValidationResult
		want   string
	}{"legacy IAM issuer: an empty claim is ignored too", legacyAdmin, join(c.roles["admin"])})
	for _, tc := range cases {
		if got := join(c.EffectivePermissions(tc.result)); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// vendoredCatalogueSHA256 pins the embedded catalogue to medai-accounts
// docs/permissions.json. When accounts changes the catalogue, copy the file
// and update this constant (scripts/check-permissions-copies.sh in the medai
// workspace diffs every copy against accounts).
const vendoredCatalogueSHA256 = "b2cd807a120b183f45237f8d003ec6929e4cff0bbe2d88fb2ec058e3a7817a1c"

func TestDefaultCatalogue_ContentHash(t *testing.T) {
	raw, err := os.ReadFile("route_gate_permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != vendoredCatalogueSHA256 {
		t.Fatalf("route_gate_permissions.json changed (sha256 %s, pinned %s): copy medai-accounts docs/permissions.json and update the pin", got, vendoredCatalogueSHA256)
	}
}

func TestPermissionsClaim_ExactMatch(t *testing.T) {
	// accounts' parsePermissionsClaim / hasPermission cases.
	if got := ParsePermissionsClaim(""); len(got) != 0 {
		t.Fatalf("empty claim: %v", got)
	}
	if got := strings.Join(ParsePermissionsClaim("cohort:view, members:view,"), "|"); got != "cohort:view|members:view" {
		t.Fatalf("parse: %q", got)
	}
	has := func(claim, name string) bool { return PermissionsInclude(ParsePermissionsClaim(claim), name) }
	cases := []struct {
		claim, name string
		want        bool
	}{
		{"*", "platform:users", true},
		{"*", "anything", true},
		{"catalog:edit-global", "catalog:edit", false},
		{"catalog:edit", "catalog:edit-global", false},
		{"members:view", "members", false},
		{"members:view", "view", false},
		{"cohort:view,members:view", "members:view", true},
		{"cohort:view,members:view", "cohort:view,members:view", false},
		{"", "", false},
		{"", "members:view", false},
		{"x*", "members:view", false},
	}
	for _, tc := range cases {
		if got := has(tc.claim, tc.name); got != tc.want {
			t.Errorf("hasPermission(%q, %q) = %t, want %t", tc.claim, tc.name, got, tc.want)
		}
	}
}

func TestPermissionCatalogue_FailsClosed(t *testing.T) {
	var doc map[string]interface{}
	if err := json.Unmarshal(defaultCatalogueJSON, &doc); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(map[string]interface{})) []byte {
		var copied map[string]interface{}
		_ = json.Unmarshal(defaultCatalogueJSON, &copied)
		change(copied)
		raw, _ := json.Marshal(copied)
		return raw
	}
	bad := map[string][]byte{
		"not json":    []byte("{"),
		"version 2":   mutate(func(d map[string]interface{}) { d["version"] = 2 }),
		"other claim": mutate(func(d map[string]interface{}) { d["claim"].(map[string]interface{})["key"] = "permissions" }),
		"unknown in role": mutate(func(d map[string]interface{}) {
			d["roles"].([]interface{})[0].(map[string]interface{})["permissions"] = []string{"nope:nope"}
		}),
		"unknown in staff": mutate(func(d map[string]interface{}) {
			d["staff"] = map[string]interface{}{"permissions": []string{"nope:nope"}}
		}),
		"no legacy": mutate(func(d map[string]interface{}) { delete(d, "legacy") }),
		"bundle to unknown role": mutate(func(d map[string]interface{}) {
			d["legacy"].(map[string]interface{})["tenantRoleBundles"] = map[string]string{"owner": "boss"}
		}),
		"no permissions": mutate(func(d map[string]interface{}) { d["permissions"] = []interface{}{} }),
	}
	for name, raw := range bad {
		if _, err := ParsePermissionCatalogue(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := LoadPermissionCatalogue(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: expected an error")
	}
}

// --- Declarations and boot -------------------------------------------------

func TestRouteDeclarations_BootErrors(t *testing.T) {
	op := func(body string) string {
		return `
openapi: 3.0.3
info: {title: t, version: "1"}
security:
  - OpenIdConnect: []
paths:
  /x:
    get:
` + body + `
      responses: {"200": {description: ok}}
`
	}
	bad := map[string]string{
		"public without security: []":  "      x-access: public",
		"signed-in with security: []":  "      x-access: signed-in\n      security: []",
		"permission with security: []": "      x-permission: content:generate\n      security: []",
		"unknown permission":           "      x-permission: content:everything",
		"empty permission":             "      x-permission: \"\"",
		"both declarations":            "      x-access: signed-in\n      x-permission: content:generate",
		"unknown access":               "      x-access: staff",
		"non-string access":            "      x-access: [public]",
	}
	catalogue := DefaultPermissionCatalogue()
	for name, body := range bad {
		doc := loadDoc(t, op(body))
		if _, err := ValidateRouteDeclarations(doc, catalogue); err == nil {
			t.Errorf("%s: expected a boot error", name)
		}
		for _, mode := range []RouteGateMode{RouteGateShadow, RouteGateOn} {
			if _, err := NewRouteGate(doc, mode, false, catalogue); err == nil {
				t.Errorf("%s (%s): expected a boot error", name, mode)
			}
		}
		// off reads no declaration: today's behaviour.
		if _, err := NewRouteGate(doc, RouteGateOff, false, catalogue); err != nil {
			t.Errorf("%s (off): %s", name, err)
		}
	}
	good := map[string]string{
		"public":     "      x-access: public\n      security: []",
		"signed-in":  "      x-access: signed-in",
		"permission": "      x-permission: content:generate",
		"undeclared": "",
	}
	for name, body := range good {
		if _, err := ValidateRouteDeclarations(loadDoc(t, op(body)), catalogue); err != nil {
			t.Errorf("%s: %s", name, err)
		}
	}
}

func TestRouteGateFromEnv(t *testing.T) {
	doc := loadDoc(t, gateDoc)
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	file := catalogueFile(t)

	gate, err := NewRouteGateFromEnv(doc, env(nil))
	if err != nil || gate.Mode != RouteGateOff || gate.Catalogue == nil {
		t.Fatalf("default: %v %v", gate, err)
	}
	for _, mode := range []string{"shadow", "on"} {
		if _, err = NewRouteGateFromEnv(doc, env(map[string]string{EnvRouteGate: mode})); err == nil {
			t.Errorf("%s without %s: expected an error", mode, EnvPermissionsFile)
		}
	}
	if _, err = NewRouteGateFromEnv(doc, env(map[string]string{EnvRouteGate: "ON"})); err == nil {
		t.Error("unknown mode: expected an error")
	}
	if _, err = NewRouteGateFromEnv(doc, env(map[string]string{EnvRouteGate: "on", EnvPermissionsFile: file, EnvRouteGateStrict: "yes"})); err == nil {
		t.Error("bad strict value: expected an error")
	}
	gate, err = NewRouteGateFromEnv(doc, env(map[string]string{EnvRouteGate: "on", EnvPermissionsFile: file}))
	if err != nil {
		t.Fatal(err)
	}
	var undeclared []string
	for _, d := range gate.Undeclared {
		undeclared = append(undeclared, d.String())
	}
	if got := strings.Join(undeclared, "; "); got != "GET /legacy (legacyUndeclared); GET /open-undeclared (openUndeclared)" {
		t.Fatalf("undeclared: %q", got)
	}
	// strict refuses boot in on, not in shadow.
	if _, err = NewRouteGateFromEnv(doc, env(map[string]string{EnvRouteGate: "on", EnvPermissionsFile: file, EnvRouteGateStrict: "true"})); err == nil || !strings.Contains(err.Error(), "GET /legacy") {
		t.Fatalf("strict on: expected a boot error naming the operation, got %v", err)
	}
	if _, err = NewRouteGateFromEnv(doc, env(map[string]string{EnvRouteGate: "shadow", EnvPermissionsFile: file, EnvRouteGateStrict: "true"})); err != nil {
		t.Fatalf("strict shadow: %s", err)
	}

	// RouteInitializer reads the same variables and refuses to boot.
	t.Setenv(EnvRouteGate, "on")
	t.Setenv(EnvPermissionsFile, file)
	t.Setenv(EnvRouteGateStrict, "true")
	if _, err = newGateServer(t, loadDoc(t, withControllers(gateDoc)), nil); err == nil {
		t.Fatal("RouteInitializer with strict and undeclared operations: expected an error")
	}
	t.Setenv(EnvRouteGateStrict, "false")
	server, err := newGateServer(t, loadDoc(t, withControllers(gateDoc)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if lines := server.boot.matching("route_gate.undeclared"); len(lines) != 2 {
		t.Fatalf("boot listing: %v", lines)
	}
}

// --- The matrix ------------------------------------------------------------

func TestRouteGate_Matrix(t *testing.T) {
	doc := loadDoc(t, withControllers(gateDoc))
	type row struct {
		method, path, token string
		off, on             int // shadow answers as off
	}
	rows := []row{
		{"GET", "/public", "", 200, 200},
		{"GET", "/public", "learner", 200, 200},
		{"GET", "/me", "", 401, 401},
		{"GET", "/me", "nobody", 401, 401},
		{"GET", "/me", "learner", 200, 200},
		{"GET", "/me", "iam-staff", 200, 200},
		{"GET", "/me", "superadmin", 403, 200}, // casbin: superadmin was never in x-auth
		{"GET", "/me", "machine", 200, 403},    // not a user token
		{"POST", "/generate", "learner", 403, 403},
		{"POST", "/generate", "accounts-admin", 403, 200}, // university admin: casbin only knew Administrator
		{"POST", "/generate", "accounts-empty", 403, 403}, // "" is none, never the fallback
		{"POST", "/generate", "iam-admin", 403, 200},      // IAM token: legacy admin bundle
		{"POST", "/generate", "iam-staff", 200, 200},
		{"POST", "/generate", "iam-admin-uni-user", 200, 403}, // Administrator in a university as user: not staff
		{"POST", "/generate", "superadmin", 403, 200},
		{"PUT", "/global/42", "iam-staff", 200, 200},
		{"PUT", "/global/42", "accounts-admin", 403, 403},
		{"PUT", "/global/42", "superadmin", 403, 200},
		{"PUT", "/global/42", "superadmin-role-empty-claim", 403, 403}, // the claim decides
		{"POST", "/generate", "superadmin-role-empty-claim", 403, 403},
		{"PUT", "/global/42", "iam-superadmin", 403, 200}, // legacy: exact superadmin role
		{"GET", "/legacy", "learner", 200, 403},           // undeclared: 403 with a token
		{"GET", "/legacy", "", 401, 401},                  // and 401 without
		{"GET", "/open-undeclared", "", 200, 401},
		{"GET", "/open-undeclared", "learner", 200, 403},
	}
	for _, mode := range []RouteGateMode{RouteGateOff, RouteGateShadow, RouteGateOn} {
		t.Run(string(mode), func(t *testing.T) {
			var gate *RouteGate
			if mode != RouteGateOff {
				gate = gateFor(t, doc, mode, false)
			}
			server, err := newGateServer(t, doc, gate)
			if err != nil {
				t.Fatal(err)
			}
			disagreements := 0
			for _, r := range rows {
				want := r.off
				if mode == RouteGateOn {
					want = r.on
				}
				before := strings.Count(server.reqLog.String(), "route_gate.disagree")
				if got := server.do(r.method, r.path, r.token); got != want {
					t.Errorf("%s %s as %q: got %d want %d", r.method, r.path, r.token, got, want)
				}
				logged := strings.Count(server.reqLog.String(), "route_gate.disagree") - before
				differ := (r.off == 200) != (r.on == 200)
				if mode == RouteGateShadow {
					if differ && logged != 1 || !differ && logged != 0 {
						t.Errorf("shadow %s %s as %q: %d disagree lines, differ=%t", r.method, r.path, r.token, logged, differ)
					}
					if differ {
						disagreements++
					}
				} else if logged != 0 {
					t.Errorf("%s: unexpected disagree log", mode)
				}
			}
			switch mode {
			case RouteGateOn:
				if n := server.counter.count(); n != 0 {
					t.Fatalf("on: casbin Enforce called %d times", n)
				}
				if policies := server.enforcer.GetPolicy(); len(policies) != 0 {
					t.Fatalf("on: casbin policies were added: %v", policies)
				}
			default:
				if server.counter.count() == 0 {
					t.Fatalf("%s: casbin Enforce was never called", mode)
				}
				if policies := server.enforcer.GetPolicy(); len(policies) == 0 {
					t.Fatalf("%s: casbin policies missing", mode)
				}
			}
			if mode == RouteGateShadow {
				if disagreements == 0 {
					t.Fatal("matrix has no disagreement to log")
				}
				line := ""
				for _, l := range strings.Split(server.reqLog.String(), "\n") {
					if strings.Contains(l, "route_gate.disagree") && strings.Contains(l, "/generate") && strings.Contains(l, `role="user"`) {
						line = l
						break
					}
				}
				for _, part := range []string{"method=POST", "path=/generate", "casbin=deny", "gate=allow", "content:generate"} {
					if !strings.Contains(line, part) {
						t.Fatalf("disagree line %q lacks %q\n%s", line, part, server.reqLog.String())
					}
				}
			}
		})
	}
}

// The off rows are what casbin alone gives: the same server without any gate
// code path (no RouteGate, nothing in the environment) answers identically.
func TestRouteGate_OffIsToday(t *testing.T) {
	doc := loadDoc(t, withControllers(gateDoc))
	explicit, err := newGateServer(t, doc, gateFor(t, doc, RouteGateOff, false))
	if err != nil {
		t.Fatal(err)
	}
	fromEnv, err := newGateServer(t, doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lines := fromEnv.boot.lines; len(lines) != 0 {
		t.Fatalf("off logs nothing at boot, got %v", lines)
	}
	tokens := []string{"", "nobody"}
	for name := range gateUsers {
		tokens = append(tokens, name)
	}
	sort.Strings(tokens)
	for _, route := range [][2]string{{"GET", "/public"}, {"GET", "/me"}, {"POST", "/generate"}, {"PUT", "/global/1"}, {"GET", "/legacy"}, {"GET", "/open-undeclared"}} {
		for _, token := range tokens {
			a, b := explicit.do(route[0], route[1], token), fromEnv.do(route[0], route[1], token)
			if a != b {
				t.Errorf("%s %s as %q: %d vs %d", route[0], route[1], token, a, b)
			}
		}
	}
}

// With the gate on and no document-level security, every operation is still gated.
func TestRouteGate_OnWithoutGlobalSecurity(t *testing.T) {
	doc := loadDoc(t, withControllers(strings.Replace(gateDoc, "security:\n  - OpenIdConnect: []\npaths:", "paths:", 1)))
	server, err := newGateServer(t, doc, gateFor(t, doc, RouteGateOn, false))
	if err != nil {
		t.Fatal(err)
	}
	if got := server.do("GET", "/legacy", "learner"); got != http.StatusUnauthorized {
		t.Fatalf("undeclared with no schemes: %d", got)
	}
	if got := server.do("GET", "/public", ""); got != http.StatusOK {
		t.Fatalf("public: %d", got)
	}
	if got := server.do("POST", "/generate", "iam-staff"); got != http.StatusUnauthorized {
		t.Fatalf("permission route without any scheme must fail closed: %d", got)
	}
}

// --- Real tokens through the real validator --------------------------------

func TestRouteGate_RealTokens(t *testing.T) {
	g := loadGolden(t)
	accountsKey := newKey(t, "accounts-gate-key")
	accounts := newJWKSServer(t, jwksOf(t, accountsKey))
	golden := newJWKSServer(t, g.jwks)
	iam := newKey(t, "iam-test-key")
	c := &clock{t: g.time()}

	clearIssuerEnv(t)
	t.Setenv(EnvJWTIssuer, g.Issuer)
	t.Setenv(EnvJWTJWKSURL, golden.URL+"/oauth2/certs")
	t.Setenv(EnvJWTAudience, g.Audience)
	t.Setenv(EnvLegacyIAMJWK, iam.jwkJSON(t))
	t.Setenv(EnvLegacyIAMIssuer, iamIssuer)
	t.Setenv(EnvLegacyIAMAudience, g.Audience)
	goldenValidator := newValidator(t, "http://unused.invalid", c.now)
	t.Setenv(EnvJWTJWKSURL, accounts.URL+"/oauth2/certs")
	validator := newValidator(t, "http://unused.invalid", c.now)

	doc := loadDoc(t, withControllers(gateDoc))
	gate := gateFor(t, doc, RouteGateOn, false)
	build := func(v Validator) *echo.Echo {
		enforcer, _ := newCountingEnforcer(t)
		e := echo.New()
		e.Logger.SetOutput(&bytes.Buffer{})
		if err := RouteInitializer(RouteParams{
			Config: doc, APIConfig: testAPIConfig(), Echo: e, Logger: &captureLog{},
			Controllers:           []map[string]Controller{{"ok": okController}},
			AuthorizationEnforcer: enforcer,
			SecuritySchemes:       map[string]Validator{"OpenIdConnect": v},
			RouteGate:             gate,
		}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	call := func(e *echo.Echo, method, path, token string) int {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}

	// The real golden accounts token (made before the claim existed): a MedAI
	// learner, so signed-in passes and a permission is refused.
	ge := build(goldenValidator)
	if got := call(ge, "GET", "/me", g.token); got != 200 {
		t.Fatalf("golden /me: %d", got)
	}
	if got := call(ge, "POST", "/generate", g.token); got != 403 {
		t.Fatalf("golden /generate: %d", got)
	}

	e := build(validator)
	university := func(claims jwt.MapClaims, tenantRole string) jwt.MapClaims {
		claims["https://iam.weos.io/v1/tenant"] = "/tenants/uni-1"
		claims["https://iam.weos.io/v1/tenant_role"] = tenantRole
		return claims
	}
	// The golden token's claims, signed by accounts with the claim set.
	withPermissions := func(claim interface{}) string {
		claims := university(claimsFor(g.Issuer, g.Audience, g.UserID, g.AccountID, c.now()), "admin")
		claims[PermissionsClaim] = claim
		return accountsKey.sign(t, claims)
	}
	if got := call(e, "POST", "/generate", withPermissions("catalog:edit,content:generate,content:review")); got != 200 {
		t.Fatalf("accounts token with the claim: %d", got)
	}
	if got := call(e, "POST", "/generate", withPermissions("")); got != 403 {
		t.Fatalf(`accounts token with v1/permissions="" must be denied, not fall back: %d`, got)
	}
	if got := call(e, "POST", "/generate", withPermissions("content:generate-all")); got != 403 {
		t.Fatalf("substring must not match: %d", got)
	}
	if got := call(e, "POST", "/generate", withPermissions([]string{"content:generate"})); got != 403 {
		t.Fatalf("non-string claim is none: %d", got)
	}
	if got := call(e, "GET", "/me", withPermissions("")); got != 200 {
		t.Fatalf("signed-in with an empty claim: %d", got)
	}
	// An IAM token (no claim) for a university admin: the legacy admin bundle.
	iamAdmin := iam.sign(t, university(claimsFor(iamIssuer, g.Audience, g.UserID, g.AccountID, c.now()), "admin"))
	if got := call(e, "POST", "/generate", iamAdmin); got != 200 {
		t.Fatalf("IAM admin token (fallback): %d", got)
	}
	if got := call(e, "PUT", "/global/1", iamAdmin); got != 403 {
		t.Fatalf("IAM admin token on a staff route: %d", got)
	}
	// An IAM token carrying a planted v1/permissions claim: the legacy IAM
	// issuer verified it, so the claim is ignored and the legacy mapping decides.
	planted := university(claimsFor(iamIssuer, g.Audience, g.UserID, g.AccountID, c.now()), "user")
	planted[PermissionsClaim] = "*"
	if got := call(e, "POST", "/generate", iam.sign(t, planted)); got != 403 {
		t.Fatalf("IAM token with a planted * claim must get the legacy mapping (none): %d", got)
	}
	plantedAdmin := university(claimsFor(iamIssuer, g.Audience, g.UserID, g.AccountID, c.now()), "admin")
	plantedAdmin[PermissionsClaim] = ""
	if got := call(e, "POST", "/generate", iam.sign(t, plantedAdmin)); got != 200 {
		t.Fatalf("IAM admin token with a planted empty claim keeps the legacy admin bundle: %d", got)
	}
	// An accounts token whose v1/roles is superadmin but whose claim is "":
	// the claim decides.
	superNone := claimsFor(g.Issuer, g.Audience, g.UserID, g.AccountID, c.now())
	superNone["https://iam.weos.io/v1/roles"] = "superadmin"
	superNone[PermissionsClaim] = ""
	if got := call(e, "PUT", "/global/1", accountsKey.sign(t, superNone)); got != 403 {
		t.Fatalf("accounts token: v1/roles superadmin with v1/permissions=\"\" is not superadmin: %d", got)
	}
	// An IAM superadmin token passes everything declared.
	superClaims := claimsFor(iamIssuer, g.Audience, g.UserID, g.AccountID, c.now())
	superClaims["https://iam.weos.io/v1/roles"] = "superadmin"
	if got := call(e, "PUT", "/global/1", iam.sign(t, superClaims)); got != 200 {
		t.Fatalf("IAM superadmin: %d", got)
	}
}

// --- mapClaims and handler helpers -----------------------------------------

func TestMapClaims_RouteGateClaims(t *testing.T) {
	doc := loadDoc(t, fmt.Sprintf(learningSchemeYAML, "http://unused.invalid"))
	clearIssuerEnv(t)
	o := &OpenIDConnect{}
	if _, err := o.FromSchema(context.Background(), doc.Components.SecuritySchemes["OpenIdConnect"].Value, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	mapJSON := func(claims map[string]interface{}) mappedClaims {
		raw, _ := json.Marshal(claims)
		return o.mapClaims(claims["sub"].(string), func(v interface{}) error { return json.Unmarshal(raw, v) })
	}
	// No tenant, tenant_role, permissions or v1/user at all: no panic, absent.
	m := mapJSON(map[string]interface{}{"sub": "/users/1", "https://iam.weos.io/v1/roles": "user"})
	if m.claimsErr != nil || m.Tenant != "" || m.TenantRole != "" || m.PermissionsClaimPresent || m.Permissions != "" || m.IsUserToken() {
		t.Fatalf("missing keys: %+v", m)
	}
	// Wrong types: no panic; a present permissions key of another type is none.
	m = mapJSON(map[string]interface{}{
		"sub": "/users/1", "https://iam.weos.io/v1/user": "/users/1",
		"https://iam.weos.io/v1/tenant": 7, "https://iam.weos.io/v1/tenant_role": []string{"admin"},
		PermissionsClaim: map[string]string{"a": "b"},
	})
	if m.Tenant != "" || m.TenantRole != "" || !m.PermissionsClaimPresent || m.Permissions != "" || !m.IsUserToken() {
		t.Fatalf("wrong types: %+v", m)
	}
	m = mapJSON(map[string]interface{}{"sub": "/users/1", PermissionsClaim: nil})
	if !m.PermissionsClaimPresent {
		t.Fatal("a null claim is present (none), not absent")
	}
	m = mapJSON(map[string]interface{}{
		"sub": "/users/1", "https://iam.weos.io/v1/user": "/users/1",
		"https://iam.weos.io/v1/tenant": "/tenants/uni-1", "https://iam.weos.io/v1/tenant_role": "owner",
		PermissionsClaim: "content:generate",
	})
	if m.Tenant != "/tenants/uni-1" || m.TenantRole != "owner" || m.Permissions != "content:generate" || !m.PermissionsClaimPresent {
		t.Fatalf("mapped: %+v", m)
	}

	// x-jwt-map user = v1/user: the sub pre-fill of the user claim must not
	// make a token without v1/user a user token.
	byUser := &OpenIDConnect{userIDClaim: iamUserClaim, roleClaim: "https://iam.weos.io/v1/roles"}
	raw, _ := json.Marshal(map[string]interface{}{"sub": "/users/1", "https://iam.weos.io/v1/roles": "superadmin"})
	m = byUser.mapClaims("/users/1", func(v interface{}) error { return json.Unmarshal(raw, v) })
	if m.claimsErr != nil || m.User != "" || m.IsUserToken() || m.UserID != "/users/1" {
		t.Fatalf("a token without v1/user is not a user token: %+v", m)
	}
	raw, _ = json.Marshal(map[string]interface{}{"sub": "/users/1", iamUserClaim: "/users/1"})
	m = byUser.mapClaims("/users/1", func(v interface{}) error { return json.Unmarshal(raw, v) })
	if !m.IsUserToken() {
		t.Fatalf("a token with v1/user equal to sub is a user token: %+v", m)
	}

	// Without tenant/tenant_role in x-jwt-map (tutor's scheme) the defaults apply.
	tutor := &OpenIDConnect{userIDClaim: "sub", roleClaim: "https://iam.weos.io/v1/roles"}
	raw, _ = json.Marshal(map[string]interface{}{"sub": "/users/1", "https://iam.weos.io/v1/tenant": "/tenants/x", "https://iam.weos.io/v1/tenant_role": "admin"})
	m = tutor.mapClaims("/users/1", func(v interface{}) error { return json.Unmarshal(raw, v) })
	if m.Tenant != "/tenants/x" || m.TenantRole != "admin" {
		t.Fatalf("defaults: %+v", m)
	}
}

func TestHasPermission_Context(t *testing.T) {
	if HasPermission(context.Background(), "content:generate") || Permissions(context.Background()) != nil {
		t.Fatal("no user: no permissions")
	}
	ctx := context.WithValue(context.Background(), PERMISSIONS, []string{"catalog:edit", "content:generate"})
	if !HasPermission(ctx, "content:generate") || HasPermission(ctx, "content") || HasPermission(ctx, "catalog:edit-global") || HasPermission(ctx, "") {
		t.Fatal("exact matches only")
	}
	list := Permissions(ctx)
	list[0] = "*"
	if HasPermission(ctx, "platform:users") {
		t.Fatal("Permissions must return a copy")
	}
	if !HasPermission(context.WithValue(context.Background(), PERMISSIONS, []string{"*"}), "platform:users") {
		t.Fatal(`"*" passes everything`)
	}

	// Through the middleware (off): handlers see tenant, tenant role and the
	// effective permissions, the legacy mapping for an IAM token.
	doc := loadDoc(t, withControllers(gateDoc))
	var seen struct {
		tenant, tenantRole string
		perms              []string
		generate           bool
	}
	e := echo.New()
	e.Logger.SetOutput(&bytes.Buffer{})
	enforcer, _ := newCountingEnforcer(t)
	err := RouteInitializer(RouteParams{
		Config: doc, APIConfig: testAPIConfig(), Echo: e, Logger: &captureLog{},
		Controllers: []map[string]Controller{{"ok": func(*ControllerParams) echo.HandlerFunc {
			return func(c echo.Context) error {
				ctx := c.Request().Context()
				seen.tenant, seen.tenantRole, seen.perms = GetTenant(ctx), GetTenantRole(ctx), Permissions(ctx)
				seen.generate = HasPermission(ctx, "content:generate")
				return c.NoContent(http.StatusOK)
			}
		}}},
		AuthorizationEnforcer: enforcer,
		SecuritySchemes:       map[string]Validator{"OpenIdConnect": gateUsers},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer iam-admin")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != 200 || seen.tenant != "/tenants/uni-1" || seen.tenantRole != "admin" || !seen.generate || len(seen.perms) == 0 {
		t.Fatalf("context: %d %+v", rec.Code, seen)
	}
	req = httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer accounts-empty")
	e.ServeHTTP(httptest.NewRecorder(), req)
	if seen.generate || len(seen.perms) != 0 {
		t.Fatalf(`v1/permissions="" gives none: %+v`, seen)
	}
}

// The embedded copy must stay a valid catalogue (it is also what services
// vendor from medai-accounts docs/permissions.json).
func TestDefaultCatalogue_IsValid(t *testing.T) {
	raw, err := os.ReadFile("route_gate_permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePermissionCatalogue(raw); err != nil {
		t.Fatal(err)
	}
}

// With the gate on, NewSecurityConfiguration does not load casbin policies (it
// never touches the database: a nil GORM handle is fine).
func TestNewSecurityConfiguration_OnLoadsNoPolicies(t *testing.T) {
	doc := loadDoc(t, "openapi: 3.0.3\ninfo: {title: t, version: \"1\"}\npaths: {}\ncomponents: {securitySchemes: {}}\n")
	t.Setenv(EnvRouteGate, "on")
	config, err := NewSecurityConfiguration(SecurityParams{Config: doc, HttpClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	if config.AuthEnforcer == nil || len(config.AuthEnforcer.GetPolicy()) != 0 {
		t.Fatal("expected an empty in-memory enforcer")
	}
	t.Setenv(EnvRouteGate, "sideways")
	if _, err = NewSecurityConfiguration(SecurityParams{Config: doc, HttpClient: http.DefaultClient}); err == nil {
		t.Fatal("unknown mode: expected an error")
	}
}
