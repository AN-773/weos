package rest

// The route gate (medai plan PLAN_iam-workspaces-permissions.md, D7).
//
// Each OpenAPI operation declares exactly one of
//
//	x-access: public | signed-in
//	x-permission: <name>          (implies signed-in)
//
// and `x-access: public` must go with `security: []` (and only it). The
// permission names come from a vendored copy of the accounts catalogue
// (docs/permissions.json in medai-accounts), named by WEOS_PERMISSIONS_FILE.
//
// WEOS_ROUTE_GATE picks the mode:
//
//	off     (default) the casbin x-auth rules decide, exactly as before;
//	shadow  casbin decides, the gate logs `route_gate.disagree` when it would answer differently;
//	on      the gate decides; casbin Enforce is never called and no x-auth policy is added.
//
// In `on`, an operation without a declaration answers 403 to a valid token and
// 401 without one, and is listed at boot as `route_gate.undeclared`;
// WEOS_ROUTE_GATE_STRICT=true refuses to boot instead.

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"golang.org/x/net/context"
)

const (
	// AccessExtension declares who may call an operation: public | signed-in.
	AccessExtension = "x-access"
	// PermissionExtension declares the permission an operation needs (signed-in implied).
	PermissionExtension = "x-permission"

	// AccessPublic needs no token; the operation must also declare `security: []`.
	AccessPublic = "public"
	// AccessSignedIn needs a valid user token and nothing else.
	AccessSignedIn = "signed-in"

	EnvRouteGate       = "WEOS_ROUTE_GATE"
	EnvRouteGateStrict = "WEOS_ROUTE_GATE_STRICT"
	EnvPermissionsFile = "WEOS_PERMISSIONS_FILE"

	// PermissionsClaim is the accounts claim: permission names, sorted, comma-joined; "" none; "*" all.
	PermissionsClaim = "https://iam.weos.io/v1/permissions"
	// TenantClaim and TenantRoleClaim are read when x-jwt-map does not name them.
	TenantClaim     = "https://iam.weos.io/v1/tenant"
	TenantRoleClaim = "https://iam.weos.io/v1/tenant_role"
	// AllPermissions is the claim value (and list entry) that passes every permission.
	AllPermissions = "*"
)

// RouteGateMode is the value of WEOS_ROUTE_GATE.
type RouteGateMode string

const (
	RouteGateOff    RouteGateMode = "off"
	RouteGateShadow RouteGateMode = "shadow"
	RouteGateOn     RouteGateMode = "on"
)

// ParseRouteGateMode reads WEOS_ROUTE_GATE: "" means off; anything but off, shadow or on is an error.
func ParseRouteGateMode(value string) (RouteGateMode, error) {
	switch mode := RouteGateMode(strings.TrimSpace(value)); mode {
	case "", RouteGateOff:
		return RouteGateOff, nil
	case RouteGateShadow, RouteGateOn:
		return mode, nil
	default:
		return RouteGateOff, fmt.Errorf("%s must be off, shadow or on, not %q", EnvRouteGate, value)
	}
}

// --- The catalogue ---------------------------------------------------------

//go:embed route_gate_permissions.json
var defaultCatalogueJSON []byte

// PermissionCatalogue is the parsed docs/permissions.json (version 1).
type PermissionCatalogue struct {
	names          map[string]bool
	roles          map[string][]string
	staff          []string
	superadminRole string
	staffRole      string
	medaiTenants   []string
	tenantBundles  map[string]string
}

type catalogueDocument struct {
	Version int `json:"version"`
	Claim   struct {
		Key string `json:"key"`
		All string `json:"all"`
	} `json:"claim"`
	Permissions []struct {
		Name string `json:"name"`
	} `json:"permissions"`
	Roles []struct {
		Key         string   `json:"key"`
		Permissions []string `json:"permissions"`
	} `json:"roles"`
	Staff struct {
		Permissions []string `json:"permissions"`
	} `json:"staff"`
	Legacy struct {
		SuperadminRole    *string           `json:"superadminRole"`
		StaffRole         *string           `json:"staffRole"`
		MedaiTenants      []string          `json:"medaiTenants"`
		TenantRoleBundles map[string]string `json:"tenantRoleBundles"`
	} `json:"legacy"`
}

var permissionNamePattern = regexp.MustCompile(`^[a-z0-9-]+:[a-z0-9-]+$`)

// ParsePermissionCatalogue parses and checks a catalogue document. It fails
// closed: an unknown version, claim key or shape, an unknown permission in a
// bundle, or a missing legacy field is an error.
func ParsePermissionCatalogue(raw []byte) (*PermissionCatalogue, error) {
	var doc catalogueDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("permission catalogue: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("permission catalogue: version %d is not supported (want 1)", doc.Version)
	}
	if doc.Claim.Key != PermissionsClaim || doc.Claim.All != AllPermissions {
		return nil, fmt.Errorf("permission catalogue: claim is %q/%q, want %q/%q", doc.Claim.Key, doc.Claim.All, PermissionsClaim, AllPermissions)
	}
	c := &PermissionCatalogue{names: map[string]bool{}, roles: map[string][]string{}}
	for _, p := range doc.Permissions {
		if !permissionNamePattern.MatchString(p.Name) {
			return nil, fmt.Errorf("permission catalogue: bad permission name %q", p.Name)
		}
		if c.names[p.Name] {
			return nil, fmt.Errorf("permission catalogue: permission %q listed twice", p.Name)
		}
		c.names[p.Name] = true
	}
	if len(c.names) == 0 {
		return nil, errors.New("permission catalogue: no permissions")
	}
	known := func(where string, list []string) error {
		for _, name := range list {
			if !c.names[name] {
				return fmt.Errorf("permission catalogue: %s holds unknown permission %q", where, name)
			}
		}
		return nil
	}
	for _, role := range doc.Roles {
		if role.Key == "" {
			return nil, errors.New("permission catalogue: role without a key")
		}
		if err := known("role "+role.Key, role.Permissions); err != nil {
			return nil, err
		}
		c.roles[role.Key] = sortedCopy(role.Permissions)
	}
	if err := known("staff", doc.Staff.Permissions); err != nil {
		return nil, err
	}
	c.staff = sortedCopy(doc.Staff.Permissions)
	l := doc.Legacy
	if l.SuperadminRole == nil || *l.SuperadminRole == "" || l.StaffRole == nil || *l.StaffRole == "" || l.MedaiTenants == nil || l.TenantRoleBundles == nil {
		return nil, errors.New("permission catalogue: legacy needs superadminRole, staffRole, medaiTenants and tenantRoleBundles")
	}
	for tenantRole, roleKey := range l.TenantRoleBundles {
		if _, ok := c.roles[roleKey]; !ok {
			return nil, fmt.Errorf("permission catalogue: legacy tenant role %q names unknown role %q", tenantRole, roleKey)
		}
	}
	c.superadminRole = *l.SuperadminRole
	c.staffRole = *l.StaffRole
	c.medaiTenants = append([]string(nil), l.MedaiTenants...)
	c.tenantBundles = l.TenantRoleBundles
	return c, nil
}

// LoadPermissionCatalogue reads a vendored docs/permissions.json.
func LoadPermissionCatalogue(path string) (*PermissionCatalogue, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvPermissionsFile, err)
	}
	return ParsePermissionCatalogue(raw)
}

// DefaultPermissionCatalogue is the copy built into this fork. It serves only
// rest.Permissions/HasPermission in `off` when WEOS_PERMISSIONS_FILE is unset;
// shadow and on always read the service's vendored file.
func DefaultPermissionCatalogue() *PermissionCatalogue {
	c, err := ParsePermissionCatalogue(defaultCatalogueJSON)
	if err != nil {
		panic(err)
	}
	return c
}

// Known reports whether name is in the catalogue.
func (c *PermissionCatalogue) Known(name string) bool { return c.names[name] }

// LegacyPermissions is accounts' legacyPermissions for a token without the
// claim (IAM tokens, older tokens): superadmin (v1/roles exactly the
// superadmin role) → ["*"]; in the MedAI workspace (see IsMedaiTenant) the
// staff bundle for staffRole, else none; elsewhere the bundle of
// tenantRoleBundles[tenantRole], else none. Role and tenant-role matches are
// exact and case-sensitive.
func (c *PermissionCatalogue) LegacyPermissions(roles, tenant, tenantRole string) []string {
	if roles == c.superadminRole {
		return []string{AllPermissions}
	}
	if c.IsMedaiTenant(tenant) {
		if roles == c.staffRole {
			return append([]string{}, c.staff...)
		}
		return []string{}
	}
	if key, ok := c.tenantBundles[tenantRole]; ok {
		return append([]string{}, c.roles[key]...)
	}
	return []string{}
}

// IsMedaiTenant reports whether a v1/tenant value names the MedAI workspace
// for the legacy mapping. The value is first normalised exactly as the
// services' tenant code does (learning's tenantctx.NormalizeID): a URL keeps
// only its path, BASE_PATH and a leading /v1 are stripped. So IAM's "", the
// catalogue's medaiTenants ("", "/tenants/medai", "medai") and their URL,
// BASE_PATH and /v1 forms ("https://iam.example/tenants/medai",
// "/v1/tenants/medai") are MedAI.
//
// A non-empty value that normalises to nothing (junk, or a bare id other than
// "medai") is not MedAI: it fails closed to the tenant-role bundles, never to
// the staff bundle.
func (c *PermissionCatalogue) IsMedaiTenant(tenant string) bool {
	trimmed := strings.TrimSpace(tenant)
	normalized := NormalizeTenantID(trimmed)
	for _, medai := range c.medaiTenants {
		if trimmed == medai || (normalized != "" && normalized == medai) {
			return true
		}
	}
	return false
}

// NormalizeTenantID is learning's tenantctx.NormalizeID: the tenant path of a
// v1/tenant value ("/tenants/<id>"), or "" when it has none. A URL keeps only
// its path; BASE_PATH (the service's env) and a leading "/v1" are stripped; a
// value without a "/" is "" (a bare id is not a path); a path of fewer than
// two segments is "".
func NormalizeTenantID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		raw = parsed.EscapedPath()
		if raw == "" {
			raw = parsed.Path
		}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if basePath := strings.TrimSpace(os.Getenv("BASE_PATH")); basePath != "" && basePath != "/" {
		if raw == basePath {
			raw = "/"
		} else if strings.HasPrefix(raw, basePath+"/") {
			raw = strings.TrimPrefix(raw, basePath)
		}
	}
	if !strings.HasPrefix(raw, "/") {
		if !strings.Contains(raw, "/") {
			return ""
		}
		raw = "/" + raw
	}
	if strings.HasPrefix(raw, "/v1/") {
		raw = strings.TrimPrefix(raw, "/v1")
	}
	if parts := strings.Split(strings.Trim(raw, "/"), "/"); len(parts) < 2 {
		return ""
	}
	return raw
}

// EffectivePermissions is what a verified token may do:
//   - a token the old IAM issuer verified (LegacyIssuer) gets the legacy
//     mapping, whatever v1/permissions it carries (IAM never mints the claim);
//   - otherwise, when the v1/permissions key is present, the claim alone
//     decides ("" is none, never the fallback; accounts writes "*" for a
//     superadmin, so v1/roles is not read);
//   - only when the key is absent, the legacy mapping (where superadmin is
//     v1/roles exactly the superadmin role).
func (c *PermissionCatalogue) EffectivePermissions(r *ValidationResult) []string {
	if r == nil {
		return []string{}
	}
	if r.PermissionsClaimPresent && !r.LegacyIssuer {
		return ParsePermissionsClaim(r.Permissions)
	}
	return c.LegacyPermissions(r.Role, r.Tenant, r.TenantRole)
}

// ParsePermissionsClaim splits the claim: "" → []; "*" → ["*"]; names are
// trimmed and empty entries dropped (accounts' parsePermissionsClaim).
func ParsePermissionsClaim(claim string) []string {
	return splitClaimList(claim)
}

// PermissionsInclude is accounts' hasPermission over a list: "*" passes
// everything; otherwise an exact name match, never a substring.
func PermissionsInclude(list []string, name string) bool {
	if listContains(list, AllPermissions) {
		return true
	}
	return name != "" && listContains(list, name)
}

func splitClaimList(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func listContains(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

func sortedCopy(list []string) []string {
	out := append([]string{}, list...)
	sort.Strings(out)
	return out
}

// --- Declarations ----------------------------------------------------------

// RouteRule is one operation's declaration.
type RouteRule struct {
	// Declared is false when the operation has neither x-access nor x-permission.
	Declared bool
	// Access is AccessPublic or AccessSignedIn (x-permission implies signed-in).
	Access string
	// Permission is the x-permission name, or "".
	Permission string
}

// RouteDeclaration names one operation, for boot listings.
type RouteDeclaration struct {
	Method      string
	Path        string
	OperationID string
}

func (d RouteDeclaration) String() string {
	if d.OperationID != "" {
		return fmt.Sprintf("%s %s (%s)", d.Method, d.Path, d.OperationID)
	}
	return d.Method + " " + d.Path
}

func routeKey(method, path string) string { return method + " " + path }

func extensionString(ext map[string]interface{}, name string) (value string, present bool, err error) {
	raw, ok := ext[name]
	if !ok {
		return "", false, nil
	}
	switch v := raw.(type) {
	case string:
		return v, true, nil
	case json.RawMessage:
		if err = json.Unmarshal(v, &value); err != nil {
			return "", true, fmt.Errorf("%s must be a string", name)
		}
		return value, true, nil
	default:
		return "", true, fmt.Errorf("%s must be a string", name)
	}
}

// operationRule reads and checks one operation's declaration.
func operationRule(operation *openapi3.Operation, catalogue *PermissionCatalogue) (RouteRule, error) {
	access, hasAccess, err := extensionString(operation.Extensions, AccessExtension)
	if err != nil {
		return RouteRule{}, err
	}
	permission, hasPermission, err := extensionString(operation.Extensions, PermissionExtension)
	if err != nil {
		return RouteRule{}, err
	}
	explicitlyOpen := operation.Security != nil && len(*operation.Security) == 0
	switch {
	case hasAccess && hasPermission:
		return RouteRule{}, fmt.Errorf("declares both %s and %s (use exactly one)", AccessExtension, PermissionExtension)
	case hasPermission:
		if permission == "" {
			return RouteRule{}, fmt.Errorf("%s is empty", PermissionExtension)
		}
		if !catalogue.Known(permission) {
			return RouteRule{}, fmt.Errorf("%s %q is not in the permission catalogue", PermissionExtension, permission)
		}
		if explicitlyOpen {
			return RouteRule{}, fmt.Errorf("%s needs a signed-in user but the operation declares security: []", PermissionExtension)
		}
		return RouteRule{Declared: true, Access: AccessSignedIn, Permission: permission}, nil
	case hasAccess:
		switch access {
		case AccessPublic:
			if !explicitlyOpen {
				return RouteRule{}, fmt.Errorf("%s: public needs security: []", AccessExtension)
			}
		case AccessSignedIn:
			if explicitlyOpen {
				return RouteRule{}, fmt.Errorf("%s: signed-in cannot declare security: []", AccessExtension)
			}
		default:
			return RouteRule{}, fmt.Errorf("%s must be public or signed-in, not %q", AccessExtension, access)
		}
		return RouteRule{Declared: true, Access: access}, nil
	default:
		return RouteRule{}, nil
	}
}

// ValidateRouteDeclarations checks every operation's declaration against the
// catalogue and returns the undeclared operations (sorted). A service can call
// it from a unit test to catch a bad declaration before deploying.
func ValidateRouteDeclarations(doc *openapi3.T, catalogue *PermissionCatalogue) (undeclared []RouteDeclaration, err error) {
	_, undeclared, err = routeRules(doc, catalogue)
	return undeclared, err
}

func routeRules(doc *openapi3.T, catalogue *PermissionCatalogue) (map[string]RouteRule, []RouteDeclaration, error) {
	rules := map[string]RouteRule{}
	var undeclared []RouteDeclaration
	var problems []string
	if doc != nil && doc.Paths != nil {
		for path, item := range doc.Paths.Map() {
			for method, operation := range item.Operations() {
				rule, err := operationRule(operation, catalogue)
				where := RouteDeclaration{Method: method, Path: path, OperationID: operation.OperationID}
				if err != nil {
					problems = append(problems, where.String()+": "+err.Error())
					continue
				}
				rules[routeKey(method, path)] = rule
				if !rule.Declared {
					undeclared = append(undeclared, where)
				}
			}
		}
	}
	sort.Slice(undeclared, func(i, j int) bool {
		if undeclared[i].Path != undeclared[j].Path {
			return undeclared[i].Path < undeclared[j].Path
		}
		return undeclared[i].Method < undeclared[j].Method
	})
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, nil, fmt.Errorf("route gate: %s", strings.Join(problems, "; "))
	}
	return rules, undeclared, nil
}

// --- The gate --------------------------------------------------------------

// RouteGate holds the mode, the catalogue and every operation's rule.
type RouteGate struct {
	Mode       RouteGateMode
	Strict     bool
	Catalogue  *PermissionCatalogue
	Undeclared []RouteDeclaration
	rules      map[string]RouteRule
	// onDisagree, when set (tests), also receives each route_gate.disagree line.
	onDisagree func(line string)
}

// NewRouteGate builds the gate for doc. In off it reads no declaration (today's
// behaviour; the catalogue only serves rest.Permissions). In shadow and on a bad
// declaration is an error, and in on with strict so is any undeclared operation.
func NewRouteGate(doc *openapi3.T, mode RouteGateMode, strict bool, catalogue *PermissionCatalogue) (*RouteGate, error) {
	if catalogue == nil {
		return nil, errors.New("route gate: no permission catalogue")
	}
	gate := &RouteGate{Mode: mode, Strict: strict, Catalogue: catalogue}
	if mode == RouteGateOff {
		return gate, nil
	}
	rules, undeclared, err := routeRules(doc, catalogue)
	if err != nil {
		return nil, err
	}
	gate.rules, gate.Undeclared = rules, undeclared
	if mode == RouteGateOn && strict && len(undeclared) > 0 {
		names := make([]string, len(undeclared))
		for i, d := range undeclared {
			names[i] = d.String()
		}
		return nil, fmt.Errorf("route gate: %s=true and %d operation(s) are undeclared: %s", EnvRouteGateStrict, len(undeclared), strings.Join(names, ", "))
	}
	return gate, nil
}

// NewRouteGateFromEnv reads WEOS_ROUTE_GATE, WEOS_ROUTE_GATE_STRICT and
// WEOS_PERMISSIONS_FILE (required in shadow and on).
func NewRouteGateFromEnv(doc *openapi3.T, getenv func(string) string) (*RouteGate, error) {
	mode, err := ParseRouteGateMode(getenv(EnvRouteGate))
	if err != nil {
		return nil, err
	}
	strict := false
	if raw := strings.TrimSpace(getenv(EnvRouteGateStrict)); raw != "" {
		if strict, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("%s must be true or false, not %q", EnvRouteGateStrict, raw)
		}
	}
	file := strings.TrimSpace(getenv(EnvPermissionsFile))
	var catalogue *PermissionCatalogue
	switch {
	case file != "":
		if catalogue, err = LoadPermissionCatalogue(file); err != nil {
			return nil, err
		}
	case mode != RouteGateOff:
		return nil, fmt.Errorf("%s=%s needs %s (a vendored copy of medai-accounts docs/permissions.json)", EnvRouteGate, mode, EnvPermissionsFile)
	default:
		catalogue = DefaultPermissionCatalogue()
	}
	return NewRouteGate(doc, mode, strict, catalogue)
}

// ruleFor is the rule of one operation (the zero rule, undeclared, when unknown).
func (g *RouteGate) ruleFor(method, path string) RouteRule {
	if g == nil {
		return RouteRule{}
	}
	return g.rules[routeKey(method, path)]
}

// gateMode is the mode of a possibly nil gate (nil is off).
func (g *RouteGate) gateMode() RouteGateMode {
	if g == nil {
		return RouteGateOff
	}
	return g.Mode
}

func (g *RouteGate) catalogue() *PermissionCatalogue {
	if g == nil || g.Catalogue == nil {
		return defaultCatalogue
	}
	return g.Catalogue
}

var defaultCatalogue = DefaultPermissionCatalogue()

// Allows is the gate's answer for a request with a verified token (result
// non-nil and Valid) or without one (result nil). Public passes; undeclared is
// refused; otherwise a user token is needed (sub equals v1/user), superadmin
// passes, signed-in passes, and a permission must be in the token's permissions.
func (g *RouteGate) Allows(rule RouteRule, result *ValidationResult) bool {
	if rule.Declared && rule.Access == AccessPublic {
		return true
	}
	if !rule.Declared || result == nil || !result.Valid || !result.IsUserToken() {
		return false
	}
	permissions := g.catalogue().EffectivePermissions(result)
	if PermissionsInclude(permissions, AllPermissions) {
		return true
	}
	if rule.Permission == "" {
		return true
	}
	return PermissionsInclude(permissions, rule.Permission)
}

// --- Handler helpers -------------------------------------------------------

// Permissions is the signed-in user's effective permissions (the claim, or the
// legacy mapping for a token without it; ["*"] for superadmin), or nil when the
// request has no verified user.
func Permissions(ctx context.Context) []string {
	if list, ok := ctx.Value(PERMISSIONS).([]string); ok {
		return append([]string{}, list...)
	}
	return nil
}

// HasPermission reports whether the signed-in user holds name ("*" passes
// everything; exact matches only).
func HasPermission(ctx context.Context, name string) bool {
	list, ok := ctx.Value(PERMISSIONS).([]string)
	return ok && PermissionsInclude(list, name)
}

// GetTenant is the token's v1/tenant (the active workspace), or "".
func GetTenant(ctx context.Context) string {
	value, _ := ctx.Value(TENANT).(string)
	return value
}

// GetTenantRole is the token's v1/tenant_role, or "".
func GetTenantRole(ctx context.Context) string {
	value, _ := ctx.Value(TENANT_ROLE).(string)
	return value
}
