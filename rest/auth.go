package rest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"net/http"
	"os"
	"strings"
	"time"
)

// ValidationResult is the result of a security validation
type ValidationResult struct {
	Valid          bool
	Token          interface{}
	UserID         string
	Role           string
	AccountID      string
	ApplicationID  string
	SubscriptionID string
	// Subject is the token's sub and User its https://iam.weos.io/v1/user; a
	// user token has both, equal (see IsUserToken).
	Subject string
	User    string
	// Tenant and TenantRole are v1/tenant and v1/tenant_role ("" when absent).
	Tenant     string
	TenantRole string
	// Permissions is the v1/permissions claim. PermissionsClaimPresent is false
	// only when the key is absent (IAM and older tokens get the legacy mapping);
	// a present "" (or a non-string) means no permissions.
	Permissions             string
	PermissionsClaimPresent bool
}

// IsUserToken reports whether the token names a user: sub is non-empty and
// equals https://iam.weos.io/v1/user.
func (r *ValidationResult) IsUserToken() bool {
	return r != nil && r.Subject != "" && r.Subject == r.User
}

//security interfaces

type Validator interface {
	Validate(ctxt echo.Context) (*ValidationResult, error)
	FromSchema(ctx context.Context, scheme *openapi3.SecurityScheme, httpClient *http.Client) (Validator, error)
}

type SecurityParams struct {
	fx.In
	Config     *openapi3.T
	HttpClient *http.Client
	GORMDB     *gorm.DB
}

type SecurityConfiguration struct {
	fx.Out
	SecuritySchemes map[string]Validator
	AuthEnforcer    *casbin.Enforcer
}

func NewSecurityConfiguration(p SecurityParams) (result SecurityConfiguration, err error) {
	result = SecurityConfiguration{
		SecuritySchemes: make(map[string]Validator),
	}
	for name, schema := range p.Config.Components.SecuritySchemes {
		if schema.Value != nil {
			switch schema.Value.Type {
			case "openIdConnect":
				ctxt := context.WithValue(context.Background(), oauth2.HTTPClient, p.HttpClient)
				result.SecuritySchemes[name], err = new(OpenIDConnect).FromSchema(ctxt, schema.Value, p.HttpClient)
			default:
				err = fmt.Errorf("unsupported security scheme '%s'", name)
				return result, err
			}
		}
	}

	// With WEOS_ROUTE_GATE=on the route gate decides and casbin is never
	// consulted, so its policies are not loaded (nor its table touched): the
	// enforcer is an empty in-memory one, kept only so the fx graph is unchanged.
	gateMode, err := ParseRouteGateMode(os.Getenv(EnvRouteGate))
	if err != nil {
		return result, err
	}
	if gateMode == RouteGateOn {
		m, _ := casbinmodel.NewModelFromString(casbinRESTModel)
		result.AuthEnforcer, err = casbin.NewEnforcer(m)
		return result, err
	}

	//setup casbin enforcer
	adapter, err := gormadapter.NewAdapterByDB(p.GORMDB)
	if err != nil {
		return result, err
	}

	//default REST permission model
	m, _ := casbinmodel.NewModelFromString(casbinRESTModel)
	result.AuthEnforcer, err = casbin.NewEnforcer(m, adapter)
	return result, err
}

// casbinRESTModel is the default REST permission model.
const casbinRESTModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
`

// OpenIDConnect authorizer for OpenID
type OpenIDConnect struct {
	connectURL        string
	skipExpiryCheck   bool
	clientID          string
	userIDClaim       string
	roleClaim         string
	accountClaim      string
	applicationClaim  string
	subscriptionClaim string
	tenantClaim       string
	tenantRoleClaim   string
	permissionsClaim  string
	httpClient        *http.Client
	KeySet            oidc.KeySet
	// trusted is set in trusted-issuer mode (see auth_issuers.go); nil keeps
	// the original discovery-document behaviour.
	trusted *trustedIssuerVerifier
	// now is the clock for trusted-issuer mode (tests set it).
	now func() time.Time
}

// WithTrustedIssuers switches the validator to trusted-issuer mode with the
// given issuers (the programmatic form of the JWT_* / LEGACY_IAM_* variables).
func (o *OpenIDConnect) WithTrustedIssuers(issuers []TrustedIssuer) error {
	if o.skipExpiryCheck {
		return fmt.Errorf("%s cannot be combined with trusted issuers", SkipExpiryCheckExtension)
	}
	verifier, err := newTrustedIssuerVerifier(issuers, o.httpClient, o.now)
	if err != nil {
		return err
	}
	o.trusted = verifier
	return nil
}

// validateTrustedIssuer is Validate in trusted-issuer mode. It always returns
// a result (Valid false on any failure), and maps claims exactly as the
// discovery-document mode does.
func (o *OpenIDConnect) validateTrustedIssuer(ctxt echo.Context) (*ValidationResult, error) {
	authorizationHeader := ctxt.Request().Header.Get("Authorization")
	tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)
	payload, err := o.trusted.verify(ctxt.Request().Context(), tokenString)
	if err != nil {
		ctxt.Logger().Debugf("invalid token: %s", err)
		return &ValidationResult{Valid: false, Token: tokenString}, err
	}
	var subject struct {
		Subject string `json:"sub"`
	}
	if err = json.Unmarshal(payload, &subject); err != nil {
		return &ValidationResult{Valid: false, Token: tokenString}, err
	}
	result := o.mapClaims(subject.Subject, func(v interface{}) error { return json.Unmarshal(payload, v) })
	result.Valid = result.claimsErr == nil
	result.Token = tokenString
	return &result.ValidationResult, result.claimsErr
}

type mappedClaims struct {
	ValidationResult
	claimsErr error
}

// mapClaims applies the x-jwt-map to a verified token's claims. Both modes use
// it, so the request context values are the same whichever issuer signed the
// token: user defaults to sub, and role/account/application/subscription,
// tenant, tenant_role and permissions are read as strings ("" when absent).
func (o *OpenIDConnect) mapClaims(subject string, claims func(v interface{}) error) (result mappedClaims) {
	tclaims := make(map[string]interface{})
	tclaims[o.userIDClaim] = subject
	tclaims[o.roleClaim] = ""
	if o.accountClaim != "" {
		tclaims[o.accountClaim] = ""
	}
	if o.applicationClaim != "" {
		tclaims[o.applicationClaim] = ""
	}
	result.claimsErr = claims(&tclaims)
	if result.claimsErr == nil {
		// Every claim is read with comma-ok: IAM and older tokens lack some of
		// them (v1/subscription, v1/tenant_role, v1/permissions), and a missing
		// key or a value of another type must never panic; it reads as "".
		result.Role, _ = tclaims[o.roleClaim].(string)
		result.UserID, _ = tclaims[o.userIDClaim].(string)
		if o.accountClaim != "" {
			result.AccountID, _ = tclaims[o.accountClaim].(string)
		}
		if o.applicationClaim != "" {
			result.ApplicationID, _ = tclaims[o.applicationClaim].(string)
		}
		if o.subscriptionClaim != "" {
			result.SubscriptionID, _ = tclaims[o.subscriptionClaim].(string)
		}
		result.Subject = subject
		result.User, _ = tclaims[iamUserClaim].(string)
		result.Tenant, _ = tclaims[o.claimName(o.tenantClaim, TenantClaim)].(string)
		result.TenantRole, _ = tclaims[o.claimName(o.tenantRoleClaim, TenantRoleClaim)].(string)
		var permissions interface{}
		permissions, result.PermissionsClaimPresent = tclaims[o.claimName(o.permissionsClaim, PermissionsClaim)]
		result.Permissions, _ = permissions.(string)
	}
	return result
}

// claimName is the x-jwt-map name of a claim, or its default.
func (o *OpenIDConnect) claimName(mapped, fallback string) string {
	if mapped != "" {
		return mapped
	}
	return fallback
}

func (o *OpenIDConnect) Validate(ctxt echo.Context) (result *ValidationResult, err error) {
	if o.trusted != nil {
		return o.validateTrustedIssuer(ctxt)
	}
	//get the Jwk url from open id connect url and validate url
	openIDConfig, err := GetOpenIDConfig(o.connectURL, o.httpClient)
	if err != nil {
		return result, err
	} else {
		if jwks_uri, ok := openIDConfig["jwks_uri"]; ok {
			//create key set and verifier
			if o.KeySet == nil {
				o.KeySet = oidc.NewRemoteKeySet(context.Background(), jwks_uri.(string))
			}
			keySet := o.KeySet
			var algs []string
			if talgs, ok := openIDConfig["id_token_signing_alg_values_supported"]; ok {
				for _, alg := range talgs.([]interface{}) {
					algs = append(algs, alg.(string))
				}

			}
			if talgs, ok := openIDConfig["request_object_signing_alg_values_supported"]; ok {
				for _, alg := range talgs.([]interface{}) {
					algs = append(algs, alg.(string))
				}
			}
			tokenVerifier := oidc.NewVerifier(o.connectURL, keySet, &oidc.Config{
				ClientID:             o.clientID,
				SupportedSigningAlgs: algs,
				SkipClientIDCheck:    o.clientID == "",
				SkipExpiryCheck:      o.skipExpiryCheck,
				SkipIssuerCheck:      true,
				Now:                  time.Now,
			})
			authorizationHeader := ctxt.Request().Header.Get("Authorization")
			tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)
			token, err := tokenVerifier.Verify(context.Background(), tokenString)
			ctxt.Logger().Debugf("invalid token: %s", err)

			var userID string
			var role string
			var accountID string
			var applicationID string
			var subscriptionID string

			var mapped mappedClaims
			if token != nil {
				mapped = o.mapClaims(token.Subject, token.Claims)
				err = mapped.claimsErr
				role = mapped.Role
				userID = mapped.UserID
				accountID = mapped.AccountID
				applicationID = mapped.ApplicationID
				subscriptionID = mapped.SubscriptionID
			}

			return &ValidationResult{
				Valid:                   token != nil && err == nil,
				Token:                   tokenString,
				UserID:                  userID,
				Role:                    role,
				AccountID:               accountID,
				ApplicationID:           applicationID,
				SubscriptionID:          subscriptionID,
				Subject:                 mapped.Subject,
				User:                    mapped.User,
				Tenant:                  mapped.Tenant,
				TenantRole:              mapped.TenantRole,
				Permissions:             mapped.Permissions,
				PermissionsClaimPresent: mapped.PermissionsClaimPresent,
			}, err
		} else {
			return result, fmt.Errorf("expected jwks_url to be set")
		}
	}
}

func (o *OpenIDConnect) FromSchema(ctxt context.Context, scheme *openapi3.SecurityScheme, httpClient *http.Client) (Validator, error) {
	var err error
	o.httpClient = httpClient
	o.connectURL = scheme.OpenIdConnectUrl

	if tinterface, ok := scheme.Extensions[SkipExpiryCheckExtension]; ok {
		if expiryCheck, ok := tinterface.(json.RawMessage); ok {
			err = json.Unmarshal(expiryCheck, &o.skipExpiryCheck)
		}
	}

	if jwtMapRaw, ok := scheme.Extensions[JWTMapExtension]; ok {
		if user, ok := jwtMapRaw.(map[string]interface{})["user"]; ok {
			o.userIDClaim = user.(string)
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["role"]; ok {
			o.roleClaim = value.(string)
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["account"]; ok {
			o.accountClaim = value.(string)
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["application"]; ok {
			o.applicationClaim = value.(string)
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["subscription"]; ok {
			o.subscriptionClaim = value.(string)
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["tenant"].(string); ok {
			o.tenantClaim = value
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["tenant_role"].(string); ok {
			o.tenantRoleClaim = value
		}
		if value, ok := jwtMapRaw.(map[string]interface{})["permissions"].(string); ok {
			o.permissionsClaim = value
		}
	} else {
		o.userIDClaim = "sub"
	}
	if err != nil {
		return o, err
	}

	// Trusted-issuer mode when JWT_* / LEGACY_IAM_* are set; otherwise the
	// original discovery-document behaviour (see auth_issuers.go).
	issuers, err := TrustedIssuersFromEnv(os.Getenv)
	if err != nil {
		return o, err
	}
	if len(issuers) > 0 {
		err = o.WithTrustedIssuers(issuers)
	}
	return o, err
}

type OAuth2 struct {
	connectURL   string
	Flows        *openapi3.OAuthFlows
	clientSecret string
}

func (o *OAuth2) Validate(ctxt echo.Context) (*ValidationResult, error) {
	authorizationHeader := ctxt.Request().Header.Get("Authorization")
	tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		//TODO figure out good way to load certificate here
		cert := ``

		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			return nil, fmt.Errorf("unable to decode cert")
		}

		pub, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key '%s'", err)
		}

		return pub.PublicKey, nil
	})
	return &ValidationResult{
		Valid: token.Valid,
	}, err
}

func (o *OAuth2) FromSchema(ctxt context.Context, scheme *openapi3.SecurityScheme, client *http.Client) (Validator, error) {
	var err error
	o.Flows = scheme.Flows
	return o, err
}
