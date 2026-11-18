package rest

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/segmentio/ksuid"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type MiddlewareParams struct {
	Logger                Log
	CommandDispatcher     CommandDispatcher
	ResourceRepository    *ResourceRepository
	Schema                *openapi3.T
	APIConfig             *APIConfig
	PathMap               map[string]*openapi3.PathItem
	Operation             map[string]*openapi3.Operation
	SecuritySchemes       map[string]Validator
	AuthorizationEnforcer *casbin.Enforcer
	// RouteGate is the route gate (route_gate.go); nil is off.
	RouteGate *RouteGate
}

// ZapLogger switches the echo context logger to be ZapLogger
func ZapLogger(p *MiddlewareParams) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		var configuredLevel string
		var serviceName string
		if p.APIConfig.Log != nil {
			configuredLevel = p.APIConfig.Log.Level
			serviceName = p.APIConfig.Log.Name
		}
		return func(c echo.Context) error {
			//setting the default logger in the context as zap with the default mode being error
			req := c.Request()
			id := req.Header.Get(echo.HeaderXRequestID)
			if id == "" {
				id = ksuid.New().String()
				req.Header.Set(echo.HeaderXRequestID, id)
			}
			level := req.Header.Get("X-Log-Level")
			if level == "" {
				if configuredLevel != "" {
					level = configuredLevel
				} else { //by default only show errors
					level = "info"
				}
			} else {
				//only allow setting the level to debug from this header for security reasons
				level = "debug"
			}
			if serviceName == "" {
				serviceName = "weos"
			}
			zapLogger, err := new(Zap).WithRequestID(serviceName, level, id)
			if err != nil {
				c.Logger().Errorf("Unexpected error setting the context logger : %s", err)
			}
			c.SetLogger(zapLogger)
			start := time.Now()
			cc := c.Request().Context()
			cc = context.WithValue(cc, echo.HeaderXRequestID, id)
			request := c.Request().WithContext(cc)
			c.SetRequest(request)
			err = next(c)
			response := c.Response()
			re := regexp.MustCompile(`^` + os.Getenv("BASE_PATH") + `/health`)
			if !re.MatchString(request.URL.Path) {
				zapLogger.With(
					zap.String("remote_ip", c.RealIP()),
					zap.String("uri", req.RequestURI),
					zap.Int("status", response.Status),
					zap.String("method", c.Request().Method),
					zap.Duration("latency", time.Since(start)),
					zap.Int64("response_size", response.Size),
					zap.String("referer", req.Referer()),
					zap.String("user_agent", req.UserAgent()),
				).Info("request")
			}
			return err
		}
	}
}

func SecurityMiddleware(p *MiddlewareParams) echo.MiddlewareFunc {
	//check that the schemes exist
	logger := p.Logger
	securitySchemes := p.Schema.Security
	for _, operation := range p.Operation {
		if operation.Security != nil {
			securitySchemes = *operation.Security
		}
	}
	if securitySchemes == nil {
		securitySchemes = make(openapi3.SecurityRequirements, 0)
	}
	validators := securityValidators(logger, p.SecuritySchemes, securitySchemes)

	// The route gate (route_gate.go). A nil gate is off.
	gate := p.RouteGate
	var method, path string
	for m := range p.Operation {
		method = m
	}
	for tpath := range p.PathMap {
		path = tpath
	}
	rule := gate.ruleFor(method, path)
	catalogue := gate.catalogue()
	if gate.gateMode() == RouteGateOn {
		return gatedSecurityMiddleware(p, gate, rule, method, path, catalogue, securitySchemes, validators)
	}
	shadow := gate.gateMode() == RouteGateShadow
	// compare logs route_gate.disagree when, in shadow, the gate would answer
	// differently from casbin. casbin's answer is what the request gets.
	compare := func(ctxt echo.Context, result *ValidationResult, casbinAllowed bool) {
		if !shadow {
			return
		}
		if gateAllowed := gate.Allows(rule, result); gateAllowed != casbinAllowed {
			role := ""
			if result != nil {
				role = result.Role
			}
			line := fmt.Sprintf("route_gate.disagree method=%s path=%s route=%q role=%q access=%q permission=%q casbin=%s gate=%s",
				ctxt.Request().Method, ctxt.Request().URL.Path, path, role, rule.Access, rule.Permission, answer(casbinAllowed), answer(gateAllowed))
			ctxt.Logger().Warn(line)
			if gate.onDisagree != nil {
				gate.onDisagree(line)
			}
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctxt echo.Context) error {
			var success bool
			var err error
			var result *ValidationResult
			//if there are security schemes then authenticate the user
			if len(securitySchemes) > 0 {
				//loop through the validators and go to the next middleware when one authenticates otherwise return 403
				for _, validator := range validators {
					if result, err = validator.Validate(ctxt); result.Valid {
						setSecurityContext(ctxt, result, catalogue)
						//check the scopes of the logged-in user against what is required and if the user doesn't have the required scope deny access
						if !hasRequiredScopes(ctxt, securitySchemes, result) {
							return ctxt.NoContent(http.StatusForbidden)
						}
						//check permissions to ensure the user can access this endpoint

						tpath := strings.Replace(ctxt.Request().URL.Path, p.APIConfig.BasePath, "", 1)
						success, err = p.AuthorizationEnforcer.Enforce(result.UserID, tpath, ctxt.Request().Method)
						//fmt.Printf("explanations %v", explanations)
						if err != nil {
							ctxt.Logger().Errorf("error looking up permissions '%s'", err)
						}
						if success {
							compare(ctxt, result, true)
							return next(ctxt)
						}
						//check if the role has access to the endpoint
						success, err = p.AuthorizationEnforcer.Enforce(result.Role, tpath, ctxt.Request().Method)
						if success {
							compare(ctxt, result, true)
							return next(ctxt)
						}
						if err != nil {
							ctxt.Logger().Errorf("the role '%s' does not have access to '%s' action '%s': original error '%s'", result.Role, tpath, ctxt.Request().Method, err)
						}
						compare(ctxt, result, false)
						return ctxt.NoContent(http.StatusForbidden)
					}
					ctxt.Logger().Debugf("error authenticating '%s'", err)
				}
				//if there were validators configured then return un authorized status code
				if len(validators) > 0 {
					compare(ctxt, nil, false)
					return ctxt.NoContent(http.StatusUnauthorized)
				}
			}
			compare(ctxt, nil, true)
			return next(ctxt)
		}
	}
}

func answer(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// securityValidators resolves the validators of a list of security requirements.
func securityValidators(logger Log, all map[string]Validator, requirements openapi3.SecurityRequirements) []Validator {
	var validators []Validator
	for _, scheme := range requirements {
		for name, _ := range scheme {
			if validator, ok := all[name]; ok {
				validators = append(validators, validator)
			} else {
				logger.Errorf("security scheme '%s' was not configured in components > security schemes", name)
			}
		}
	}
	return validators
}

// setSecurityContext puts a verified token's values in the request context.
func setSecurityContext(ctxt echo.Context, result *ValidationResult, catalogue *PermissionCatalogue) {
	newContext := context.WithValue(ctxt.Request().Context(), USER_ID, result.UserID)
	newContext = context.WithValue(newContext, ROLE, result.Role)
	newContext = context.WithValue(newContext, ACCOUNT_ID, result.AccountID)
	newContext = context.WithValue(newContext, APPLICATION_ID, result.ApplicationID)
	newContext = context.WithValue(newContext, SUBSCRIPTION_ID, result.SubscriptionID)
	newContext = context.WithValue(newContext, AUTHORIZATION_HEADER, ctxt.Request().Header.Get("Authorization"))
	newContext = context.WithValue(newContext, TENANT, result.Tenant)
	newContext = context.WithValue(newContext, TENANT_ROLE, result.TenantRole)
	var permissions []string
	if result.IsUserToken() {
		permissions = catalogue.EffectivePermissions(result)
	} else {
		permissions = []string{}
	}
	newContext = context.WithValue(newContext, PERMISSIONS, permissions)

	request := ctxt.Request().WithContext(newContext)
	ctxt.SetRequest(request)
}

// hasRequiredScopes checks the scopes of the logged-in user against what the
// security requirements need.
func hasRequiredScopes(ctxt echo.Context, securitySchemes openapi3.SecurityRequirements, result *ValidationResult) bool {
	for _, securityScheme := range securitySchemes {
		for _, scopes := range securityScheme {
			for _, scope := range scopes {
				//account for the different token types that could be returned
				switch t := result.Token.(type) {
				case *oidc.IDToken:
					claims := make(map[string]interface{})
					err := t.Claims(&claims)
					if err != nil {
						ctxt.Logger().Debugf("invalid claims '%s'", err)
					}
					if _, ok := claims["scope"]; !ok {
						ctxt.Logger().Debug("token from issuer '%s' does not have scopes", t.Issuer)
						return false
					}
					//if the required scope is not in the user scope
					if !strings.Contains(claims["scope"].(string), scope) {
						ctxt.Logger().Debug("token from issuer '%s' does not have required scope '%s'", t.Issuer, scope)
						return false
					}
				case *jwt.Token:
					if claims, ok := t.Claims.(jwt.MapClaims); ok {
						if _, ok := claims["scope"]; !ok {
							ctxt.Logger().Debug("token from issuer '%s' does not have scopes", claims["iss"])
							return false
						}
						//if the required scope is not in the user scope
						if !strings.Contains(claims["scope"].(string), scope) {
							ctxt.Logger().Debug("token from issuer '%s' does not have required scope '%s'", claims["iss"], scope)
							return false
						}
					}
				}
			}
		}
	}
	return true
}

// gatedSecurityMiddleware is SecurityMiddleware with WEOS_ROUTE_GATE=on: the
// gate decides and casbin is never consulted.
func gatedSecurityMiddleware(p *MiddlewareParams, gate *RouteGate, rule RouteRule, method, path string, catalogue *PermissionCatalogue, securitySchemes openapi3.SecurityRequirements, validators []Validator) echo.MiddlewareFunc {
	// An undeclared operation still authenticates (403 to a token, 401 without
	// one), with the document's schemes when it declares none of its own.
	if !rule.Declared && len(validators) == 0 && p.Schema != nil {
		securitySchemes = p.Schema.Security
		validators = securityValidators(p.Logger, p.SecuritySchemes, securitySchemes)
	}
	public := rule.Declared && rule.Access == AccessPublic
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctxt echo.Context) error {
			if public {
				return next(ctxt)
			}
			var result *ValidationResult
			for _, validator := range validators {
				candidate, err := validator.Validate(ctxt)
				if candidate != nil && candidate.Valid {
					result = candidate
					break
				}
				ctxt.Logger().Debugf("error authenticating '%s'", err)
			}
			if result == nil {
				return ctxt.NoContent(http.StatusUnauthorized)
			}
			setSecurityContext(ctxt, result, catalogue)
			if !hasRequiredScopes(ctxt, securitySchemes, result) {
				return ctxt.NoContent(http.StatusForbidden)
			}
			if !rule.Declared {
				ctxt.Logger().Warnf("route_gate.undeclared method=%s path=%s route=%q", method, ctxt.Request().URL.Path, path)
				return ctxt.NoContent(http.StatusForbidden)
			}
			if !gate.Allows(rule, result) {
				return ctxt.NoContent(http.StatusForbidden)
			}
			return next(ctxt)
		}
	}
}
