---
layout: default
title: Route gate (permissions)
parent: Features
---
# Route gate (permissions)

The route gate decides who may call each operation from a declaration on the
operation and the permissions in the caller's token. It replaces the casbin
`x-auth` rules. Row filtering (which tenant's rows a caller sees) stays in the
service.

## Declaring routes

Each operation declares exactly one of these:

```yaml
paths:
  /health-check:
    get:
      x-access: public        # no token; must go with security: []
      security: []
  /me:
    get:
      x-access: signed-in     # any valid user token
  /questions/generate:
    post:
      x-permission: content:generate   # a signed-in user holding this permission
```

Boot fails (in `shadow` and `on`) when:

- an operation declares both `x-access` and `x-permission`;
- `x-access` is anything but `public` or `signed-in`;
- `x-access: public` lacks `security: []`, or `signed-in` / `x-permission`
  declares `security: []`;
- an `x-permission` name is not in the catalogue.

An operation with no declaration is *undeclared*. `security: []` alone does not
make an operation public: declare `x-access: public` as well.

`x-auth` may stay on operations during the overlap: casbin uses it in `off` and
`shadow`, and the gate ignores it.

## Vendoring the catalogue

The permission names come from medai-accounts (`docs/permissions.json`,
exported from `src/auth/permissions.ts`). Each service commits a copy and points
`WEOS_PERMISSIONS_FILE` at it:

```sh
cp ../medai-accounts/docs/permissions.json ./permissions.json   # commit it
# Dockerfile / task definition
WEOS_PERMISSIONS_FILE=/app/permissions.json
```

Re-copy it whenever accounts adds a permission the service uses. A catalogue
the gate can't read refuses boot: an unknown `version`, a different claim key,
an unknown permission in a bundle, or missing `legacy` fields. The fork carries
its own copy (`rest/route_gate_permissions.json`), but only for
`rest.HasPermission` in `off` when the variable is unset. `shadow` and `on`
always need the service's file.

To catch a bad declaration in CI, call the validator from a unit test:

```go
doc, _ := openapi3.NewLoader().LoadFromFile("api.yaml")
catalogue, _ := rest.LoadPermissionCatalogue("permissions.json")
undeclared, err := rest.ValidateRouteDeclarations(doc, catalogue)
```

## Modes

| `WEOS_ROUTE_GATE` | Who decides |
|---|---|
| `off` (default) | casbin `x-auth`, exactly as before. Declarations are not read. |
| `shadow` | casbin decides. The gate also decides and logs `route_gate.disagree` (method, path, route, role, `user_token`, `legacy_issuer`, access, permission, `casbin=allow/deny`, `gate=allow/deny`) when the answers differ. |
| `on` | The gate decides. casbin `Enforce` is never called, `x-auth` policies are not added, and casbin policies are not loaded from the database. |

In `on`, an undeclared operation answers **403** to a valid token and **401**
without one. In `shadow` and `on`, each undeclared operation is logged at boot as
`route_gate.undeclared`. With `WEOS_ROUTE_GATE_STRICT=true`, `on` refuses to boot
while any operation is undeclared.

With the gate `on`, the security middleware runs on every operation, even when
the document has no top-level `security`.

A suggested rollout: `shadow` on TEST, then read the `route_gate.disagree` and
`route_gate.undeclared` lines. Then `on`, then `on` with strict.

## The decision

1. `x-access: public` passes, with or without a token.
2. Undeclared operations are refused (see above).
3. A valid **user** token is required, where `sub` equals
   `https://iam.weos.io/v1/user`.
4. When the effective permissions hold `*` (superadmin), everything declared
   passes.
5. `signed-in` passes.
6. `x-permission: <name>` passes when the effective permissions hold `<name>`
   or `*`. Matches are exact, never by substring.

The effective permissions come from `https://iam.weos.io/v1/permissions`, a
sorted, comma-separated string. `""` means none, and `*` means all. When the key
is present, **the claim alone decides**: accounts writes `*` for a superadmin,
so `v1/roles` is not read (a `v1/roles: superadmin` token with `""` has none).

The gate uses the catalogue's `legacy` mapping, the same as accounts'
`legacyPermissions`, when the token has no such key (older tokens), and for
**every token the legacy IAM issuer verified** (trusted-issuer mode,
`LEGACY_IAM_*`): IAM never mints the claim, so one on an IAM token is ignored.

- `v1/roles` exactly `superadmin` gets `*` (no list split, case-sensitive).
- In the MedAI workspace, `Administrator` gets the staff bundle, and anyone
  else gets none. `v1/tenant` is first normalised as learning's
  `tenantctx.NormalizeID` does (a URL keeps its path; `BASE_PATH` and a leading
  `/v1` are stripped); MedAI is `""`, `/tenants/medai` or `medai` before or
  after that. A non-empty value that normalises to nothing (a bare id other than
  `medai`, junk) is **not** MedAI: it fails closed to the tenant-role rule.
- Elsewhere, `v1/tenant_role` `owner` or `admin` gets that role's bundle, and
  anyone else gets none.

The fallback applies **only when the key is absent** (or the issuer is IAM). A
present `""`, a `null` or a value of another type means no permissions.

## Handler checks

The security middleware puts these in the request context, in every mode:

```go
rest.GetTenant(ctx)                         // v1/tenant
rest.GetTenantRole(ctx)                     // v1/tenant_role
rest.Permissions(ctx)                       // effective permissions (a copy), nil without a user
rest.HasPermission(ctx, "catalog:view-hidden")
```

`v1/user` is read from the token's own claims, never from the `x-jwt-map`
`user` default (`sub`), so a token without `v1/user` is never a user token.

`HasPermission` follows the gate's rules, including the legacy fallback and `*`.
Convert handler role checks to it, so that `off` stays as safe as today.

`x-jwt-map` may name the claims (`tenant`, `tenant_role`, `permissions`). When
it doesn't, the `https://iam.weos.io/v1/...` names are used. Every claim is read
safely: a missing key or a value of another type reads as `""` and never panics.
