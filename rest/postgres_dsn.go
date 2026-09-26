package rest

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultPostgresSSLMode is used when neither the config nor the environment sets an sslmode.
// "require" encrypts the connection without verifying the server certificate, which works against
// any Postgres server that has TLS enabled (Azure Flexible Server, AWS RDS with rds.force_ssl=1).
// A local Postgres without TLS needs DB_SSLMODE=disable.
const DefaultPostgresSSLMode = "require"

// libpqSSLModes are the modes github.com/lib/pq (registered as the "postgres" driver) accepts.
// lib/pq rejects "allow" and "prefer" at connect time, which is why weos once fell back to
// sslmode=disable (WS-707).
var libpqSSLModes = map[string]bool{"disable": true, "require": true, "verify-ca": true, "verify-full": true}

// pgxSSLModes are the modes github.com/jackc/pgx (registered as the "pgx" driver) accepts.
var pgxSSLModes = map[string]bool{"disable": true, "allow": true, "prefer": true, "require": true, "verify-ca": true, "verify-full": true}

// PostgresSSLMode resolves the sslmode for a database config:
// config ssl-mode, then DB_SSLMODE, then PGSSLMODE, then DefaultPostgresSSLMode.
func PostgresSSLMode(config *DBConfig) string {
	for _, candidate := range []string{config.SSLMode, os.Getenv("DB_SSLMODE"), os.Getenv("PGSSLMODE")} {
		if candidate = strings.ToLower(strings.TrimSpace(candidate)); candidate != "" {
			return candidate
		}
	}
	return DefaultPostgresSSLMode
}

// PostgresDSN builds a key/value connection string for the "postgres" (lib/pq) and "pgx" drivers.
// Values are quoted so passwords (or IAM auth tokens) containing spaces, quotes or backslashes
// survive intact.
func PostgresDSN(config *DBConfig, password string) (string, error) {
	sslMode := PostgresSSLMode(config)
	allowed := pgxSSLModes
	if config.Driver != "pgx" {
		allowed = libpqSSLModes
	}
	if !allowed[sslMode] {
		return "", fmt.Errorf("sslmode '%s' is not supported by the '%s' driver; use disable, require, verify-ca or verify-full", sslMode, config.Driver)
	}

	parts := []string{
		"host=" + quoteDSNValue(config.Host),
		"port=" + quoteDSNValue(strconv.Itoa(config.Port)),
		"user=" + quoteDSNValue(config.User),
		"password=" + quoteDSNValue(password),
		"dbname=" + quoteDSNValue(config.Database),
		"sslmode=" + quoteDSNValue(sslMode),
	}

	rootCert := strings.TrimSpace(config.SSLRootCert)
	if rootCert == "" {
		rootCert = strings.TrimSpace(os.Getenv("DB_SSLROOTCERT"))
	}
	if rootCert != "" && sslMode != "disable" {
		parts = append(parts, "sslrootcert="+quoteDSNValue(rootCert))
	}

	return strings.Join(parts, " "), nil
}

// quoteDSNValue single-quotes a key/value DSN value, escaping backslashes and single quotes
// (the format both lib/pq and pgx parse).
func quoteDSNValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}
