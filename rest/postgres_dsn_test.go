package rest_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wepala/weos/v2/rest"
)

func clearSSLEnv(t *testing.T) {
	t.Setenv("DB_SSLMODE", "")
	t.Setenv("PGSSLMODE", "")
	t.Setenv("DB_SSLROOTCERT", "")
}

func baseDBConfig() *rest.DBConfig {
	return &rest.DBConfig{Driver: "postgres", Host: "db.example.com", Port: 5432, User: "app", Database: "iam"}
}

func TestPostgresSSLMode(t *testing.T) {
	t.Run("defaults to require", func(t *testing.T) {
		clearSSLEnv(t)
		if got := rest.PostgresSSLMode(baseDBConfig()); got != "require" {
			t.Fatalf("expected require, got %q", got)
		}
	})
	t.Run("DB_SSLMODE is honoured", func(t *testing.T) {
		clearSSLEnv(t)
		t.Setenv("DB_SSLMODE", "disable")
		if got := rest.PostgresSSLMode(baseDBConfig()); got != "disable" {
			t.Fatalf("expected disable, got %q", got)
		}
	})
	t.Run("PGSSLMODE is the fallback after DB_SSLMODE", func(t *testing.T) {
		clearSSLEnv(t)
		t.Setenv("PGSSLMODE", "verify-full")
		if got := rest.PostgresSSLMode(baseDBConfig()); got != "verify-full" {
			t.Fatalf("expected verify-full, got %q", got)
		}
		t.Setenv("DB_SSLMODE", "disable")
		if got := rest.PostgresSSLMode(baseDBConfig()); got != "disable" {
			t.Fatalf("expected DB_SSLMODE to win over PGSSLMODE, got %q", got)
		}
	})
	t.Run("config wins over the environment", func(t *testing.T) {
		clearSSLEnv(t)
		t.Setenv("DB_SSLMODE", "disable")
		config := baseDBConfig()
		config.SSLMode = " Require "
		if got := rest.PostgresSSLMode(config); got != "require" {
			t.Fatalf("expected require, got %q", got)
		}
	})
}

func TestPostgresDSN(t *testing.T) {
	t.Run("default DSN requires TLS and round-trips through the pgx parser", func(t *testing.T) {
		clearSSLEnv(t)
		password := `p@ss w'rd\with#odd$chars`
		dsn, err := rest.PostgresDSN(baseDBConfig(), password)
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}
		if !strings.Contains(dsn, "sslmode='require'") {
			t.Fatalf("expected sslmode require in %s", dsn)
		}
		parsed, err := pgconn.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("pgx could not parse dsn: %s", err)
		}
		if parsed.Password != password {
			t.Errorf("password did not round-trip: got %q", parsed.Password)
		}
		if parsed.Host != "db.example.com" || parsed.Port != 5432 || parsed.User != "app" || parsed.Database != "iam" {
			t.Errorf("unexpected parsed config %+v", parsed)
		}
		if parsed.TLSConfig == nil {
			t.Errorf("expected a TLS config for sslmode=require")
		}
	})
	t.Run("disable produces a plaintext connection", func(t *testing.T) {
		clearSSLEnv(t)
		t.Setenv("DB_SSLMODE", "disable")
		dsn, err := rest.PostgresDSN(baseDBConfig(), "secret")
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}
		parsed, err := pgconn.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("pgx could not parse dsn: %s", err)
		}
		if parsed.TLSConfig != nil || len(parsed.Fallbacks) != 0 {
			t.Errorf("expected no TLS for sslmode=disable")
		}
	})
	t.Run("prefer is rejected for lib/pq but allowed for pgx", func(t *testing.T) {
		clearSSLEnv(t)
		config := baseDBConfig()
		config.SSLMode = "prefer"
		if _, err := rest.PostgresDSN(config, "secret"); err == nil {
			t.Errorf("expected an error for sslmode=prefer with the postgres (lib/pq) driver")
		}
		config.Driver = "pgx"
		if _, err := rest.PostgresDSN(config, "secret"); err != nil {
			t.Errorf("expected prefer to be accepted for pgx, got %s", err)
		}
	})
	t.Run("unknown modes are rejected", func(t *testing.T) {
		clearSSLEnv(t)
		config := baseDBConfig()
		config.SSLMode = "on"
		if _, err := rest.PostgresDSN(config, "secret"); err == nil {
			t.Errorf("expected an error for sslmode=on")
		}
	})
	t.Run("sslrootcert is added from config or DB_SSLROOTCERT", func(t *testing.T) {
		clearSSLEnv(t)
		t.Setenv("DB_SSLROOTCERT", "/etc/ssl/rds.pem")
		dsn, err := rest.PostgresDSN(baseDBConfig(), "secret")
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}
		if !strings.Contains(dsn, "sslrootcert='/etc/ssl/rds.pem'") {
			t.Errorf("expected sslrootcert in %s", dsn)
		}
		t.Setenv("DB_SSLMODE", "disable")
		dsn, _ = rest.PostgresDSN(baseDBConfig(), "secret")
		if strings.Contains(dsn, "sslrootcert") {
			t.Errorf("expected no sslrootcert when TLS is disabled, got %s", dsn)
		}
	})
}
