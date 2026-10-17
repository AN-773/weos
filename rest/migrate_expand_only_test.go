package rest_test

import (
	"errors"
	"os"
	"testing"

	"github.com/wepala/weos/v2/rest"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// basicResourceWithExtra is BasicResource plus a column the database does not have yet.
type basicResourceWithExtra struct {
	rest.BasicResource
	Extra string
}

func (basicResourceWithExtra) TableName() string { return "basic_resources" }

// Needs a real Postgres: WEOS_TEST_POSTGRES_DSN="host=localhost port=55432 user=postgres password=test dbname=postgres sslmode=disable"
func TestExpandOnlyDialector_Postgres(t *testing.T) {
	dsn := os.Getenv("WEOS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WEOS_TEST_POSTGRES_DSN not set")
	}

	plain, err := gorm.Open(postgres.New(postgres.Config{DSN: dsn}), nil)
	if err != nil {
		t.Fatalf("open plain: %s", err)
	}
	for _, stmt := range []string{
		"DROP VIEW IF EXISTS basic_resource_bodies",
		"DROP TABLE IF EXISTS basic_resources CASCADE",
		"DROP TABLE IF EXISTS events CASCADE",
	} {
		if err := plain.Exec(stmt).Error; err != nil {
			t.Fatalf("%s: %s", stmt, err)
		}
	}
	if err := plain.AutoMigrate(&rest.Event{}, &rest.BasicResource{}); err != nil {
		t.Fatalf("first migration: %s", err)
	}
	// What production has: something reads the body column through a view.
	if err := plain.Exec("CREATE VIEW basic_resource_bodies AS SELECT id, body FROM basic_resources").Error; err != nil {
		t.Fatalf("create view: %s", err)
	}
	// The hazard this dialector exists for. Whether it reproduces depends on the driver version this module
	// resolves (v1.4.0, which the IAM pins, always retypes JSONB columns), so it is logged, not asserted.
	t.Logf("plain AutoMigrate with a view on body: %v", plain.AutoMigrate(&rest.Event{}, &rest.BasicResource{}))

	db, err := gorm.Open(rest.ExpandOnlyDialector{Dialector: postgres.New(postgres.Config{DSN: dsn})}, nil)
	if err != nil {
		t.Fatalf("open expand-only: %s", err)
	}

	t.Run("migrating an unchanged schema with a view on a column succeeds", func(t *testing.T) {
		if err := db.AutoMigrate(&rest.Event{}, &rest.BasicResource{}); err != nil {
			t.Fatalf("expected no error, got %s", err)
		}
	})

	t.Run("a new column is still added", func(t *testing.T) {
		if err := db.AutoMigrate(&basicResourceWithExtra{}); err != nil {
			t.Fatalf("expected no error, got %s", err)
		}
		if !db.Migrator().HasColumn(&basicResourceWithExtra{}, "Extra") {
			t.Fatal("expected column extra to be added")
		}
	})

	t.Run("a missing table is still created", func(t *testing.T) {
		if err := db.Exec("DROP TABLE IF EXISTS events").Error; err != nil {
			t.Fatalf("drop events: %s", err)
		}
		if err := db.AutoMigrate(&rest.Event{}); err != nil {
			t.Fatalf("expected no error, got %s", err)
		}
		if !db.Migrator().HasTable(&rest.Event{}) {
			t.Fatal("expected table events to be created")
		}
	})

	t.Run("nested transactions still use savepoints", func(t *testing.T) {
		inner := errors.New("inner rolled back")
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Transaction(func(tx2 *gorm.DB) error { return inner }); !errors.Is(err, inner) {
				t.Fatalf("expected the inner error back, got %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("expected the outer transaction to commit, got %s", err)
		}
	})

	t.Run("the dialector still reports postgres", func(t *testing.T) {
		if name := db.Dialector.Name(); name != "postgres" {
			t.Fatalf("expected postgres, got %s", name)
		}
	})
}
