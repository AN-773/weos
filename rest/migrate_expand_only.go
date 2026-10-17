package rest

import (
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// ExpandOnlyDialector wraps a GORM dialector so that AutoMigrate only ever expands a schema: it creates
// missing tables, adds missing columns and creates missing indexes and constraints, but it never alters a
// column that already exists.
//
// Why. Services run AutoMigrate on every boot against shared production databases, and two things make
// GORM's column migration unsafe there:
//   - It issues DDL even when nothing changed. gorm.io/driver/postgres v1.4.0 compares the database's type
//     name ("jsonb") with the model's ("JSONB") case-sensitively, so every boot runs
//     ALTER TABLE ... ALTER COLUMN ... TYPE JSONB. Postgres refuses that once any view reads the column
//     ("cannot alter type of a column used by a view or rule"), and the service can no longer start.
//   - A rolling deploy runs the old and the new build side by side on one database. Retyping a column,
//     setting NOT NULL or adding a UNIQUE constraint from the new build can break the old one mid-deploy.
//
// A real type, nullability or constraint change is a deliberate migration: write it explicitly (and make it
// backward compatible with the build that is still running).
type ExpandOnlyDialector struct {
	gorm.Dialector
}

// Migrator returns the wrapped dialector's migrator with column migration switched off.
func (d ExpandOnlyDialector) Migrator(db *gorm.DB) gorm.Migrator {
	return expandOnlyMigrator{Migrator: d.Dialector.Migrator(db)}
}

// The optional interfaces GORM looks for on a dialector (gorm.Open, Transaction, TranslateError). Embedding
// the gorm.Dialector interface does not promote them, so each is forwarded explicitly, and behaves exactly as
// the wrapped dialector does when that dialector lacks it.

// Apply forwards gorm.Open's dialector configuration hook.
func (d ExpandOnlyDialector) Apply(config *gorm.Config) error {
	if applier, ok := d.Dialector.(interface{ Apply(*gorm.Config) error }); ok {
		return applier.Apply(config)
	}
	return nil
}

// SavePoint forwards nested-transaction savepoints.
func (d ExpandOnlyDialector) SavePoint(tx *gorm.DB, name string) error {
	if savePointer, ok := d.Dialector.(gorm.SavePointerDialectorInterface); ok {
		return savePointer.SavePoint(tx, name)
	}
	return gorm.ErrUnsupportedDriver
}

// RollbackTo forwards nested-transaction rollbacks.
func (d ExpandOnlyDialector) RollbackTo(tx *gorm.DB, name string) error {
	if savePointer, ok := d.Dialector.(gorm.SavePointerDialectorInterface); ok {
		return savePointer.RollbackTo(tx, name)
	}
	return gorm.ErrUnsupportedDriver
}

// Translate forwards driver error translation (gorm.Config.TranslateError).
func (d ExpandOnlyDialector) Translate(err error) error {
	if translator, ok := d.Dialector.(gorm.ErrorTranslator); ok {
		return translator.Translate(err)
	}
	return err
}

type expandOnlyMigrator struct {
	gorm.Migrator
}

// MigrateColumn leaves an existing column as it is. AutoMigrate calls it only for columns it found in the
// database; missing columns still go through AddColumn. GORM's AutoMigrate reaches this through
// db.Migrator(), that is through ExpandOnlyDialector, so it applies to every AutoMigrate on the connection.
func (m expandOnlyMigrator) MigrateColumn(dst interface{}, field *schema.Field, columnType gorm.ColumnType) error {
	return nil
}
