//go:build integration_postgres

package postgres_test

import (
	"log"
	"os"
	"testing"
)

// pgContainerDSN is the connection string for the PostgreSQL test database.
// Read from AUTHPLANE_STORAGE_POSTGRES_DSN (set by CI or docker compose).
var pgContainerDSN string

const defaultPGDSN = "postgres://authserver:authserver@localhost:5433/authserver?sslmode=disable"

func TestMain(m *testing.M) {
	pgContainerDSN = os.Getenv("AUTHPLANE_STORAGE_POSTGRES_DSN")
	if pgContainerDSN == "" {
		pgContainerDSN = defaultPGDSN
	}
	log.Printf("postgres integration tests using DSN: %s", pgContainerDSN)

	os.Exit(m.Run())
}
