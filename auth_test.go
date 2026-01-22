package kalshi

import (
	"testing"
)

func TestLoadPrivateKeyFromPEM(t *testing.T) {
	t.Parallel()

	// Basic test to ensure the function exists
	// More comprehensive tests would require test key fixtures
	_, err := LoadPrivateKeyFromPEM([]byte("invalid"), "")
	if err == nil {
		t.Error("expected error for invalid PEM data")
	}
}
