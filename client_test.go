package kalshi

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

var rateLimit = rate.NewLimiter(rate.Every(time.Second), 10-1)

func testClient(t *testing.T) *Client {
	const (
		keyIDEnv         = "KALSHI_KEY_ID"
		privateKeyEnv    = "KALSHI_PRIVATE_KEY_PATH"
		privateKeyPEMEnv = "KALSHI_PRIVATE_KEY_PEM"
	)

	ctx := context.Background()
	_ = ctx // Keep for future use

	keyID, ok := os.LookupEnv(keyIDEnv)
	if !ok {
		t.Fatalf("no $%s provided", keyIDEnv)
	}

	var pemData []byte
	var err error

	// Try to load from file path first
	if keyPath, ok := os.LookupEnv(privateKeyEnv); ok {
		pemData, err = os.ReadFile(keyPath)
		require.NoError(t, err, "failed to read private key file")
	} else if pemStr, ok := os.LookupEnv(privateKeyPEMEnv); ok {
		// Otherwise use PEM string directly
		pemData = []byte(pemStr)
	} else {
		t.Fatalf("no $%s or $%s provided", privateKeyEnv, privateKeyPEMEnv)
	}

	privateKey, err := LoadPrivateKeyFromPEM(pemData, "")
	require.NoError(t, err, "failed to load private key")

	c := NewClient(keyID, privateKey, APIDemoURL)
	c.WriteRatelimit = rateLimit
	return c
}
