package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// stuckCreatorClient creates a key whose version never leaves
// PENDING_GENERATION. It counts the polls and, past ceiling, answers with an
// error instead, so a poll loop that has lost its bound fails the test rather
// than spinning for ever.
type stuckCreatorClient struct {
	versionName string
	polls       int
	ceiling     int
}

var errPolledPastCeiling = errors.New("test fake: polled past the ceiling")

func (c *stuckCreatorClient) CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return &kmspb.CryptoKey{
		Primary: &kmspb.CryptoKeyVersion{Name: c.versionName, State: kmspb.CryptoKeyVersion_PENDING_GENERATION},
	}, nil
}

func (c *stuckCreatorClient) GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	c.polls++
	if c.polls > c.ceiling {
		return nil, errPolledPastCeiling
	}
	return &kmspb.CryptoKeyVersion{Name: c.versionName, State: kmspb.CryptoKeyVersion_PENDING_GENERATION}, nil
}

func (c *stuckCreatorClient) Close() error { return nil }

// create.go:85 — a version that never becomes ENABLED is polled exactly
// pollMaxAttempts times, then reported as a timeout naming the last state.
func TestCreateKeyGivesUpAfterPollMaxAttempts(t *testing.T) {
	oldInterval, oldAttempts := pollInterval, pollMaxAttempts
	pollInterval, pollMaxAttempts = time.Microsecond, 3
	t.Cleanup(func() { pollInterval, pollMaxAttempts = oldInterval, oldAttempts })

	client := &stuckCreatorClient{
		versionName: "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		ceiling:     10,
	}
	got, err := createKeyWithClient(context.Background(), client, CreateKeyParams{
		Project: "p", Location: "us", Keyring: "r", Name: "k",
	})

	if errors.Is(err, errPolledPastCeiling) {
		t.Fatalf("the poll loop ran past pollMaxAttempts=3 (%d polls)", client.polls)
	}
	const want = "gcp kms: timed out waiting for key version to become ENABLED (last state: PENDING_GENERATION)"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
	if got != "" {
		t.Errorf("returned resource %q for a key that never became usable", got)
	}
	if client.polls != 3 {
		t.Errorf("polled %d times, want exactly pollMaxAttempts = 3", client.polls)
	}
}

// With pollMaxAttempts = 0 there is no polling at all: a pending version is
// reported as timed out without a single GetCryptoKeyVersion call.
func TestCreateKeyDoesNotPollWhenNoAttemptsAreAllowed(t *testing.T) {
	oldInterval, oldAttempts := pollInterval, pollMaxAttempts
	pollInterval, pollMaxAttempts = time.Microsecond, 0
	t.Cleanup(func() { pollInterval, pollMaxAttempts = oldInterval, oldAttempts })

	client := &stuckCreatorClient{versionName: "v", ceiling: 10}
	_, err := createKeyWithClient(context.Background(), client, CreateKeyParams{
		Project: "p", Location: "us", Keyring: "r", Name: "k",
	})

	if err == nil || !strings.Contains(err.Error(), "timed out waiting for key version to become ENABLED") {
		t.Errorf("error = %v, want the timeout", err)
	}
	if client.polls != 0 {
		t.Errorf("polled %d times with pollMaxAttempts = 0, want none", client.polls)
	}
}
