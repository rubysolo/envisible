package aws

import (
	"context"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

// realCreatorRegion builds a client with the production constructor (no fake)
// and reports the region it ended up configured for. Nothing is sent: the SDK
// resolves credentials and endpoints lazily, and TestMain has emptied the
// ambient AWS configuration.
func realCreatorRegion(t *testing.T, region string) string {
	t.Helper()
	api, err := newCreatorClient(context.Background(), region)
	if err != nil {
		t.Fatalf("newCreatorClient(%q): %v", region, err)
	}
	client, ok := api.(*awskms.Client)
	if !ok {
		t.Fatalf("newCreatorClient returned %T, want *kms.Client", api)
	}
	return client.Options().Region
}

// create.go:36 — an explicit --region must reach the SDK client: it decides
// which region the new key is created in.
func TestNewCreatorClientAppliesAnExplicitRegion(t *testing.T) {
	if got := realCreatorRegion(t, "eu-west-3"); got != "eu-west-3" {
		t.Errorf("client region = %q, want the explicit eu-west-3", got)
	}
}

// ...and it outranks the SDK's own chain, while an empty --region leaves that
// chain in charge instead of overriding it with nothing.
func TestNewCreatorClientRegionPrecedence(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-south-1")

	if got := realCreatorRegion(t, "eu-west-3"); got != "eu-west-3" {
		t.Errorf("client region = %q, want the explicit eu-west-3 over AWS_REGION", got)
	}
	if got := realCreatorRegion(t, ""); got != "ap-south-1" {
		t.Errorf("client region = %q with no --region, want AWS_REGION's ap-south-1", got)
	}
}
