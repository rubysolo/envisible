package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeCreatorAPI struct {
	createInput *awskms.CreateKeyInput
	createErr   error
	createResp  *awskms.CreateKeyOutput

	aliasInput *awskms.CreateAliasInput
	aliasErr   error
}

func (f *fakeCreatorAPI) CreateKey(_ context.Context, in *awskms.CreateKeyInput, _ ...func(*awskms.Options)) (*awskms.CreateKeyOutput, error) {
	f.createInput = in
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createResp, nil
}

func (f *fakeCreatorAPI) CreateAlias(_ context.Context, in *awskms.CreateAliasInput, _ ...func(*awskms.Options)) (*awskms.CreateAliasOutput, error) {
	f.aliasInput = in
	if f.aliasErr != nil {
		return nil, f.aliasErr
	}
	return &awskms.CreateAliasOutput{}, nil
}

func newFakeCreator(arn string) *fakeCreatorAPI {
	return &fakeCreatorAPI{
		createResp: &awskms.CreateKeyOutput{
			KeyMetadata: &types.KeyMetadata{Arn: &arn},
		},
	}
}

func TestCreateKeyHappyPathWithoutAlias(t *testing.T) {
	arn := "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
	api := newFakeCreator(arn)

	got, err := createKeyWithClient(context.Background(), api, CreateKeyParams{})
	if err != nil {
		t.Fatalf("createKeyWithClient: %v", err)
	}
	if got != arn {
		t.Errorf("returned resource %q, want %q", got, arn)
	}
	if api.createInput.KeySpec != types.KeySpecRsa2048 {
		t.Errorf("KeySpec = %v, want RSA_2048", api.createInput.KeySpec)
	}
	if api.createInput.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		t.Errorf("KeyUsage = %v, want ENCRYPT_DECRYPT", api.createInput.KeyUsage)
	}
	if api.aliasInput != nil {
		t.Errorf("CreateAlias was called despite no --alias: %+v", api.aliasInput)
	}
}

func TestCreateKeyCreatesAliasWhenProvided(t *testing.T) {
	arn := "arn:aws:kms:us-east-1:111122223333:key/uuid"
	api := newFakeCreator(arn)

	if _, err := createKeyWithClient(context.Background(), api, CreateKeyParams{Alias: "my-app"}); err != nil {
		t.Fatalf("createKeyWithClient: %v", err)
	}
	if api.aliasInput == nil {
		t.Fatalf("CreateAlias was not called")
	}
	if api.aliasInput.AliasName == nil || *api.aliasInput.AliasName != "alias/my-app" {
		t.Errorf("AliasName = %v, want %q (note: prefix should be added automatically)", api.aliasInput.AliasName, "alias/my-app")
	}
	if api.aliasInput.TargetKeyId == nil || *api.aliasInput.TargetKeyId != arn {
		t.Errorf("TargetKeyId = %v, want %q", api.aliasInput.TargetKeyId, arn)
	}
}

func TestCreateKeyPreservesAliasPrefix(t *testing.T) {
	api := newFakeCreator("arn:aws:kms:::key/x")
	if _, err := createKeyWithClient(context.Background(), api, CreateKeyParams{Alias: "alias/already-prefixed"}); err != nil {
		t.Fatalf("createKeyWithClient: %v", err)
	}
	if *api.aliasInput.AliasName != "alias/already-prefixed" {
		t.Errorf("alias was double-prefixed: %q", *api.aliasInput.AliasName)
	}
}

func TestCreateKeyAliasFailureSurfacesARN(t *testing.T) {
	arn := "arn:aws:kms:::key/orphan"
	api := newFakeCreator(arn)
	api.aliasErr = errors.New("AlreadyExistsException")

	_, err := createKeyWithClient(context.Background(), api, CreateKeyParams{Alias: "my-app"})
	if err == nil || !strings.Contains(err.Error(), arn) {
		t.Errorf("alias error should mention the orphan ARN so users can clean up; got %v", err)
	}
}

func TestCreateKeyPropagatesAPIError(t *testing.T) {
	api := &fakeCreatorAPI{createErr: errors.New("LimitExceededException: customer-managed key quota")}
	_, err := createKeyWithClient(context.Background(), api, CreateKeyParams{})
	if err == nil || !strings.Contains(err.Error(), "LimitExceededException") {
		t.Errorf("expected API error, got %v", err)
	}
}

func TestCreateKeyThroughInjectedClient(t *testing.T) {
	arn := "arn:aws:kms:us-west-2:123456789012:key/injected"
	api := newFakeCreator(arn)
	var gotRegion string
	prev := newCreatorClient
	newCreatorClient = func(_ context.Context, region string) (creatorAPI, error) {
		gotRegion = region
		return api, nil
	}
	t.Cleanup(func() { newCreatorClient = prev })

	got, err := CreateKey(context.Background(), CreateKeyParams{Region: "us-west-2", Alias: "my-app"})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if got != arn {
		t.Errorf("CreateKey returned %q, want %q", got, arn)
	}
	if gotRegion != "us-west-2" {
		t.Errorf("region passed to client constructor = %q, want us-west-2", gotRegion)
	}
}

func TestCreateKeyClientConstructionError(t *testing.T) {
	prev := newCreatorClient
	newCreatorClient = func(context.Context, string) (creatorAPI, error) {
		return nil, errors.New("no credentials")
	}
	t.Cleanup(func() { newCreatorClient = prev })

	if _, err := CreateKey(context.Background(), CreateKeyParams{}); err == nil {
		t.Error("expected client-construction error")
	}
}
