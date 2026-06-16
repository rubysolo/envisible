package aws

import (
	"context"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// CreateKeyParams holds the AWS-specific fields needed to provision a new key.
// Both Region and Alias are optional: Region falls back to the SDK config chain,
// and Alias is skipped when empty (the key is still usable by its ARN).
type CreateKeyParams struct {
	Region string
	Alias  string
}

// creatorAPI is the slice of *awskms.Client that CreateKey uses. Distinct from
// the read-path kmsAPI so create tests don't have to stub unused methods.
type creatorAPI interface {
	CreateKey(ctx context.Context, params *awskms.CreateKeyInput, optFns ...func(*awskms.Options)) (*awskms.CreateKeyOutput, error)
	CreateAlias(ctx context.Context, params *awskms.CreateAliasInput, optFns ...func(*awskms.Options)) (*awskms.CreateAliasOutput, error)
}

// CreateKey provisions an asymmetric RSA-2048 KMS key with KeyUsage=ENCRYPT_DECRYPT
// and returns its ARN. If Alias is set, a matching `alias/<name>` is also created.
// newCreatorClient builds the provisioning-path SDK client. As with
// newKMSClient, it's a package var so tests can inject a fake and cover
// CreateKey's region handling without live AWS credentials.
var newCreatorClient = func(ctx context.Context, region string) (creatorAPI, error) {
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws kms: load default config: %w", err)
	}
	return awskms.NewFromConfig(cfg), nil
}

func CreateKey(ctx context.Context, p CreateKeyParams) (string, error) {
	client, err := newCreatorClient(ctx, p.Region)
	if err != nil {
		return "", err
	}
	return createKeyWithClient(ctx, client, p)
}

func createKeyWithClient(ctx context.Context, client creatorAPI, p CreateKeyParams) (string, error) {
	resp, err := client.CreateKey(ctx, &awskms.CreateKeyInput{
		KeySpec:     types.KeySpecRsa2048,
		KeyUsage:    types.KeyUsageTypeEncryptDecrypt,
		Description: awsv2.String("envisible asymmetric envelope key"),
	})
	if err != nil {
		return "", fmt.Errorf("aws kms: create key: %w", err)
	}
	if resp.KeyMetadata == nil || resp.KeyMetadata.Arn == nil {
		return "", fmt.Errorf("aws kms: CreateKey returned no ARN")
	}
	arn := *resp.KeyMetadata.Arn

	if p.Alias != "" {
		alias := p.Alias
		if !strings.HasPrefix(alias, "alias/") {
			alias = "alias/" + alias
		}
		if _, err := client.CreateAlias(ctx, &awskms.CreateAliasInput{
			AliasName:   awsv2.String(alias),
			TargetKeyId: awsv2.String(arn),
		}); err != nil {
			return "", fmt.Errorf("aws kms: create alias %q (key was created at %s): %w", alias, arn, err)
		}
	}
	return arn, nil
}
