// Package aws implements the pkg/kms provider interfaces for AWS KMS.
//
// Importing this package registers AWS with the kms provider registry via init():
//
//	import _ "github.com/rubysolo/envisible/pkg/kms/aws"
//
// Authentication uses the AWS SDK's default credential chain — environment vars,
// shared config, EC2 IMDS, IRSA in EKS, SSO, etc. No envisible-specific config.
package aws

import (
	"context"
	"fmt"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/rubysolo/envisible/pkg/kms"
)

func init() {
	kms.RegisterUnwrapper(kms.AWS, newUnwrapper)
	kms.RegisterBootstrap(kms.AWS, fetchPublicKey)
}

// kmsAPI is the subset of *awskms.Client we depend on. Exposed as an interface
// so tests can substitute a fake without depending on SDK mock churn.
type kmsAPI interface {
	Decrypt(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
	GetPublicKey(ctx context.Context, params *awskms.GetPublicKeyInput, optFns ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
}

// newKMSClient builds the read-path SDK client. It's a package var rather than
// a direct call so tests can inject a fake and exercise newUnwrapper/fetchPublicKey
// end-to-end without live AWS credentials.
var newKMSClient = func(ctx context.Context) (kmsAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws kms: load default config: %w", err)
	}
	return awskms.NewFromConfig(cfg), nil
}

func newUnwrapper(ctx context.Context, info *kms.PublicKeyInfo) (kms.Unwrapper, error) {
	client, err := newKMSClient(ctx)
	if err != nil {
		return nil, err
	}
	return newUnwrapperWithClient(client, info.Resource), nil
}

func newUnwrapperWithClient(client kmsAPI, resource string) *unwrapper {
	return &unwrapper{client: client, resource: resource}
}

type unwrapper struct {
	client   kmsAPI
	resource string
}

func (u *unwrapper) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	// KeyId is required even for asymmetric keys whose ciphertext is self-identifying
	// — AWS uses it to short-circuit if the caller has the wrong key in mind.
	resp, err := u.client.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob:      wrapped,
		KeyId:               awsv2.String(u.resource),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: decrypt: %w", err)
	}
	return resp.Plaintext, nil
}

func fetchPublicKey(ctx context.Context, resource string) (*kms.PublicKeyInfo, error) {
	client, err := newKMSClient(ctx)
	if err != nil {
		return nil, err
	}
	return fetchPublicKeyWithClient(ctx, client, resource)
}

func fetchPublicKeyWithClient(ctx context.Context, client kmsAPI, resource string) (*kms.PublicKeyInfo, error) {
	resp, err := client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: awsv2.String(resource)})
	if err != nil {
		return nil, fmt.Errorf("aws kms: get public key: %w", err)
	}
	if resp.KeySpec != types.KeySpecRsa2048 {
		return nil, fmt.Errorf("aws kms: unsupported key spec %q (expected RSA_2048)", resp.KeySpec)
	}
	if resp.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("aws kms: unsupported key usage %q (expected ENCRYPT_DECRYPT)", resp.KeyUsage)
	}
	if !containsAlgorithm(resp.EncryptionAlgorithms, types.EncryptionAlgorithmSpecRsaesOaepSha256) {
		return nil, fmt.Errorf("aws kms: key does not advertise RSAES_OAEP_SHA_256 (got %v)", resp.EncryptionAlgorithms)
	}
	pub, err := kms.ParseRSAPublicKeyDER(resp.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.PublicKeyInfo{
		Kind:     kms.AWS,
		Resource: resource,
		Alg:      kms.RSAOAEPSHA256_2048,
		PubKey:   pub,
	}, nil
}

func containsAlgorithm(algs []types.EncryptionAlgorithmSpec, want types.EncryptionAlgorithmSpec) bool {
	for _, a := range algs {
		if a == want {
			return true
		}
	}
	return false
}
