# Plan 09 — AWS: take the region from the key ARN

**Kind:** correctness fix (production change)
**Status:** proposed
**Depends on:** nothing (see the coupling note in plan 08)

---

## Problem

The AWS read path builds its SDK client with no region:

```go
// pkg/kms/aws/aws.go:38-44
var newKMSClient = func(ctx context.Context) (kmsAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	...
	return awskms.NewFromConfig(cfg), nil
}
```

The region therefore comes entirely from the ambient SDK chain (`AWS_REGION`,
`AWS_DEFAULT_REGION`, the active profile). Nothing reads the region that is *already in the
resource*: `kms create` writes the key ARN to `envisible.pub`, and the README tells users to
pass a full ARN to `kms init` (*"full ARN or alias ARN both work"*,
`arn:aws:kms:us-east-1:...`). KMS keys are regional; a request must go to the key's region.

### Evidence

Verified offline against the real SDK (no network): with no region in the environment and
a full `eu-west-1` key ARN, `Decrypt` fails before sending anything:

```
operation error KMS: Decrypt, failed to resolve service endpoint, endpoint rule error,
Invalid Configuration: Missing Region
```

With `AWS_REGION` set to a *different* region, the request is sent to that region's
endpoint, where the key does not exist. That half is inferred from how the SDK resolves
endpoints, not tested live.

Neither case is caught by the suite: every AWS test injects a fake through `newKMSClient`,
and `TestDefaultClientConstructorsAreOffline` only checks the constructor returns non-nil.
The README's AWS section never mentions that a region must be configured.

Who hits this: a developer whose default profile points at another region, any CI runner
or container without `AWS_REGION` set, and anyone with keys in more than one region (only
one can be the ambient default).

---

## Goals

1. A resource that is an ARN carries its own region. Decrypt and `kms init` work with no
   region configured, and with a different region configured.
2. A resource with no region in it (a bare key ID, `alias/name`) keeps today's behavior.
3. No change to `envisible.pub` or to any marker.

### Non-goals

- Cross-account access changes. The ARN's account is already honored by KMS.
- Changing `kms create`, which already takes `--region` and writes an ARN.

---

## Design

### Parse the region out of the resource

```go
// regionFromResource returns the region embedded in an ARN-form resource
// (arn:<partition>:kms:<region>:<account>:key/<id> or :alias/<name>),
// or "" for a bare key ID or alias name.
func regionFromResource(resource string) string
```

Split on `:` with a limit of 6; require `parts[0] == "arn"` and `parts[2] == "kms"`; return
`parts[3]`. Handle every partition (`aws`, `aws-cn`, `aws-us-gov`), since the region
field is the same position in all of them. Anything that doesn't match returns `""`.

### Build the client for that region

Change the injection seam to take the resource, so the fake keeps working and the new
behavior is observable:

```go
var newKMSClient = func(ctx context.Context, resource string) (kmsAPI, error) {
	var opts []func(*config.LoadOptions) error
	if region := regionFromResource(resource); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	...
}
```

`newUnwrapper` passes `info.Resource`; `fetchPublicKey` passes `resource`. `config.WithRegion`
overrides the environment, which is the point: the ARN is authoritative.

This mirrors `pkg/kms/aws/create.go:37`, which already does exactly this for `--region`.

### Error message

When the resource has no region and the SDK still can't find one, the raw `Missing Region`
error is opaque. Wrap that case: *"aws kms: no region for resource %q — use the full key ARN,
or set AWS_REGION"*. Detect it by checking `cfg.Region == ""` after loading, before building
the client, rather than by matching SDK error text.

### Docs

README AWS section: one sentence saying the region is taken from the ARN, and a bare key ID
or alias name falls back to the standard SDK region settings. Change the `kms init` example
comment from "full ARN or alias ARN both work" to also recommend the ARN form for this
reason.

---

## Tests (`pkg/kms/aws/aws_test.go`)

- `regionFromResource` table: key ARN, alias ARN, `aws-cn` and `aws-us-gov` partitions, bare
  UUID, `alias/name`, an S3 ARN (wrong service → `""`), empty string, too few segments.
- The injected `newKMSClient` receives the resource (assert in an existing fake-backed test).
- **Real-SDK, offline:** with `AWS_REGION` unset, `AWS_CONFIG_FILE=/dev/null`,
  `AWS_SHARED_CREDENTIALS_FILE=/dev/null`, dummy static credentials and
  `AWS_EC2_METADATA_DISABLED=true`, call the real `newKMSClient` with an `eu-west-1` ARN and
  assert the returned client's `Options().Region == "eu-west-1"`. Repeat with
  `AWS_REGION=us-east-1` set: the ARN's region must still win. No request is sent.
- Bare key ID with no region anywhere → the wrapped error text above.

---

## Compatibility

Behavior changes only for ARN resources, and only where the ambient region differed from
the key's region or was missing — both cases that fail today. A user who deliberately set
`AWS_REGION` to reach a key through some non-ARN path is unaffected, because non-ARN
resources keep the ambient region.

---

## Done when

- [ ] Decrypt with an ARN resource works with `AWS_REGION` unset and with it set to another
      region (offline client-region assertion above).
- [ ] Bare key IDs and alias names behave exactly as before.
- [ ] README states where the region comes from.
