# Wire-format exemplars

**A failing exemplar test means the wire format changed; fix the code, never the
exemplar. Add a new exemplar only alongside a new format version.**

These files are ciphertext written by old releases of envisible, plus the fixed
keys that open it. `exemplar_test.go` decrypts them on every `go test ./...`,
which is the only test in the repo that holds bytes today's encoder did not
produce. Every other test encrypts and decrypts with the same build, so a change
that moves the encoder and the decoder together passes all of them and strands
every file ever committed.

| file | what it is |
|------|------------|
| `exemplars.env` | one `v1:` marker written by `v0.0.1` (c7038ff) and one `v2:` marker written by `v0.0.5` (9eec89c) |
| `exemplar_v1.key` | the NaCl private key the v1 marker is sealed to (base64, as `keygen` writes it) |
| `exemplar_v2_rsa.pem` | the RSA-2048 private key (PKCS#8) the v2 data key is wrapped to; it stands in for a cloud KMS key |

The keys are test-only. They were generated for this directory, have never
protected anything, and are the only `*.key` / `*.pem` / `*.env` files exempted
from the repo's `.gitignore`.

## Never regenerate

One exemplar per format *version*, not per release: `pkg/crypto/crypto.go` is
byte-identical from `v0.0.1` through `v0.0.7`, so a second v1 exemplar would be
the same evidence twice. Each one comes from the **first release that wrote that
format**, which makes it evidence about files in the wild rather than a
restatement of today's code. Regenerating one with the current tree would
destroy exactly that property. If a `v3:` format is ever introduced, add its
exemplar next to these two in the same change, and leave these alone.

## Plaintexts

Both values carry a NUL, multi-byte UTF-8, a `]`, a `[` and a newline, so
decrypting them also exercises today's output escaping. As Go string literals:

```go
"v1 exemplar: nul=\x00 utf8=héllo-日本語 bracket=a]b[c\nsecond line"
"v2 exemplar: nul=\x00 utf8=héllo-日本語 bracket=a]b[c\nsecond line"
```

## How they were produced

Each tag was extracted with `git archive <tag> | tar -x -C <dir>` and a
throwaway module outside the repo pointed at it with a `replace` directive, so
the encoder that ran is the tagged source and nothing else. The generators call
the encryptors directly rather than the CLI: both tags predate the marker
scanner, so their CLIs cannot express a plaintext containing `]` or a newline.
The ciphertext is the same either way.

Each generator printed the marker inner (`v1:...` / `v2:...`); the surrounding
`NAME=` and marker brackets in `exemplars.env` were added around that output
unchanged. The generators are recorded here and deliberately not committed as
code. Built with go1.27.1.

### v1, from `v0.0.1`

```
module exemplargen

go 1.24.0

require github.com/rubysolo/envisible v0.0.1

require (
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
)

replace github.com/rubysolo/envisible => ../v001
```

```go
// Generates the v1 exemplar with envisible v0.0.1's own encoder.
package main

import (
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/crypto"
)

const plaintext = "v1 exemplar: nul=\x00 utf8=héllo-日本語 bracket=a]b[c\nsecond line"

func main() {
	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		panic(err)
	}
	ct, err := crypto.Encrypt([]byte(plaintext), pub)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("exemplar_v1.key", []byte(crypto.EncodeKey(priv)), 0o600); err != nil {
		panic(err)
	}
	// The marker inner: the version prefix plus the encoder's base64 output.
	fmt.Println("v1:" + ct)
}
```

### v2, from `v0.0.5`

```
module exemplargen

go 1.25.0

require github.com/rubysolo/envisible v0.0.5

require (
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace github.com/rubysolo/envisible => ../v005
```

```go
// Generates the v2 exemplar with envisible v0.0.5's own encoder.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/processor"
)

const plaintext = "v2 exemplar: nul=\x00 utf8=héllo-日本語 bracket=a]b[c\nsecond line"

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile("exemplar_v2_rsa.pem", keyPEM, 0o600); err != nil {
		panic(err)
	}
	// kms.NewRSAWrapper is the RSA-OAEP-SHA256 wrapper every provider shares.
	enc := processor.NewEnvelopeEncryptor(kms.NewRSAWrapper(&priv.PublicKey))
	inner, err := enc.EncryptValue([]byte(plaintext))
	if err != nil {
		panic(err)
	}
	// EncryptValue already returns the full marker inner, "v2:" included.
	fmt.Println(inner)
}
```

## One-time cross-check against `v0.0.7`

`pkg/processor/processor.go` changed between `v0.0.5` and `v0.0.7`, so when the
exemplars were generated they were also decrypted with `v0.0.7` (01bf6de), the
last release before the marker scanner:

- the `v0.0.7` binary, `envisible decrypt --key exemplar_v1.key`, recovered the
  v1 plaintext;
- `v0.0.7`'s `CompositeDecryptor{NaclDecryptor, EnvelopeDecryptor}`, driven from
  a scratch module with an RSA-OAEP-SHA256 unwrapper over `exemplar_v2_rsa.pem`,
  recovered both. The v2 half could not go through the binary: its CLI only
  unwraps through a cloud KMS.
