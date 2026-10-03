# pkg/kms testdata

**A failing golden test means the format changed. Fix the code, never the fixture.**

## `envisible.pub.v2.golden`

A v2 (KMS-backed) `envisible.pub` descriptor exactly as `kms.WritePublicKey` wrote it at
tag `v0.0.5` (`9eec89c`), the first release with the v2 format. Projects have files like it
committed, so every later release has to keep loading it.
`TestLoadPublicKeyGoldenV2Descriptor` asserts the exact `Kind`, `Resource`, `Alg` and RSA
modulus it loads to.

Only the public half of the key exists; the private half was discarded when the generator
exited. The resource names no real cloud key.

### How it was generated

Not committed as code, so it cannot drift along with the package it is meant to pin. In a
throwaway module outside the repo, with `v0.0.5` extracted next to it
(`git archive v0.0.5 | tar -x -C ../v005`):

```
module gen

go 1.25.0

require github.com/rubysolo/envisible v0.0.5

replace github.com/rubysolo/envisible => ../v005
```

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/kms"
)

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	info := &kms.PublicKeyInfo{
		Kind:     kms.GCP,
		Resource: "projects/envisible-golden/locations/us/keyRings/golden/cryptoKeys/golden/cryptoKeyVersions/1",
		Alg:      kms.RSAOAEPSHA256_2048,
		PubKey:   &priv.PublicKey,
	}
	if err := kms.WritePublicKey(os.Args[1], info); err != nil {
		panic(err)
	}
	fmt.Printf("E=%d\nN=%x\n", priv.PublicKey.E, priv.PublicKey.N)
}
```

`go run . envisible.pub.v2.golden` writes the file and prints the modulus recorded in
`goldenDescriptorModulus` in `kms_test.go`. The key is random, so a re-run produces a
different fixture; there is no reason to re-run it.
