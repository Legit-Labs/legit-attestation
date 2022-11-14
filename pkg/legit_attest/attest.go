package legit_attest

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func Attest(ctx context.Context, keyRef string, payload []byte) ([]byte, error) {
	sv, err := signature.SignerVerifierFromKeyRef(ctx, keyRef, nil)
	if err != nil {
		return nil, err
	}

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return signedPayload, nil
}

func KeyPathFromKey(key []byte) (path string, cleaner func(), err error) {
	keyFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create a temporary file for key: %v", err)
	}
	path = keyFile.Name()
	cleaner = func() {
		os.Remove(path)
	}

	if _, err = keyFile.Write([]byte(key)); err != nil {
		_ = keyFile.Close()
		cleaner()
		return "", nil, err
	}

	_ = keyFile.Close()
	return path, cleaner, nil
}
