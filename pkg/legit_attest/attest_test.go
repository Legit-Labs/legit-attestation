package legit_attest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	privateKeyB64 = `LS0tLS1CRUdJTiBFTkNSWVBURUQgQ09TSUdOIFBSSVZBVEUgS0VZLS0tLS0KZXlKclpHWWlPbnNpYm1GdFpTSTZJbk5qY25sd2RDSXNJbkJoY21GdGN5STZleUpPSWpvek1qYzJPQ3dpY2lJNgpPQ3dpY0NJNk1YMHNJbk5oYkhRaU9pSnlRbWR4U0hSSlUwSldjR1pzZVVGeFVWbFFOR3BzWkV4Tk0xSm5RbXRyCk1ERndZVzEzU0hWbkswRlZQU0o5TENKamFYQm9aWElpT25zaWJtRnRaU0k2SW01aFkyd3ZjMlZqY21WMFltOTQKSWl3aWJtOXVZMlVpT2lKb09IbHZNWFZuTjBONlYyWkNPSGRGYVdSMGEwcDJkR3hITVVveFkzVndSQ0o5TENKagphWEJvWlhKMFpYaDBJam9pYVdwbVNuSmpXbFJGWkhVMWJrNVZabVZOVVcxdk1HMUhSa1p2TkdveFpXcHNhaXRVClExVnpXRWxOYVd0SmMyRnplbWxVVlhsblNEbGhSbTlZZUdOVWJtNWhUalZhTW13MVkyZE1WWFJpV0V4UVoySXYKYkROaFpXNTJaMDA0T0c1SVFtbHZOV05zTDA5elRtRXpReTlDYmpodE1YbFFNaXRXZW5WQ2FVWjNNRVJUT0dsNApTM0phT0V0eWIyTTRhVmRVVjFoc2JsTklaMVYzWkRsMVNsWldZbTVCUWtWeGVXOWlUVkpqUlM5MFRXbHRSVXhxClRrYzNaMFpGT0VGNVdIQnBia1oyWW1sQ1RWQnpVV2h0ZWtFOVBTSjkKLS0tLS1FTkQgRU5DUllQVEVEIENPU0lHTiBQUklWQVRFIEtFWS0tLS0tCg==`
	publicKeyB64  = `LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFRk5VNEcrTG1vMks2NWVrNlNpTW9oSU53OW5lNgovbTczTk1rREQ3dnJ5UE51SS9qNnZtd1I5cUpUNnRNcTNweitJZmpDb3NnMmlsa21mUHJLU1dXbHhRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==`
)

type PayloadData struct {
	A string
	B int
}

func makePrivateKeyPath(t *testing.T) (path string, cleaner func()) {
	key, err := base64.StdEncoding.DecodeString(privateKeyB64)
	require.Nil(t, err, "failed to decode hard-coded private key")

	path, cleaner, err = KeyPathFromKey(key)
	require.Nil(t, err, "failed to get private key path")

	return path, cleaner
}

func makePayload(t *testing.T) []byte {
	p := PayloadData{
		A: "hello",
		B: 5,
	}

	res, err := json.Marshal(p)
	require.Nil(t, err, "failed to make payload")

	return res
}

func TestBasic(t *testing.T) {
	ctx := context.Background()
	payload := makePayload(t)
	keyPath, cleaner := makePrivateKeyPath(t)
	defer cleaner()

	attestation, err := Attest(ctx, keyPath, payload)
	require.Nil(t, err, "failed to attest")
	require.NotNil(t, attestation, "got a nil attestation")

}
