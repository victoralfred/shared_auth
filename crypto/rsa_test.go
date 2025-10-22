package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerifyRSA(t *testing.T) {
	// Load test keys
	privateKey, err := LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "sign and verify valid data",
			data:    []byte("Hello, World!"),
			wantErr: false,
		},
		{
			name:    "sign and verify empty data",
			data:    []byte(""),
			wantErr: false,
		},
		{
			name:    "sign and verify large data",
			data:    []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " + string(make([]byte, 1000))),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign data
			signature, err := SignRSA(tt.data, privateKey)
			require.NoError(t, err)
			assert.NotNil(t, signature)
			assert.NotEmpty(t, signature)

			// Verify signature
			err = VerifyRSA(tt.data, signature, publicKey)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyRSAWithWrongSignature(t *testing.T) {
	publicKey, err := LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	data := []byte("Hello, World!")
	wrongSignature := []byte("this is not a valid signature")

	err = VerifyRSA(data, wrongSignature, publicKey)
	assert.Error(t, err)
}

func TestVerifyRSAWithModifiedData(t *testing.T) {
	privateKey, err := LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	originalData := []byte("Hello, World!")
	signature, err := SignRSA(originalData, privateKey)
	require.NoError(t, err)

	// Modify data after signing
	modifiedData := []byte("Hello, World! Modified")

	// Verification should fail
	err = VerifyRSA(modifiedData, signature, publicKey)
	assert.Error(t, err)
}
