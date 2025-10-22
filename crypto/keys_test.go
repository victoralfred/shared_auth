package crypto

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPublicKeyFromFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid public key",
			path:    "../testdata/jwt-public.pem",
			wantErr: false,
		},
		{
			name:    "file not found",
			path:    "../testdata/nonexistent.pem",
			wantErr: true,
		},
		{
			name:    "invalid file",
			path:    "../testdata/invalid.pem",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadPublicKeyFromFile(tt.path)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
				assert.NotNil(t, key.N)
				assert.NotNil(t, key.E)
			}
		})
	}
}

func TestLoadPrivateKeyFromFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid private key",
			path:    "../testdata/jwt-private.pem",
			wantErr: false,
		},
		{
			name:    "file not found",
			path:    "../testdata/nonexistent.pem",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadPrivateKeyFromFile(tt.path)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
				assert.NotNil(t, key.D)
				assert.NotNil(t, key.Primes)
			}
		})
	}
}

func TestLoadPublicKeyFromEnv(t *testing.T) {
	// Read test public key
	pubKeyData, err := os.ReadFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	tests := []struct {
		name    string
		envVar  string
		envVal  string
		wantErr bool
	}{
		{
			name:    "valid env var",
			envVar:  "TEST_PUBLIC_KEY",
			envVal:  string(pubKeyData),
			wantErr: false,
		},
		{
			name:    "empty env var",
			envVar:  "NONEXISTENT_KEY",
			envVal:  "",
			wantErr: true,
		},
		{
			name:    "invalid pem data",
			envVar:  "INVALID_KEY",
			envVal:  "not a valid pem",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.envVar, tt.envVal)
				defer os.Unsetenv(tt.envVar)
			}

			key, err := LoadPublicKeyFromEnv(tt.envVar)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestLoadPrivateKeyFromEnv(t *testing.T) {
	// Read test private key
	privKeyData, err := os.ReadFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	tests := []struct {
		name    string
		envVar  string
		envVal  string
		wantErr bool
	}{
		{
			name:    "valid env var",
			envVar:  "TEST_PRIVATE_KEY",
			envVal:  string(privKeyData),
			wantErr: false,
		},
		{
			name:    "empty env var",
			envVar:  "NONEXISTENT_KEY",
			envVal:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.envVar, tt.envVal)
				defer os.Unsetenv(tt.envVar)
			}

			key, err := LoadPrivateKeyFromEnv(tt.envVar)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	validPem, err := os.ReadFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	tests := []struct {
		name    string
		pemData []byte
		wantErr bool
	}{
		{
			name:    "valid public key PEM",
			pemData: validPem,
			wantErr: false,
		},
		{
			name:    "invalid PEM",
			pemData: []byte("not a pem"),
			wantErr: true,
		},
		{
			name:    "empty data",
			pemData: []byte(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePublicKey(tt.pemData)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	validPem, err := os.ReadFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	tests := []struct {
		name    string
		pemData []byte
		wantErr bool
	}{
		{
			name:    "valid private key PEM",
			pemData: validPem,
			wantErr: false,
		},
		{
			name:    "invalid PEM",
			pemData: []byte("not a pem"),
			wantErr: true,
		},
		{
			name:    "empty data",
			pemData: []byte(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKey(tt.pemData)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}
