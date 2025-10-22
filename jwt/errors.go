package jwt

import "errors"

var (
	ErrMalformedToken     = errors.New("malformed JWT token")
	ErrInvalidSignature   = errors.New("invalid JWT signature")
	ErrTokenExpired       = errors.New("JWT token expired")
	ErrTokenNotYetValid   = errors.New("JWT token not yet valid")
	ErrInvalidIssuer      = errors.New("invalid JWT issuer")
	ErrInvalidAudience    = errors.New("invalid JWT audience")
	ErrInvalidAlgorithm   = errors.New("invalid JWT algorithm")
	ErrInvalidTokenType   = errors.New("invalid token type")
	ErrMissingPublicKey   = errors.New("missing public key")
	ErrInvalidClaims      = errors.New("invalid JWT claims")
)
