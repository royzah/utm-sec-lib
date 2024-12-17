package ussp_pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKResponse struct {
	Keys []JWK `json:"keys"`
}

// GetJWKFromPublicKey expects
// Arguments:
//
//	*publicKey: a pointer to either an rsa or an ecdsa public key
//	keyID: the id label for the public key
func GetJwkFromPublicKey(publicKey interface{}, keyID string) (*JWK, error) {

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		eInt64 := int64(key.E)
		eBigInt := big.NewInt(eInt64)

		if eBigInt == nil {
			return nil, fmt.Errorf("could not create NewInt from %v", eInt64)
		}

		jwk := &JWK{
			Alg: "PS512",
			Kty: "RSA",
			Kid: keyID,
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBigInt.Bytes()),
		}
		return jwk, nil

	case *ecdsa.PublicKey:
		jwk := &JWK{
			Alg: "ES512",
			Kty: "EC",
			Kid: keyID,
			X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		}
		return jwk, nil

	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

func BuildJWKResponse(publicKeys map[string]JWK) (*JWKResponse, error) {
	jwkArray := make([]JWK, 0)

	for _, jwk := range publicKeys {

		jwkArray = append(jwkArray, jwk)
	}

	sort.Slice(jwkArray, func(i int, j int) bool {
		return jwkArray[i].Alg <= jwkArray[j].Alg
	})

	response := map[string]interface{}{
		"keys": jwkArray,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}

	var jwkResponse JWKResponse

	err = json.Unmarshal(responseBytes, &jwkResponse)
	if err != nil {
		return nil, err
	}

	return &jwkResponse, nil
}
