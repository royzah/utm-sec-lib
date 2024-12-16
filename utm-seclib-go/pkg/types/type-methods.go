package types

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func (header *JWSHeader) Base64() string {

	headerJson := fmt.Sprintf(`{
		"alg": "%s",
		"typ": "%s"
	}`, header.Alg, header.Typ)

	headerBase64 := base64.URLEncoding.EncodeToString([]byte(headerJson))
	if headerBase64 == "" {
		fmt.Printf("Could not encode header to base64 string")
		return ""
	}

	return headerBase64
}

func (jwsSignature *JWSSignature) Formatted() string {
	return fmt.Sprintf("%s.%s.%s", jwsSignature.Header, jwsSignature.Body, jwsSignature.Signature)
}

func NewJWSSignature(header string, body string, signature string) *JWSSignature {
	return &JWSSignature{
		Header:    header,
		Body:      body,
		Signature: signature,
	}
}

func NewJWSSignatureFromString(jwsSignatureString string) (*JWSSignature, error) {
	dotCount := strings.Count(jwsSignatureString, ".")
	if dotCount < 2 {
		return nil, fmt.Errorf("invalid JWS Signature string")
	}

	parts := strings.Split(jwsSignatureString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWS Signature parsing failed")
	}

	return &JWSSignature{
		Header:    parts[0],
		Body:      parts[1],
		Signature: parts[2],
	}, nil
}

func (jwsSignature *JWSSignature) GetJWSInput() string {
	jwsInputString := fmt.Sprintf("%s.%s", jwsSignature.Header, jwsSignature.Body)

	return jwsInputString
}

func (s SignatureBase) FormatAttributes() string {
	var contentDigest string = ""

	if s.Method == "POST" && s.ContentDigest != "" {
		contentDigest = fmt.Sprintf("`content-digest`: %s", s.ContentDigest)
	}

	attributes := []string{
		fmt.Sprintf("`@method`: %s", s.Method),
		fmt.Sprintf("`@authority`: %s", s.Authority),
		fmt.Sprintf("`@target-uri`: %s", s.TargetURI),
		contentDigest,
		fmt.Sprintf("`alg`: %s", s.Algorithm),
		fmt.Sprintf("`keyid`: %s", s.KeyID),
	}

	return strings.Join(attributes, "\n")
}
