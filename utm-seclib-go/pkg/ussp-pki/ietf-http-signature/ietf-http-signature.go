package ietf_http_signature

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	ussp_pki "utm-pki/pkg/ussp-pki"
)

func CreateSignature(signatureBase string, privateKeyPem string) (string, error) {
	if privateKeyPem == "" {
		return "", fmt.Errorf("private key cannot be empty")
	}

	if signatureBase == "" {
		return "", fmt.Errorf("signature base cannot be empty")
	}

	privateKey, err := ussp_pki.LoadPrivateKeyFromPEM(privateKeyPem)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %v", err)
	}

	signatureBytes := []byte(signatureBase)
	signature, err := ussp_pki.SignDataWithPrivateKey(privateKey, signatureBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create signature: %v", err)
	}

	return fmt.Sprintf("sig1=:%s:", signature), nil
}

func ValidateSignatureBase(signatureBase string) error {

	if signatureBase == "" {
		return fmt.Errorf("signature base cannot be empty")
	}

	if !strings.Contains(signatureBase, "\"@method\"") ||
		!strings.Contains(signatureBase, "\"@authority\"") ||
		!strings.Contains(signatureBase, "\"@target-uri\"") {
		return fmt.Errorf("signature base missing required components")
	}

	paramsMatch := regexp.MustCompile(`"@signature-params": \((.+?)\);`).FindStringSubmatch(signatureBase)
	if len(paramsMatch) != 2 {
		return fmt.Errorf("invalid signature params format")
	}

	params := strings.Split(paramsMatch[1], " ")
	for _, param := range params {
		param = strings.Trim(param, `"`)
		if !strings.Contains(signatureBase, fmt.Sprintf(`"%s":`, param)) {
			return fmt.Errorf("missing parameter value for %s", param)
		}
	}

	if !regexp.MustCompile(`created=\d+;keyid="[^"]+";alg="[^"]+"$`).MatchString(signatureBase) {
		return fmt.Errorf("invalid metadata format")
	}

	return nil
}

func VerifySignature(publicKeyPem string, signature string, signatureBase string) bool {
	if publicKeyPem == "" || signature == "" || signatureBase == "" {
		fmt.Printf("ERROR: Missing required parameters\n")
		return false
	}

	publicKeyPem = strings.ReplaceAll(publicKeyPem, "\r\n", "\n")

	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		fmt.Printf("ERROR: Failed to decode PEM block\n")
		return false
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("ERROR: Failed to parse public key: %v\n", err)
		return false
	}

	signatureValue := extractSignatureValue(signature)
	if signatureValue == "" {
		fmt.Printf("ERROR: Invalid signature format\n")
		return false
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		fmt.Printf("ERROR: Failed to decode signature: %v\n", err)
		return false
	}

	return ussp_pki.VerifyWithPublicKey(publicKey, signatureBytes, []byte(signatureBase))
}

func extractSignatureValue(signature string) string {
	if strings.Contains(signature, ":") {
		parts := strings.Split(signature, ":")
		if len(parts) != 3 || !strings.HasPrefix(parts[0], "sig1=") {
			return ""
		}
		return parts[1]
	}
	return signature
}
