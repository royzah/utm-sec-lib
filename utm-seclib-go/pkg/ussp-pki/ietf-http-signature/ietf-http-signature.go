package ietf_http_signature

import (
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

	privateKey, err := ussp_pki.LoadPrivateKeyFromFile(privateKeyPem)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %v", err)
	}

	signature, err := ussp_pki.SignDataWithPrivateKey(privateKey, []byte(signatureBase))
	if err != nil {
		return "", fmt.Errorf("failed to create signature: %v", err)
	}

	return fmt.Sprintf("sig1=:%s:", signature), nil
}

func ValidateSignatureBase(signatureBase string) error {
	if signatureBase == "" {
		return fmt.Errorf("signature input cannot be empty")
	}

	if !findOnlyOneSignatureParamsList(signatureBase) {
		return fmt.Errorf("signature input does not contain signature params")
	}

	re := regexp.MustCompile(`"@signature-params": \((".+")\)`)

	subMatches := re.FindStringSubmatch(signatureBase)

	if len(subMatches) != 2 {
		return fmt.Errorf("signature input does not contain signature params")
	}

	expectedParameters := strings.Split(subMatches[1], " ")

	paramValidationErr := validateSignatureParams(expectedParameters, signatureBase)
	if paramValidationErr != nil {
		return paramValidationErr
	}

	re = regexp.MustCompile(`created=\d+;keyid=\"\S+\";alg=\"\S+\"`)
	subMatches = re.FindStringSubmatch(signatureBase)

	if len(subMatches) != 1 {
		return fmt.Errorf("signature input does not contain signature metadata")
	}

	return nil
}

func validateSignatureParams(expectedParameters []string, signatureBase string) error {
	for _, param := range expectedParameters {

		regStr := fmt.Sprintf(`%s:( .+)\n`, param)

		paramRegex := regexp.MustCompile(regStr)

		paramMatches := paramRegex.FindStringSubmatch(signatureBase)

		if len(paramMatches) != 2 {
			return fmt.Errorf("signature parameter %s does not have a valid value: \"<sig param name>\": <value>\"", param)
		}

	}
	return nil
}

func findOnlyOneSignatureParamsList(signatureBase string) bool {
	return strings.Count(signatureBase, "\"@signature-params\": (") == 1
}

func VerifySignature(publicKeyPem string, signature string, signatureBase string) bool {
	if publicKeyPem == "" {
		panic("Public key cannot be null or empty")
	}

	if signature == "" {
		panic("Signature cannot be null or empty")
	}

	if signatureBase == "" {
		panic("Signature base cannot be null or empty")
	}

	if err := ValidateSignatureBase(signatureBase); err != nil {
		panic(fmt.Sprintf("Invalid signature base: %v", err))
	}

	parts := strings.Split(signature, ":")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "sig1=") {
		panic("Invalid signature format")
	}
	signatureValue := parts[1]

	err := ussp_pki.VerifyWithPublicKey(publicKeyPem, signatureValue, []byte(signatureBase))
	if err != nil {
		panic(fmt.Sprintf("Error verifying signature: %v", err))
	}

	return true
}
