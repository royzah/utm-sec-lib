package ietf_http_signature

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func CreateContentDigest(jsonString string) (string, error) {
	// Parse the JSON to validate it and normalize it
	var jsonData interface{}
	if err := json.Unmarshal([]byte(jsonString), &jsonData); err != nil {
		return "", fmt.Errorf("invalid JSON input: %v", err)
	}

	// Re-encode the JSON with consistent formatting
	formattedJson, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to format JSON: %v", err)
	}

	// Create SHA-512 hash
	hash := sha512.New()
	hash.Write(formattedJson)
	hashedBytes := hash.Sum(nil)

	// Convert to base64
	base64Hash := base64.StdEncoding.EncodeToString(hashedBytes)

	return fmt.Sprintf("sha-512=:%s:", base64Hash), nil
}

func VerifyContentDigest(body string, contentDigestHeader *string) bool {
	if contentDigestHeader == nil || *contentDigestHeader == "" {
		panic("Content-Digest header is missing")
	}

	computedDigest, err := CreateContentDigest(body)
	if err != nil {
		panic(err.Error())
	}

	return computedDigest == *contentDigestHeader
}
