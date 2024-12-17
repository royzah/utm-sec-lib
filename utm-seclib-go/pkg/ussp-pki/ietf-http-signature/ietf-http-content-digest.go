package ietf_http_signature

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

func CreateContentDigest(jsonString string) (string, error) {

	var parsedData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonString), &parsedData); err != nil {
		return "", fmt.Errorf("invalid JSON input: %v", err)
	}

	formattedJson, err := json.Marshal(parsedData)
	if err != nil {
		return "", fmt.Errorf("failed to format JSON: %v", err)
	}

	// Create SHA-512 hash
	hash := sha512.New()
	hash.Write(formattedJson)
	hashedBytes := hash.Sum(nil)

	// Convert to base64
	base64Hash := base64.StdEncoding.EncodeToString(hashedBytes)
	digest := fmt.Sprintf("sha-512=:%s:", base64Hash)

	return digest, nil
}

func VerifyContentDigest(body string, contentDigestHeader *string) bool {
	if contentDigestHeader == nil || *contentDigestHeader == "" {
		log.Printf("ERROR: Content-Digest header is missing")
		return false
	}

	hash := sha512.New()
	hash.Write([]byte(body))
	hashedBytes := hash.Sum(nil)

	base64Hash := base64.StdEncoding.EncodeToString(hashedBytes)
	computedDigest := fmt.Sprintf("sha-512=:%s:", base64Hash)

	matches := computedDigest == *contentDigestHeader

	return matches
}
