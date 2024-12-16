package ietf_http_signature

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"utm-pki/pkg/types"
)

func CreateSignatureBase(request *types.SignedRequest, keyID string, algorithm string) (string, error) {
	if request == nil || request.Headers["host"] == "" || !isSupportedMethod(request.Method) {
		return "", fmt.Errorf("invalid request")
	}

	coveredContent := types.SignatureCoveredContent{
		Authority:     request.Headers["host"],
		Method:        request.Method,
		TargetUri:     request.URL,
		ContentDigest: request.Headers["content-digest"],
	}

	signatureBase := GetCoveredContentAsString(coveredContent, keyID, algorithm)
	return signatureBase, nil
}

func GetCoveredContentAsString(content types.SignatureCoveredContent, keyID string, algorithm string) string {
	var contentDigestLine string
	if content.ContentDigest != "" {
		contentDigestLine = fmt.Sprintf("\"content-digest\": %s\n", content.ContentDigest)
	}

	base := fmt.Sprintf(
		"\"@method\": %s\n"+
			"\"@authority\": %s\n"+
			"\"@target-uri\": %s\n"+
			"%s",
		content.Method,
		content.Authority,
		content.TargetUri,
		contentDigestLine,
	)

	params := createSignatureParams(base, keyID, algorithm)
	return fmt.Sprintf("%s%s", base, params)
}

func createSignatureParams(base string, keyID string, algorithm string) string {
	params := getSpacedParameters(base)
	metadata := fmt.Sprintf("created=%d;keyid=\"%s\";alg=\"%s\"", time.Now().Unix(), keyID, algorithm)
	return fmt.Sprintf("\"@signature-params\": (%s);%s", params, metadata)
}

func getSpacedParameters(coveredContent string) string {

	spacedStringLine := ""

	sigParams := strings.Split(coveredContent, "\n")

	numOfParams := len(sigParams)

	for i, paramLine := range sigParams {
		param := strings.Split(paramLine, ":")[0]
		spacedStringLine += fmt.Sprintf("%s%s", param, getTrailingSpace(i, numOfParams))
	}

	return spacedStringLine
}

func getTrailingSpace(currentIndex int, numOfParams int) string {
	trailingSpace := ""
	if currentIndex < numOfParams-2 {
		trailingSpace = " "
	}
	return trailingSpace
}

func GetJsonBytesFromString(jsonStr string) ([]byte, error) {
	if jsonStr == "" {
		return nil, fmt.Errorf("jsonStr cannot be empty")
	}

	if !json.Valid([]byte(jsonStr)) {
		return nil, fmt.Errorf("jsonStr is not valid json")
	}

	return []byte(jsonStr), nil
}

func SanitizeJsonString(jsonStr string) (string, error) {

	if jsonStr == "" {
		return "", fmt.Errorf("jsonStr cannot be empty")
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonMap); err != nil {
		return "", fmt.Errorf("jsonStr is not valid json")
	}

	sanitizedStr, marshalError := json.Marshal(jsonMap)

	return string(sanitizedStr), marshalError
}
