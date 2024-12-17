package ietf_http_signature

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/types"
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
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf(`"@method": %s`, content.Method))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf(`"@authority": %s`, content.Authority))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf(`"@target-uri": %s`, content.TargetUri))
	builder.WriteString("\n")

	if content.ContentDigest != "" {
		builder.WriteString(fmt.Sprintf(`"content-digest": %s`, content.ContentDigest))
		builder.WriteString("\n")
	}

	components := []string{`"@method"`, `"@authority"`, `"@target-uri"`}
	if content.ContentDigest != "" {
		components = append(components, `"content-digest"`)
	}

	paramsStr := strings.Join(components, " ")
	created := time.Now().Unix()
	metadata := fmt.Sprintf(`created=%d;keyid="%s";alg="%s"`, created, keyID, algorithm)

	builder.WriteString(fmt.Sprintf(`"@signature-params": (%s);%s`, paramsStr, metadata))

	result := builder.String()

	return result
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

func ValidateSignatureBaseFormat(signatureBase string) error {
	lines := strings.Split(signatureBase, "\n")

	expectedComponents := []string{
		`"@method":`,
		`"@authority":`,
		`"@target-uri":`,
	}

	for i, expected := range expectedComponents {
		if i >= len(lines) || !strings.HasPrefix(lines[i], expected) {
			return fmt.Errorf("component %s should be at position %d", expected, i)
		}
	}

	remaining := lines[len(expectedComponents):]
	hasContentDigest := false
	hasSignatureParams := false

	for _, line := range remaining {
		if strings.HasPrefix(line, `"content-digest":`) {
			if hasSignatureParams {
				return fmt.Errorf("content-digest must come before @signature-params")
			}
			hasContentDigest = true
		} else if strings.HasPrefix(line, `"@signature-params":`) {
			if hasContentDigest && !strings.Contains(line, `"content-digest"`) {
				return fmt.Errorf("content-digest header present but not included in signature params")
			}
			if !hasContentDigest && strings.Contains(line, `"content-digest"`) {
				return fmt.Errorf("content-digest included in signature params but header not present")
			}
			hasSignatureParams = true
		}
	}

	if !hasSignatureParams {
		return fmt.Errorf("missing @signature-params")
	}

	return nil
}
