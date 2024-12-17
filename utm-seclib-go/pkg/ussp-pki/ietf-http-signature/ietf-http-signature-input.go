package ietf_http_signature

import (
	"fmt"
	"strings"
	"time"

	"github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/types"
)

func CreateSignatureInput(request *types.SignedRequest, keyID string, algorithm string) (string, error) {
	if request == nil || request.Headers["host"] == "" || !isSupportedMethod(request.Method) {
		return "", fmt.Errorf("invalid request")
	}

	coveredContent := types.SignatureCoveredContent{
		Authority:     request.Headers["host"],
		Method:        request.Method,
		TargetUri:     request.URL,
		ContentDigest: request.Headers["content-digest"],
	}

	return parseSignatureInputFromCoveredContent(&coveredContent, keyID, algorithm), nil
}

func parseSignatureInputFromCoveredContent(coveredContent *types.SignatureCoveredContent, keyID string, algorithm string) string {
	var contentDigest string
	if coveredContent.ContentDigest != "" {
		contentDigest = " \"content-digest\""
	}

	return fmt.Sprintf("sig1=(\"@method\" \"@authority\" \"@target-uri\"%s);created=%d;keyid=\"%s\";alg=\"%s\"",
		contentDigest,
		time.Now().Unix(),
		keyID,
		algorithm,
	)
}

func ParseCoveredContentFromIETFRequest(req *types.SignedRequest) (string, error) {
	lines := []string{}

	lines = append(lines, fmt.Sprintf(`"@method": %s`, req.Method))

	authority := req.Headers["host"]
	if authority == "" {
		return "", fmt.Errorf("host not found in request headers")
	}
	lines = append(lines, fmt.Sprintf(`"@authority": %s`, authority))

	lines = append(lines, fmt.Sprintf(`"@target-uri": %s`, req.URL))

	if contentDigest := req.Headers["content-digest"]; contentDigest != "" {
		lines = append(lines, fmt.Sprintf(`"content-digest": %s`, contentDigest))
	}

	sigInput := req.Headers["signature-input"]
	if sigInput == "" {
		return "", fmt.Errorf("signature input not found in request headers")
	}

	sigParams := strings.TrimPrefix(sigInput, "sig1=")
	lines = append(lines, fmt.Sprintf(`"@signature-params": %s`, sigParams))

	result := strings.Join(lines, "\n")
	return result, nil
}
