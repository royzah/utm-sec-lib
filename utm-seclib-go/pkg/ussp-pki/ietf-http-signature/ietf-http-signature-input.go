package ietf_http_signature

import (
	"fmt"
	"strings"
	"time"
	"utm-pki/pkg/types"
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
	signatureInput, exists := req.Headers["signature-input"]
	if !exists || signatureInput == "" {
		return "", fmt.Errorf("signature input not found in request headers")
	}

	signatureParams := strings.Split(signatureInput, "sig1=")[1]
	if signatureParams == "" {
		return "", fmt.Errorf("invalid signature input format")
	}

	contentDigest, exists := req.Headers["content-digest"]
	if !exists || contentDigest == "" {
		return "", fmt.Errorf("content digest not found in request headers")
	}

	authority, exists := req.Headers["host"]
	if !exists || authority == "" {
		return "", fmt.Errorf("host not found in request headers")
	}

	components := types.HttpsSignatureComponents{
		Method:          req.Method,
		Authority:       authority,
		TargetUri:       req.URL,
		ContentDigest:   contentDigest,
		SignatureParams: signatureParams,
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(`"@method": %s`, components.Method))
	builder.WriteString(fmt.Sprintf("\n\"@authority\": %s", components.Authority))
	builder.WriteString(fmt.Sprintf("\n\"@target-uri\": %s", components.TargetUri))
	builder.WriteString(fmt.Sprintf("\n\"content-digest\": %s", components.ContentDigest))
	builder.WriteString(fmt.Sprintf("\n\"@signature-params\": %s", components.SignatureParams))

	return builder.String(), nil
}
