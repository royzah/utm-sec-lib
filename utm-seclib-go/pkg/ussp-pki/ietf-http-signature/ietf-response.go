package ietf_http_signature

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"utm-pki/pkg/types"
)

func ExtractPropertiesFromResponse(resp types.IETFSignedResponse) (*types.ExtractedProperties, error) {

	if err := validateHeaders(resp.Headers); err != nil {
		return nil, err
	}

	certBytes, err := base64.StdEncoding.DecodeString(resp.Headers.CertificateBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate bundle: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	signatureBase, err := parseSignatureBase(resp)
	if err != nil {
		return nil, err
	}

	if err := ValidateSignatureBaseFormat(signatureBase); err != nil {
		return nil, fmt.Errorf("invalid signature base format: %v", err)
	}

	return &types.ExtractedProperties{
		PublicKeyPem:  publicKeyPem,
		Signature:     resp.Headers.Signature,
		SignatureBase: signatureBase,
	}, nil
}

func validateHeaders(h types.ResponseHeaders) error {
	if h.CertificateBundle == "" {
		return fmt.Errorf("server certificate bundle is missing")
	}
	if h.Signature == "" {
		return fmt.Errorf("response signature is missing")
	}
	if h.SignatureInput == "" {
		return fmt.Errorf("signature input is missing")
	}
	if h.ContentDigest == "" {
		return fmt.Errorf("content digest is missing")
	}
	return nil
}

func ValidateIETFResponse(ietfResponse *http.Response) error {

	if validRespErr := hasRequiredIETFResponseHeaders(ietfResponse); validRespErr != nil {
		return validRespErr
	}

	return nil
}

func hasRequiredIETFResponseHeaders(ietfResponse *http.Response) error {
	if ietfResponse == nil {
		return fmt.Errorf("IETF Response is nil")
	} else if ietfResponse.Header == nil {
		return fmt.Errorf("IETF Response is missing headers")
	} else if err := validateSignatureInput(ietfResponse.Header.Get("Signature-Input")); err != nil {
		return err
	} else if err := validateSignature(ietfResponse.Header.Get("Signature")); err != nil {
		return err
	} else if err := validateResponseRequest(ietfResponse.Request); err != nil {
		return err
	} else if ietfResponse.ContentLength > 0 && ietfResponse.Header.Get("Content-Digest") == "" {
		return fmt.Errorf("IETF Response is missing Content-Digest header")
	} else if ietfResponse.Header.Get("X-Certificate-Bundle") == "" {
		return fmt.Errorf("IETF Response is missing X-Certificate-Bundle header")
	}
	return nil
}

func validateSignatureInput(signatureInput string) error {
	if signatureInput == "" {
		return fmt.Errorf("signature input cannot be empty")
	}

	signatureParamsRegex := regexp.MustCompile(
		`sig1=\(\"@(method)\"\s\"@(authority)\"\s\"@(target-uri)\"([\s]\"(content-digest)\")?\);` +
			`created=\d+;keyid=\"([^\"]+)\";alg=\"([^\"]+)\"`)

	if !signatureParamsRegex.MatchString(signatureInput) {
		return fmt.Errorf("invalid signature input format")
	}

	return nil
}

func validateSignature(signature string) error {
	regexp := regexp.MustCompile(`sig1=:\S+:`)
	if !regexp.MatchString(signature) {
		return fmt.Errorf("signature does not contain sig1")
	}
	return nil
}

func validateResponseRequest(ietfRequest *http.Request) error {
	if ietfRequest == nil {
		return fmt.Errorf("IETF Response is missing request")
	} else if ietfRequest.Header == nil {
		return fmt.Errorf("IETF Response is missing request headers")
	} else if ietfRequest.URL == nil {
		return fmt.Errorf("IETF Response is missing request URL")
	} else if ietfRequest.URL.String() == "" {
		return fmt.Errorf("IETF Response request URL is empty")
	} else if ietfRequest.Host == "" {
		return fmt.Errorf("IETF Response request Host is empty")
	} else if ietfRequest.Method == "" {
		return fmt.Errorf("IETF Response request Method is empty")
	}
	return nil
}

func ParseCoveredContentFromIETFResponse(ietfResponse *http.Response) (*types.SignatureCoveredContent, error) {
	var result = &types.SignatureCoveredContent{}

	if err := ValidateIETFResponse(ietfResponse); err != nil {
		return nil, err
	}

	result.Method = ietfResponse.Request.Method
	result.Authority = ietfResponse.Request.URL.Host
	result.TargetUri = ietfResponse.Request.URL.String()

	var signInputWithoutSig1Tag string
	before, after, found := strings.Cut(ietfResponse.Header.Get("Signature-Input"), "sig1=")
	if found {
		signInputWithoutSig1Tag = fmt.Sprintf("%s%s", before, after)
	} else {
		signInputWithoutSig1Tag = ietfResponse.Header.Get("Signature-Input")
	}

	result.SignatureParams = signInputWithoutSig1Tag

	if ietfResponse.ContentLength > 0 {
		result.ContentDigest = ietfResponse.Header.Get("Content-Digest")
	}

	return result, nil
}

func parseSignatureBase(resp types.IETFSignedResponse) (string, error) {

	parsedURL, err := url.Parse(resp.Config.URL)
	if err != nil {
		return "", fmt.Errorf("error parsing URL: %v", err)
	}

	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	authority := parsedURL.Hostname()
	if (port != "80" && parsedURL.Scheme == "http") ||
		(port != "443" && parsedURL.Scheme == "https") {
		authority = fmt.Sprintf("%s:%s", authority, port)
	}

	signatureParam := resp.Headers.SignatureInput
	signatureParam = strings.TrimPrefix(signatureParam, "sig1=")

	var builder strings.Builder

	methodLine := fmt.Sprintf(`"@method": %s`, resp.Config.Method)
	builder.WriteString(methodLine)
	builder.WriteString("\n")

	authorityLine := fmt.Sprintf(`"@authority": %s`, authority)
	builder.WriteString(authorityLine)
	builder.WriteString("\n")

	targetLine := fmt.Sprintf(`"@target-uri": %s`, parsedURL.RequestURI())
	builder.WriteString(targetLine)
	builder.WriteString("\n")

	if resp.Headers.ContentDigest != "" {
		digestLine := fmt.Sprintf(`"content-digest": %s`, resp.Headers.ContentDigest)
		builder.WriteString(digestLine)
		builder.WriteString("\n")
	}

	paramsLine := fmt.Sprintf(`"@signature-params": %s`, signatureParam)
	builder.WriteString(paramsLine)

	result := builder.String()

	return result, nil
}
