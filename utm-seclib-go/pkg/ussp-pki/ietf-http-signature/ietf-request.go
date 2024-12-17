package ietf_http_signature

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	netURL "net/url"
	"os"
	"strings"
	"time"

	"github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/types"
	ussp_pki "github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/ussp-pki"
)

func CreateIETFRequest(
	ietfRequestParams types.IETFRequestParams,
	privateKey string,
	clientCertPath string,
	keyId string,
	algorithm string,
) (types.IETFRequestResult, error) {
	if ietfRequestParams.Method == "" {
		return types.IETFRequestResult{}, fmt.Errorf("method is required")
	}

	if !isSupportedMethod(ietfRequestParams.Method) {
		return types.IETFRequestResult{}, fmt.Errorf("unsupported method")
	}

	parsedURL, err := netURL.Parse(ietfRequestParams.URL)
	if err != nil {
		return types.IETFRequestResult{}, fmt.Errorf("invalid URL: %v", err)
	}

	if parsedURL.Host == "" {
		return types.IETFRequestResult{}, fmt.Errorf("invalid URL: missing host")
	}

	if ietfRequestParams.Body != "" && !json.Valid([]byte(ietfRequestParams.Body)) {
		return types.IETFRequestResult{}, fmt.Errorf("body is not valid JSON")
	}

	contentDigest, err := CreateContentDigest(ietfRequestParams.Body)
	if err != nil {
		return types.IETFRequestResult{}, fmt.Errorf("failed to create content digest: %v", err)
	}

	targetURI := parsedURL.Path
	if parsedURL.RawQuery != "" {
		targetURI += "?" + parsedURL.RawQuery
	}

	request := &types.SignedRequest{
		Method: ietfRequestParams.Method,
		URL:    targetURI,
		Headers: map[string]string{
			"host":           parsedURL.Host,
			"content-type":   "application/json",
			"content-digest": contentDigest,
			"accept":         "application/json",
		},
	}

	sigInput, err := CreateSignatureInput(request, keyId, algorithm)
	if err != nil {
		return types.IETFRequestResult{}, fmt.Errorf("failed to create Signature-Input: %v", err)
	}

	sigBase, err := CreateSignatureBase(request, keyId, algorithm)
	if err != nil {
		return types.IETFRequestResult{}, fmt.Errorf("failed to create Signature Base: %v", err)
	}

	certBase64, err := ussp_pki.CreateCertificateBundle(clientCertPath)
	if err != nil {
		return types.IETFRequestResult{}, fmt.Errorf("failed to create certificate bundle: %v", err)
	}

	signature, err := CreateSignature(sigBase, privateKey)
	if err != nil {
		return types.IETFRequestResult{}, fmt.Errorf("failed to create signature: %v", err)
	}

	var authHeader string
	if ietfRequestParams.BearerToken != "" {
		authHeader = fmt.Sprintf("Bearer %s", ietfRequestParams.BearerToken)
	} else if token := getDefaultToken(); token != "" {
		authHeader = fmt.Sprintf("Bearer %s", token)
	}

	return types.IETFRequestResult{
		ContentDigest: contentDigest,
		SigInput:      sigInput,
		CertBase64:    certBase64,
		Signature:     signature,
		AuthHeader:    authHeader,
	}, nil
}

func isSupportedMethod(method string) bool {
	supportedMethods := []string{"GET", "POST", "PUT", "PATCH"}
	method = strings.ToUpper(method)
	for _, supported := range supportedMethods {
		if method == supported {
			return true
		}
	}
	return false
}

func CreateIETFRequestParams(
	method string,
	url string,
	body string,
	bearerToken string,
) types.IETFRequestParams {
	return types.IETFRequestParams{
		Method:      method,
		URL:         url,
		Body:        body,
		BearerToken: bearerToken,
	}
}

func SendIETFRequest(
	url string,
	body interface{},
	headers map[string]string,
	config *types.IETFRequestConfig,
) (*http.Response, error) {
	ctx := context.Background()

	if config == nil {
		config = &types.IETFRequestConfig{
			Method:     "POST",
			Timeout:    5 * time.Second,
			Retries:    3,
			RetryDelay: time.Second,
		}
	}

	// Validate required headers
	requiredHeaders := []string{
		"content-type",
		"content-digest",
		"signature",
		"signature-input",
		"x-certificate-bundle",
	}

	var missingHeaders []string
	for _, header := range requiredHeaders {
		if _, exists := headers[strings.ToLower(header)]; !exists {
			missingHeaders = append(missingHeaders, header)
		}
	}

	if len(missingHeaders) > 0 {
		return nil, fmt.Errorf("missing required headers: %s", strings.Join(missingHeaders, ", "))
	}

	// Create HTTP client with configuration
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	// Prepare request body
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	var lastErr error
	for attempt := 1; attempt <= config.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, config.Method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		// Set headers
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < config.Retries {
				time.Sleep(config.RetryDelay)
				continue
			}
			break
		}

		if resp.StatusCode == 400 || resp.StatusCode == 401 ||
			resp.StatusCode == 403 || resp.StatusCode == 404 {
			return resp, nil
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		var errMsg string
		if resp.Body != nil {
			var errorResp struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&errorResp); err == nil && errorResp.Error != "" {
				errMsg = errorResp.Error
			}
			resp.Body.Close()
		}

		if errMsg == "" {
			errMsg = fmt.Sprintf("request failed with status code: %d", resp.StatusCode)
		}
		lastErr = fmt.Errorf(errMsg)

		if attempt < config.Retries {
			time.Sleep(config.RetryDelay)
		}
	}

	return nil, fmt.Errorf("all retry attempts failed, last error: %v", lastErr)
}

func SendIETFJSONRequest(ctx context.Context, url string, method string, body interface{}, headers http.Header, privateKeyPem string, clientCertPath string, keyID string, algorithm string) (*http.Response, error) {
	var bodyString string
	var err error

	parsedURL, err := netURL.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s (must be http or https)", parsedURL.Scheme)
	}

	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyString = string(bodyBytes)
	}

	params := CreateIETFRequestParams(method, url, bodyString, "")
	ietfResult, err := CreateIETFRequest(params, privateKeyPem, clientCertPath, keyID, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create IETF request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString(bodyString))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Digest", ietfResult.ContentDigest)
	httpReq.Header.Set("Signature", ietfResult.Signature)
	httpReq.Header.Set("Signature-Input", ietfResult.SigInput)
	httpReq.Header.Set("X-Certificate-Bundle", ietfResult.CertBase64)
	httpReq.Header.Set("Authorization", ietfResult.AuthHeader)

	for key, values := range headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	if httpReq.Header.Get("Host") == "" {
		httpReq.Header.Set("Host", parsedURL.Host)
	}

	config := types.IETFRequestConfig{
		Method:     method,
		Timeout:    10 * time.Second,
		Retries:    3,
		RetryDelay: 2 * time.Second,
	}

	headerMap := make(map[string]string)
	for key := range httpReq.Header {
		headerMap[strings.ToLower(key)] = httpReq.Header.Get(key)
	}

	return SendIETFRequest(url, body, headerMap, &config)
}

func ExtractPropertiesFromRequest(req types.SignedRequest) (types.ExtractedProperties, error) {

	if req.Headers == nil {
		return types.ExtractedProperties{}, fmt.Errorf("request validation failed: headers are missing from the request")
	}

	signature := req.Headers["signature"]
	certBundle := req.Headers["x-certificate-bundle"]

	if signature == "" || certBundle == "" {
		return types.ExtractedProperties{}, fmt.Errorf("request validation failed: missing required headers")
	}

	if !strings.HasPrefix(signature, "sig1=:") || !strings.HasSuffix(signature, ":") {
		return types.ExtractedProperties{}, fmt.Errorf("request validation failed: invalid signature format")
	}

	derBytes, err := base64.StdEncoding.DecodeString(certBundle)
	if err != nil {
		return types.ExtractedProperties{}, fmt.Errorf("invalid certificate bundle encoding: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return types.ExtractedProperties{}, fmt.Errorf("invalid certificate format: %v", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: cert.RawSubjectPublicKeyInfo,
	})

	signatureBase, err := ParseCoveredContentFromIETFRequest(&req)
	if err != nil {
		return types.ExtractedProperties{}, fmt.Errorf("failed to parse covered content: %v", err)
	}

	return types.ExtractedProperties{
		PublicKeyPem:  string(pubKeyPEM),
		Signature:     signature,
		SignatureBase: signatureBase,
	}, nil
}

func getDefaultToken() string {
	token := os.Getenv("BEARER_TOKEN")
	return token
}
