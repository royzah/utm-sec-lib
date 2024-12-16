package ussp_pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"

	"utm-pki/pkg/utils"

	"github.com/rs/zerolog/log"
)

const HASH_ALGORITHM crypto.Hash = crypto.SHA512
const RSA_PSS_SALT_LENGTH int = 64

// Private methods

func validateVerifyParams(key crypto.PublicKey, signature string, data []byte) error {
	if key == nil {
		return fmt.Errorf("public key cannot be nil")
	}
	if signature == "" {
		return fmt.Errorf("signature cannot be empty")
	}
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}
	return nil
}

func validateSignParams(key crypto.Signer, data []byte) error {
	if key == nil {
		return fmt.Errorf("private key cannot be nil")
	}
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}
	return nil
}

func parseSignature(signature string) (value, algorithm string) {
	parts := strings.Split(signature, ":")
	if len(parts) == 2 {
		return parts[1], parts[0]
	}
	return signature, ""
}

// Public methods

func LoadPrivateKeyFromFile(filename string) (crypto.Signer, error) {

	keyFileBytes, err := utils.LoadBytesFromFile(filename) // #nosec G304

	if err != nil || len(keyFileBytes) < 1 {
		return nil, fmt.Errorf("no bytes were read for file %s", filename)
	}

	block, _ := pem.Decode(keyFileBytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM from file")
	}

	privKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	if len(der) == ed25519.SeedSize {
		key := ed25519.NewKeyFromSeed(der)
		return &key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func ParsePEMBytesToKey(pemBytes []byte) (crypto.PublicKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func SignDataWithPrivateKey(key crypto.Signer, data []byte) (string, error) {
	if err := validateSignParams(key, data); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	var signature string
	var err error

	switch privateKey := key.(type) {
	case *rsa.PrivateKey:
		signature, err = SignDataWithRSAKey(privateKey, data)
		if err != nil {
			return "", fmt.Errorf("RSA signing failed: %w", err)
		}
		return fmt.Sprintf("rsa:%s", signature), nil

	case *ecdsa.PrivateKey:
		signature, err = SignDataWithEcdsaKey(privateKey, data)
		if err != nil {
			return "", fmt.Errorf("ECDSA signing failed: %w", err)
		}
		return fmt.Sprintf("ecdsa:%s", signature), nil

	case ed25519.PrivateKey:
		signature, err = SignDataWithEd25519Key(privateKey, data)
		if err != nil {
			return "", fmt.Errorf("Ed25519 signing failed: %w", err)
		}
		return fmt.Sprintf("ed25519:%s", signature), nil

	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

func VerifyWithPublicKey(publicKey crypto.PublicKey, signature string, data []byte) error {
	if err := validateVerifyParams(publicKey, signature, data); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	sigValue, algorithm := parseSignature(signature)

	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if algorithm != "" && algorithm != "ecdsa" {
			return fmt.Errorf("algorithm mismatch: expected ecdsa, got %s", algorithm)
		}
		return verifyEcdsaSignature(key, sigValue, data)
	case *rsa.PublicKey:
		if algorithm != "" && algorithm != "rsa" {
			return fmt.Errorf("algorithm mismatch: expected rsa, got %s", algorithm)
		}
		return verifyRsaSignature(key, sigValue, data)
	case ed25519.PublicKey:
		if algorithm != "" && algorithm != "ed25519" {
			return fmt.Errorf("algorithm mismatch: expected ed25519, got %s", algorithm)
		}
		return verifyEd25519Signature(key, sigValue, data)
	default:
		return fmt.Errorf("unsupported key type: %T", publicKey)
	}
}

func HashDataByKey(data []byte, keyType x509.SignatureAlgorithm) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	switch keyType {
	case x509.ECDSAWithSHA256:
		hash := sha256.Sum256(data)
		return hash[:], nil
	case x509.PureEd25519:
		hash := sha512.Sum512(data)
		return hash[:], nil
	case x509.SHA512WithRSAPSS:
		hash := sha512.Sum512(data)
		return hash[:], nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %v", keyType)
	}
}

func SignDataWithEcdsaKey(privateKey *ecdsa.PrivateKey, data []byte) (string, error) {
	hashedData, err := HashDataByKey(data, x509.ECDSAWithSHA256)
	if err != nil {
		return "", fmt.Errorf("hashing failed: %w", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedData)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// Convert to IEEE P1363 format
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad R and S components
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	if signatureBase64 == "" {
		return "", fmt.Errorf("failed to encode signature")
	}

	return signatureBase64, nil
}

func SignDataWithEd25519Key(privateKey ed25519.PrivateKey, data []byte) (string, error) {
	hashedData, err := HashDataByKey(data, x509.PureEd25519)
	if err != nil {
		return "", fmt.Errorf("hashing failed: %w", err)
	}

	signature := ed25519.Sign(privateKey, hashedData)

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	if signatureBase64 == "" {
		return "", fmt.Errorf("failed to encode signature")
	}

	return signatureBase64, nil
}

func SignDataWithRSAKey(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	hashedData, err := HashDataByKey(data, x509.SHA512WithRSAPSS)
	if err != nil {
		return "", fmt.Errorf("hashing failed: %w", err)
	}

	opts := &rsa.PSSOptions{
		SaltLength: 64,
		Hash:       crypto.SHA512,
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, hashedData, opts)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	if signatureBase64 == "" {
		return "", fmt.Errorf("failed to encode signature")
	}

	return signatureBase64, nil
}

func verifyEcdsaSignature(publicKey *ecdsa.PublicKey, signature string, data []byte) error {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signatureBytes) != 64 {
		return fmt.Errorf("invalid ECDSA signature length: expected 64 bytes, got %d", len(signatureBytes))
	}

	hashedData := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])

	if !ecdsa.Verify(publicKey, hashedData[:], r, s) {
		return fmt.Errorf("invalid ECDSA signature")
	}

	return nil
}

func verifyRsaSignature(publicKey *rsa.PublicKey, signature string, data []byte) error {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	hashedData := sha512.Sum512(data)
	opts := &rsa.PSSOptions{
		SaltLength: 64,
		Hash:       crypto.SHA512,
	}

	if err = rsa.VerifyPSS(publicKey, crypto.SHA512, hashedData[:], signatureBytes, opts); err != nil {
		return fmt.Errorf("invalid RSA signature: %w", err)
	}

	return nil
}

func verifyEd25519Signature(publicKey ed25519.PublicKey, signature string, data []byte) error {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	hashedData := sha512.Sum512(data)
	if !ed25519.Verify(publicKey, hashedData[:], signatureBytes) {
		return fmt.Errorf("invalid Ed25519 signature")
	}

	return nil
}

func GetPublicKeyAsPem(publicKey crypto.PublicKey) (string, error) {
	if publicKey == nil {
		return "", errors.New("publicKey cannot be nil")
	}

	publicbKeyASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("error marshaling public key: %w", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicbKeyASN1,
	}

	publicKeyPEM := string(pem.EncodeToMemory(publicKeyBlock))

	return strings.TrimSpace(publicKeyPEM), nil
}

func IsPEMFormat(input string) bool {
	pemRegex := regexp.MustCompile(`^-----BEGIN [A-Z ]+-----\n([A-Za-z0-9+/=\n]+)-----END [A-Z ]+-----$`)
	return pemRegex.MatchString(input)
}

func PublicKeyToJWK(publicKey *rsa.PublicKey, keyId string) (*JWK, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("publicKey cannot be nil")
	}

	// Convert the modulus and exponent of the public key to base64url encoding.

	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	exponent := big.NewInt(int64(publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(exponent)

	jwk := &JWK{
		Alg: "PS512", // Replace this with the appropriate algorithm if needed.
		Kty: "RSA",
		N:   n,
		E:   e,
		Kid: keyId,
	}

	return jwk, nil
}

func GenerateUsspPrivateKey() (crypto.Signer, error) {
	var privateKey crypto.Signer
	var err error

	pkKeyId := os.Getenv("PKI_KEY_ID")

	if os.Getenv("PRIVATE_KEY_PATH") == "" {
		return nil, fmt.Errorf("PRIVATE_KEY_PATH was not found in the environment variables")
	} else if supportedKeyErr := isSupportedKey(pkKeyId); supportedKeyErr != nil {
		return nil, fmt.Errorf("unsupported PKI key ID: %s", os.Getenv("PKI_KEY_ID"))
	} else if _, err := os.Stat(os.Getenv("PRIVATE_KEY_PATH")); err == nil {
		return nil, fmt.Errorf("file already exists at %s", os.Getenv("PRIVATE_KEY_PATH"))
	}

	switch pkKeyId {
	case "ecdsa":
		privateKey, _ = CreateEcdsaPrivateKey()
	case "rsa":
		privateKey, _ = CreateRSAPSSPrivateKey(&RsaOptions{KeySize: 4096})
	}

	_, saveFileError := SavePrivateKeyToFile(privateKey, os.Getenv("PRIVATE_KEY_PATH"))
	if saveFileError != nil {
		return nil, saveFileError
	}

	return privateKey, err
}

func isSupportedKey(keyId string) error {

	if keyId == "ecdsa" || keyId == "rsa" {
		return nil
	} else if keyId == "ed25519" {
		return fmt.Errorf("ed25519 not supported but it will be added later")
	} else {
		return fmt.Errorf("unsupported PKI key ID: %s. Expected \"rsa\" or \"ecdsa\"", keyId)
	}

}

func LoadOrCreateCertFile() (certificate *x509.Certificate, certErr error) {
	certificatePath := os.Getenv("CERTIFICATE_PATH")
	if certificatePath == "" {
		panic("Certificate path is missing")
	}

	certificate, certErr = LoadCertFromFile(certificatePath)

	if certificate != nil {
		utils.LogMessage("Certificate found", utils.InfoLevel, utils.GeneralCategory)
		return certificate, certErr
	}

	utils.LogMessage("No certificate found, creating a new one", utils.InfoLevel, utils.GeneralCategory)

	privateKey, keyErr := LoadOrCreateKeyFile()
	if keyErr != nil {
		panic(keyErr)
	}

	return CreateTestCert(privateKey)
}

func CreateTestCert(privateKey crypto.Signer) (*x509.Certificate, error) {
	var CA_COMMON_NAME string = "Test CA"
	var CA_ORGANIZATION string = "Test CA Oy"
	var CA_ORGANIZATION_UNIT string = "Root CA"
	var CA_COUNTRY string = "FI"

	var CA_DISTINGUISHED_NAME = DistinguishedName{
		CommonName:       CA_COMMON_NAME,
		Organization:     CA_ORGANIZATION,
		OrganizationUnit: CA_ORGANIZATION_UNIT,
		Country:          CA_COUNTRY,
	}

	subject, err := CreateX509Subject(CA_DISTINGUISHED_NAME)
	if err != nil {
		panic(err)
	}

	csr, err := CreateCSR(privateKey, *subject)
	if err != nil {
		return nil, err
	}

	certAttrs := CertificateAttributes{
		CertificateSigningRequest: csr,
		SignerPrivateKey:          privateKey,
		ParentCert:                nil,
		IsCA:                      true,
	}

	cert, certErr := CreateX509Cert(certAttrs)
	if certErr != nil {
		panic(certErr)
	}

	certErr = SaveCertToFile(cert, os.Getenv("CERTIFICATE_PATH"))
	if certErr != nil {
		return nil, certErr
	}

	return cert, certErr
}

func LoadOrCreateKeyFile() (crypto.Signer, error) {
	privateKeyPath := os.Getenv("PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		panic("Private key path is missing")
	}
	var privateKey crypto.Signer
	var keyErr error

	privateKey, _ = LoadPrivateKeyFromFile(privateKeyPath)

	if privateKey != nil {
		log.Debug().Msg("Private key found")
		return privateKey, keyErr

	}

	log.Debug().Msg("No private key found, creating a new one")
	privateKey, keyErr = CreateEcdsaPrivateKey()
	if keyErr != nil {
		panic(keyErr)
	}

	_, saveKeyErr := SavePrivateKeyToFile(privateKey, privateKeyPath)
	if saveKeyErr != nil {
		panic(saveKeyErr)
	}
	return privateKey, keyErr
}

func CreateCertificateBundle(clientCertPath string) (string, error) {
	certBytes, err := utils.LoadBytesFromFile(clientCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate bundle: %w", err)
	}

	return base64.StdEncoding.EncodeToString(certBytes), nil
}
