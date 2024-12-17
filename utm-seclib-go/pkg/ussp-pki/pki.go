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

	"github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/utils"

	"github.com/rs/zerolog/log"
)

const HASH_ALGORITHM crypto.Hash = crypto.SHA512
const RSA_PSS_SALT_LENGTH int = 64

// Private methods

func validateSignParams(key crypto.Signer, data []byte) error {
	if key == nil {
		return fmt.Errorf("private key cannot be nil")
	}
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}
	return nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	// Try PKCS#8 first as it supports multiple key types including Ed25519
	if keyInterface, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := keyInterface.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unsupported private key type from PKCS#8")
		}
	}

	// Fallback to older parsing methods if PKCS#8 fails
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	// Attempt a direct Ed25519 key from seed if size matches
	if len(der) == ed25519.SeedSize {
		key := ed25519.NewKeyFromSeed(der)
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func signDataWithEcdsaKey(privateKey *ecdsa.PrivateKey, data []byte) (string, error) {
	hashedData, err := HashDataByKey(data, x509.ECDSAWithSHA256)
	if err != nil {
		return "", fmt.Errorf("hashing failed: %w", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedData)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	if signatureBase64 == "" {
		return "", fmt.Errorf("failed to encode signature")
	}

	return signatureBase64, nil
}

func signDataWithEd25519Key(privateKey ed25519.PrivateKey, data []byte) (string, error) {
	signature := ed25519.Sign(privateKey, data)

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	if signatureBase64 == "" {
		return "", fmt.Errorf("failed to encode signature")
	}
	return signatureBase64, nil
}

func signDataWithRSAKey(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	hashedData, err := HashDataByKey(data, x509.SHA512WithRSAPSS)
	if err != nil {
		return "", fmt.Errorf("hashing failed: %w", err)
	}

	opts := &rsa.PSSOptions{
		SaltLength: RSA_PSS_SALT_LENGTH,
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

func verifyEcdsaSignature(publicKey *ecdsa.PublicKey, signatureBytes []byte, signatureBase []byte) error {
	hasher := sha256.New()
	hasher.Write(signatureBase)
	hash := hasher.Sum(nil)

	if len(signatureBytes) != 64 {
		return fmt.Errorf("invalid ECDSA signature length")
	}

	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])

	if !ecdsa.Verify(publicKey, hash, r, s) {
		return fmt.Errorf("invalid ECDSA signature")
	}
	return nil
}

func verifyRsaSignature(publicKey *rsa.PublicKey, signatureBytes []byte, signatureBase []byte) error {
	hasher := sha512.New()
	hasher.Write(signatureBase)
	hash := hasher.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: RSA_PSS_SALT_LENGTH,
		Hash:       crypto.SHA512,
	}

	err := rsa.VerifyPSS(publicKey, crypto.SHA512, hash, signatureBytes, opts)
	if err != nil {
		return fmt.Errorf("invalid RSA signature: %w", err)
	}
	return nil
}

func verifyEd25519Signature(publicKey ed25519.PublicKey, signatureBytes []byte, signatureBase []byte) error {
	if !ed25519.Verify(publicKey, signatureBase, signatureBytes) {
		return fmt.Errorf("invalid Ed25519 signature")
	}
	return nil
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

func LoadPrivateKeyFromPEM(keyPem string) (crypto.Signer, error) {
	if keyPem == "" {
		return nil, fmt.Errorf("private key PEM cannot be empty")
	}

	block, _ := pem.Decode([]byte(keyPem))
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM from provided key content")
	}

	privKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from PEM: %v", err)
	}

	return privKey, nil
}

func ParsePEMBytesToKey(pemBytes []byte) (crypto.PublicKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

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

	switch privateKey := key.(type) {
	case *rsa.PrivateKey:
		return signDataWithRSAKey(privateKey, data)
	case *ecdsa.PrivateKey:
		return signDataWithEcdsaKey(privateKey, data)
	case ed25519.PrivateKey:
		return signDataWithEd25519Key(privateKey, data)
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
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

func VerifyWithPublicKey(publicKey interface{}, signatureBytes []byte, signatureBase []byte) bool {
	var err error

	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		err = verifyEcdsaSignature(key, signatureBytes, signatureBase)
	case *rsa.PublicKey:
		err = verifyRsaSignature(key, signatureBytes, signatureBase)
	case ed25519.PublicKey:
		err = verifyEd25519Signature(key, signatureBytes, signatureBase)
	default:
		fmt.Printf("ERROR: Unsupported key type: %T\n", publicKey)
		return false
	}

	if err != nil {
		fmt.Printf("ERROR: Verification failed: %v\n", err)
		return false
	}

	return true
}

func GetPublicKeyAsPem(publicKey crypto.PublicKey) (string, error) {
	if publicKey == nil {
		return "", errors.New("publicKey cannot be nil")
	}

	publicKeyASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("error marshaling public key: %w", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyASN1,
	}

	publicKeyPEM := string(pem.EncodeToMemory(publicKeyBlock))
	return strings.TrimSpace(publicKeyPEM), nil
}

func IsPEMFormat(input string) bool {
	pemRegex := regexp.MustCompile(`^-----BEGIN [A-Z ]+-----\n([A-Za-z0-9+/=\n]+)-----END [A-Z ]+-----$`)
	return pemRegex.MatchString(input)
}

func PublicKeyToJWK(publicKey crypto.PublicKey, keyId string) (*JWK, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	jwk := &JWK{
		Kid: keyId,
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.Alg = "PS512"
		jwk.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.Alg = "ES256"
		jwk.Crv = "P-256"
		jwk.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	case ed25519.PublicKey:
		jwk.Kty = "OKP"
		jwk.Alg = "EdDSA"
		jwk.Crv = "Ed25519"
		jwk.X = base64.RawURLEncoding.EncodeToString(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", publicKey)
	}

	return jwk, nil
}

func GenerateUsspPrivateKey() (crypto.Signer, error) {
	pkKeyId := os.Getenv("PKI_KEY_ID")
	if os.Getenv("PRIVATE_KEY_PATH") == "" {
		return nil, fmt.Errorf("PRIVATE_KEY_PATH was not found in the environment variables")
	} else if supportedKeyErr := isSupportedKey(pkKeyId); supportedKeyErr != nil {
		return nil, fmt.Errorf("unsupported PKI key ID: %s", os.Getenv("PKI_KEY_ID"))
	} else if _, err := os.Stat(os.Getenv("PRIVATE_KEY_PATH")); err == nil {
		return nil, fmt.Errorf("file already exists at %s", os.Getenv("PRIVATE_KEY_PATH"))
	}

	var privateKey crypto.Signer
	var err error

	switch pkKeyId {
	case "ecdsa":
		privateKey, err = CreateEcdsaPrivateKey()
		if err != nil {
			return nil, err
		}
	case "rsa":
		privateKey, err = CreateRSAPSSPrivateKey(&RsaOptions{KeySize: 4096})
		if err != nil {
			return nil, err
		}
	case "ed25519":
		privateKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	default:
		return nil, fmt.Errorf("unsupported PKI key ID: %s", pkKeyId)
	}

	_, saveFileError := SavePrivateKeyToFile(privateKey, os.Getenv("PRIVATE_KEY_PATH"))
	if saveFileError != nil {
		return nil, saveFileError
	}

	return privateKey, err
}

func isSupportedKey(keyId string) error {
	switch keyId {
	case "ecdsa", "rsa", "ed25519":
		return nil
	default:
		return fmt.Errorf("unsupported PKI key ID: %s. Expected \"rsa\", \"ecdsa\", or \"ed25519\"", keyId)
	}
}

func LoadOrCreateCertFile() (*x509.Certificate, error) {
	certificatePath := os.Getenv("CERTIFICATE_PATH")
	if certificatePath == "" {
		panic("Certificate path is missing")
	}

	certificate, certErr := LoadCertFromFile(certificatePath)
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
	CA_COMMON_NAME := "Test CA"
	CA_ORGANIZATION := "Test CA Oy"
	CA_ORGANIZATION_UNIT := "Root CA"
	CA_COUNTRY := "FI"

	CA_DISTINGUISHED_NAME := DistinguishedName{
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
	privateKey, _ := LoadPrivateKeyFromFile(privateKeyPath)

	if privateKey != nil {
		log.Debug().Msg("Private key found")
		return privateKey, nil
	}

	log.Debug().Msg("No private key found, creating a new one")

	// Defaulting to ECDSA if PKI_KEY_ID is not set. Adjust if needed.
	pkKeyId := os.Getenv("PKI_KEY_ID")
	if pkKeyId == "" {
		pkKeyId = "ecdsa"
	}

	var err error
	switch pkKeyId {
	case "ecdsa":
		privateKey, err = CreateEcdsaPrivateKey()
	case "rsa":
		privateKey, err = CreateRSAPSSPrivateKey(&RsaOptions{KeySize: 4096})
	case "ed25519":
		seed := make([]byte, ed25519.SeedSize)
		privateKey = ed25519.NewKeyFromSeed(seed)
	default:
		err = fmt.Errorf("unsupported key type for creation: %s", pkKeyId)
	}

	if err != nil {
		panic(err)
	}

	_, saveKeyErr := SavePrivateKeyToFile(privateKey, privateKeyPath)
	if saveKeyErr != nil {
		panic(saveKeyErr)
	}
	return privateKey, nil
}

func CreateCertificateBundle(clientCertPath string) (string, error) {
	certBytes, err := utils.LoadBytesFromFile(clientCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate bundle: %w", err)
	}

	return base64.StdEncoding.EncodeToString(certBytes), nil
}
