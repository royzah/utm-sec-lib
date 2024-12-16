package ussp_pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"utm-pki/pkg/utils"
)

var ELLIPTIC_CURVE elliptic.Curve = elliptic.P256()

const DEFAULT_RSA_KEY_SIZE int = 4096

var randomSeedBytes []byte

type RsaOptions struct {
	KeySize int
}

func init() {
	randomSeedBytes = make([]byte, 32)
	_, err := rand.Read(randomSeedBytes)
	if err != nil {
		panic("cannot seed math/rand package with cryptographically secure random number generator")
	}
}

func CreateEcdsaPrivateKey() (crypto.Signer, error) {

	return ecdsa.GenerateKey(ELLIPTIC_CURVE, rand.Reader)
}

func CreateEd25519PrivateKey() (crypto.Signer, error) {

	key := ed25519.NewKeyFromSeed(randomSeedBytes)
	if key == nil {
		return nil, fmt.Errorf("failed to generate private key")
	}

	return &key, nil
}

func CreateRSAPSSPrivateKey(rsaOptions *RsaOptions) (crypto.Signer, error) {

	if rsaOptions == nil {
		rsaOptions = &RsaOptions{KeySize: DEFAULT_RSA_KEY_SIZE}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaOptions.KeySize)

	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return privateKey, nil
}

func GetPrivateKeyAsPemBytes(privateKey crypto.Signer) ([]byte, error) {
	var encodedBytes []byte
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	if !IsSupportedKey(privateKey) {
		return nil, fmt.Errorf("private key not supported")
	}

	keyLabel, err := GetKeyTypeLabel(privateKey)
	if err != nil {
		return nil, err
	}

	rawBytes, err := ParseBytesFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("failed to get raw bytes from private key")
	}

	pemBlock := pem.Block{
		Type:  keyLabel + " PRIVATE KEY",
		Bytes: rawBytes,
	}

	encodedBytes = pem.EncodeToMemory(&pemBlock)

	return encodedBytes, nil
}

func GetKeyTypeLabel(key crypto.Signer) (string, error) {
	if key == nil {
		return "", fmt.Errorf("key is nil")
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA", nil
	case *ecdsa.PrivateKey:
		return "ECDSA", nil
	case *ed25519.PrivateKey:
		return "Ed25519", nil
	default:
		return "", fmt.Errorf("unsupported key type")
	}
}

func ParseBytesFromPrivateKey(privateKey crypto.Signer) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	if !IsSupportedKey(privateKey) {
		return nil, fmt.Errorf("private key not supported")
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(key), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(key)
	case *ed25519.PrivateKey:
		return key.Seed(), nil
	default:
		return nil, fmt.Errorf("unknown key type")
	}
}

func SavePrivateKeyToFile(privateKey crypto.Signer, filePath string) (byteCount int, err error) {
	err = validateKeyFileParameters(privateKey, filePath)
	if err != nil {
		return 0, err
	}

	_, errorNilIfFileExists := LoadPrivateKeyFromFile(filePath)
	if errorNilIfFileExists == nil {
		return 0, fmt.Errorf("file already exists")
	}

	pemBytes, err := GetPrivateKeyAsPemBytes(privateKey)
	if err != nil || len(pemBytes) < 1 {
		return 0, err
	}

	return utils.SaveBytesToFile(pemBytes, filePath)
}

func validateKeyFileParameters(key crypto.Signer, path string) error {
	if key == nil {
		return fmt.Errorf("private key is nil")
	}

	if !IsSupportedKey(key) {
		return fmt.Errorf("private key not supported")
	}

	if path == "" {
		return fmt.Errorf("path is empty")
	}

	return nil
}

func IsSupportedKey(key crypto.Signer) bool {
	switch key.(type) {
	case *rsa.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return true
	case *ed25519.PrivateKey:
		return true
	default:
		return false
	}
}
