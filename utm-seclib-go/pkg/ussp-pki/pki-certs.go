package ussp_pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/royzah/utm-sec-lib/utm-seclib-go/pkg/utils"
)

type CertificateAttributes struct {
	CertificateSigningRequest *x509.CertificateRequest
	SignerPrivateKey          crypto.Signer
	ParentCert                *x509.Certificate
	IsCA                      bool
	ValidForDays              int
}

type DistinguishedName struct {
	CommonName       string
	Organization     string
	OrganizationUnit string
	Country          string
	Locality         string
}

func CreateX509Subject(distinguishedName DistinguishedName) (subject *pkix.Name, err error) {
	subject = &pkix.Name{
		CommonName:         distinguishedName.CommonName,
		Organization:       []string{distinguishedName.Organization},
		OrganizationalUnit: []string{distinguishedName.OrganizationUnit},
		Country:            []string{distinguishedName.Country},
		Locality:           []string{distinguishedName.Locality},
	}

	err = checkX509SubjectRequiredFields(subject)
	if err != nil {
		subject = nil
	}

	return subject, err
}

func checkX509SubjectRequiredFields(subject *pkix.Name) error {
	if subject.CommonName == "" {
		return fmt.Errorf("common name is empty")
	} else if subject.Organization[0] == "" {
		return fmt.Errorf("organization is empty")
	} else if subject.OrganizationalUnit[0] == "" {
		return fmt.Errorf("organization unit is empty")
	} else if subject.Country[0] == "" {
		return fmt.Errorf("country is empty")
	}

	return nil
}

func CreateCSR(certPrivateKey crypto.Signer, caSubject pkix.Name) (*x509.CertificateRequest, error) {

	certificateTemplate := &x509.CertificateRequest{
		Subject:            caSubject,
		PublicKey:          certPrivateKey.Public(),
		SignatureAlgorithm: getSignatureAlgorithmForPrivateKey(certPrivateKey),
	}

	certBytes, err := x509.CreateCertificateRequest(rand.Reader, certificateTemplate, certPrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(certBytes)
}

func getSignatureAlgorithmForPrivateKey(privateKey crypto.Signer) x509.SignatureAlgorithm {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return x509.SHA512WithRSA
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA512
	case *ed25519.PrivateKey:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}

}

func CreateX509Cert(certAttrs CertificateAttributes) (*x509.Certificate, error) {
	var certTemplate x509.Certificate

	csr := certAttrs.CertificateSigningRequest
	parentCert := certAttrs.ParentCert
	signerPrivateKey := certAttrs.SignerPrivateKey
	validForDays := certAttrs.ValidForDays

	if signerPrivateKey == nil || csr == nil {
		return nil, fmt.Errorf("missing required parameters")
	}

	if certAttrs.IsCA {
		certTemplate = getCACertificateTemplate(*big.NewInt(1), csr.Subject)
	} else {
		certTemplate = getGenericCertificateTemplate(*big.NewInt(1), csr.Subject)
	}

	if validForDays > 0 {
		certTemplate.NotAfter = time.Now().AddDate(0, 0, validForDays)
	}

	if isRootCertificate(parentCert) {
		parentCert = &certTemplate
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, parentCert, csr.PublicKey, signerPrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func getGenericCertificateTemplate(serialNumber big.Int, subjectName pkix.Name) x509.Certificate {
	return x509.Certificate{
		SerialNumber: &serialNumber,
		Subject:      subjectName,
		NotBefore:    time.Now(),
	}
}

func getCACertificateTemplate(serialNumber big.Int, subjectName pkix.Name) x509.Certificate {

	certTemplate := getGenericCertificateTemplate(serialNumber, subjectName)

	certTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	certTemplate.IsCA = true
	certTemplate.BasicConstraintsValid = true
	certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	return certTemplate
}

func isRootCertificate(parentCert *x509.Certificate) bool {
	return parentCert == nil
}

func LoadCertFromFile(certFilePath string) (*x509.Certificate, error) {

	if certFilePath == "" {
		return nil, fmt.Errorf("empty file path given")
	}

	fileBytes, err := utils.LoadBytesFromFile(certFilePath) // #nosec G304
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(fileBytes)
}

func SaveCertToFile(cert *x509.Certificate, certFilePath string) error {

	if cert == nil {
		return fmt.Errorf("cert must be valid x509 Certificate")
	}

	existingCert, _ := LoadCertFromFile(certFilePath)

	if existingCert != nil {
		return fmt.Errorf("certificate already exists")
	}

	certBytes := cert.Raw

	byteCount, saveBytesErr := utils.SaveBytesToFile(certBytes, certFilePath)
	if saveBytesErr != nil || byteCount == 0 {
		return fmt.Errorf("error saving certificate to file: %v", saveBytesErr)
	}

	return nil
}
