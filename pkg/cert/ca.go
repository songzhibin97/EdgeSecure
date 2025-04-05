package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	caOnce sync.Once
	caCM   *CertManager
	caErr  error
)

type CertManager struct {
	CertPEM   []byte
	KeyPEM    []byte
	Cert      *x509.Certificate
	expiresAt time.Time
}

func GenerateCACert(dataDir string) (*CertManager, error) {
	caCertFile := filepath.Join(dataDir, "ca-cert.pem")
	caKeyFile := filepath.Join(dataDir, "ca-key.pem")

	caOnce.Do(func() {
		if _, err := os.Stat(caCertFile); err == nil {
			if _, err := os.Stat(caKeyFile); err == nil {
				caCM, caErr = LoadCACertWithKey(dataDir)
				return
			}
			caCM, caErr = LoadCACertOnly(dataDir)
			return
		}

		caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			caErr = fmt.Errorf("failed to generate CA private key: %v", err)
			return
		}

		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "EdgeSecure CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			caErr = fmt.Errorf("failed to create CA certificate: %v", err)
			return
		}

		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

		if err := os.MkdirAll(dataDir, 0755); err != nil {
			caErr = fmt.Errorf("failed to create data directory: %v", err)
			return
		}
		if err := os.WriteFile(caCertFile, caPEM, 0644); err != nil {
			caErr = fmt.Errorf("failed to save CA certificate: %v", err)
			return
		}
		if err := os.WriteFile(caKeyFile, keyPEM, 0600); err != nil {
			caErr = fmt.Errorf("failed to save CA private key: %v", err)
			return
		}

		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			caErr = fmt.Errorf("failed to parse CA certificate: %v", err)
			return
		}

		fmt.Printf("Generated CA certificate, expires at %s\n", caCert.NotAfter)
		caCM = &CertManager{
			CertPEM:   caPEM,
			KeyPEM:    keyPEM,
			Cert:      caCert,
			expiresAt: caCert.NotAfter,
		}
	})

	if caErr != nil {
		return nil, caErr
	}
	return caCM, nil
}

func LoadCACertWithKey(dataDir string) (*CertManager, error) {
	caCertFile := filepath.Join(dataDir, "ca-cert.pem")
	caKeyFile := filepath.Join(dataDir, "ca-key.pem")

	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %v", err)
	}

	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	fmt.Printf("Loaded CA certificate, expires at %s\n", caCert.NotAfter)
	return &CertManager{
		CertPEM:   caPEM,
		KeyPEM:    keyPEM,
		Cert:      caCert,
		expiresAt: caCert.NotAfter,
	}, nil
}

func LoadCACertOnly(dataDir string) (*CertManager, error) {
	caCertFile := filepath.Join(dataDir, "ca-cert.pem")

	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	fmt.Printf("Loaded CA certificate (no key), expires at %s\n", caCert.NotAfter)
	return &CertManager{
		CertPEM:   caPEM,
		KeyPEM:    nil, // 不加载私钥
		Cert:      caCert,
		expiresAt: caCert.NotAfter,
	}, nil
}
