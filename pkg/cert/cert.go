package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GenerateSignedCert 生成自签名证书
func GenerateSignedCert(deviceID string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, dataDir string, caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*CertManager, error) {
	certFile := filepath.Join(dataDir, "cert.pem")
	if _, err := os.Stat(certFile); err == nil {
		return LoadCertificate(dataDir)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: deviceID,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"mtlsserver"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	cm := &CertManager{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Cert:      cert,
		expiresAt: cert.NotAfter,
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %v", err)
	}
	keyFile := filepath.Join(dataDir, "key.pem")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}

	log.Printf("Generated signed certificate for device %s, expires at %s", deviceID, cert.NotAfter)
	return cm, nil
}

// LoadCertificate 从文件加载证书
func LoadCertificate(dataDir string) (*CertManager, error) {
	certFile := filepath.Join(dataDir, "cert.pem")
	keyFile := filepath.Join(dataDir, "key.pem") // 改为key.pem

	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}

	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate format")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	log.Printf("Loaded certificate for device %s, expires at %s", cert.Subject.CommonName, cert.NotAfter)
	return &CertManager{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Cert:      cert,
		expiresAt: cert.NotAfter,
	}, nil
}

// Save 将证书保存到文件
func (cm *CertManager) Save(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	certFile := filepath.Join(dataDir, "cert.pem")
	if err := ioutil.WriteFile(certFile, cm.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	return nil
}

// IsExpired 检查证书是否已过期
func (cm *CertManager) IsExpired() bool {
	now := time.Now()
	expired := now.After(cm.Cert.NotAfter) // 更新为Cert.NotAfter
	if expired {
		log.Printf("Certificate expired at %s", cm.Cert.NotAfter)
	}
	return expired
}

// Renew 更新证书
func (cm *CertManager) Renew(deviceID string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, dataDir string, caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) error {
	if !cm.IsExpired() {
		log.Printf("Certificate for device %s is still valid until %s, no renewal needed", deviceID, cm.expiresAt)
		return nil
	}

	newCert, err := GenerateSignedCert(deviceID, publicKey, privateKey, dataDir, caCert, caPrivKey)
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %v", err)
	}

	cm.CertPEM = newCert.CertPEM
	cm.KeyPEM = newCert.KeyPEM
	cm.Cert = newCert.Cert
	cm.expiresAt = newCert.expiresAt
	log.Printf("Certificate renewed for device %s, new expiry: %s", deviceID, cm.expiresAt)
	return nil
}

// GetExpiry 返回证书到期时间
func (cm *CertManager) GetExpiry() time.Time {
	return cm.expiresAt
}
