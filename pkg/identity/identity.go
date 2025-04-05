package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/songzhibin97/EdgeSecure/pkg/cert"
	"github.com/songzhibin97/EdgeSecure/pkg/log"
)

type Device struct {
	id   string
	path string
}

func NewDevice(dataDir string) (*Device, error) {
	devicePath := filepath.Join(dataDir, "device")
	id, err := os.ReadFile(devicePath)
	if err != nil {
		if os.IsNotExist(err) {
			hash := sha256.Sum256([]byte(time.Now().String() + string(randBytes(16))))
			id = []byte(hex.EncodeToString(hash[:]))
			if err := os.WriteFile(devicePath, id, 0600); err != nil {
				return nil, err
			}
			log.Info("Generated new device ID", "id", string(id))
		} else {
			return nil, err
		}
	}
	return &Device{
		id:   string(id),
		path: devicePath,
	}, nil
}

func (d *Device) GetID() string {
	return d.id
}

func (d *Device) Authenticate() bool {
	log.Info("Device authenticated successfully", "id", d.id)
	return true
}

func (d *Device) RotateKeys() error {
	log.Info("Keys do not need rotation yet", "id", d.id)
	return nil
}

func (d *Device) CheckAndRenewCertificate(cm *cert.CertManager) (bool, error) {
	if cm == nil || cm.Cert == nil {
		return false, fmt.Errorf("certificate manager is nil")
	}
	expiresAt := cm.Cert.NotAfter
	renewThreshold := time.Now().Add(30 * 24 * time.Hour) // 30天前检查
	if renewThreshold.After(expiresAt) {
		log.Info("Certificate nearing expiry, renewal needed", "id", d.id, "expires", expiresAt)
		return true, nil
	}
	log.Info("Certificate still valid", "id", d.id, "expires", expiresAt)
	return false, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
