package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/songzhibin97/EdgeSecure/pkg/cert"
	"github.com/songzhibin97/EdgeSecure/pkg/config"
	"github.com/songzhibin97/EdgeSecure/pkg/log"
	"github.com/songzhibin97/EdgeSecure/pkg/tls"
)

func renewServerCertificate(cfg *config.Config, cm *cert.CertManager, caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*cert.CertManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new private key: %v", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cfg.ServerDomain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &privateKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new server certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	newCM := &cert.CertManager{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode new certificate PEM")
	}
	newCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse new certificate: %v", err)
	}
	newCM.Cert = newCert

	if err := newCM.Save(cfg.DataDir + "/certs"); err != nil {
		return nil, fmt.Errorf("failed to save new server certificate: %v", err)
	}
	return newCM, nil
}

func calculateCheckInterval(expiry time.Time) time.Duration {
	remaining := time.Until(expiry)
	switch {
	case remaining > 90*24*time.Hour:
		return 7 * 24 * time.Hour
	case remaining > 30*24*time.Hour:
		return 3 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func main() {
	configFile := flag.String("config", os.Getenv("CONFIG_FILE"), "Path to config file")
	flag.Parse()

	if *configFile == "" {
		log.Error("Config file path must be provided via --config or CONFIG_FILE environment variable")
		return
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Error("Failed to load config", "error", err)
		return
	}

	caCM, err := cert.GenerateCACert(cfg.DataDir)
	if err != nil {
		log.Error("Failed to generate/load CA certificate", "error", err)
		return
	}
	caKeyBlock, _ := pem.Decode(caCM.KeyPEM)
	if caKeyBlock == nil {
		log.Error("Failed to decode CA private key PEM")
		return
	}
	caPrivKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		log.Error("Failed to parse CA private key", "error", err)
		return
	}

	cm, err := cert.LoadCertificate(cfg.DataDir + "/certs")
	if err != nil {
		log.Info("No existing server certificate found, generating new one")
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		cm, err = cert.GenerateSignedCert(cfg.ServerDomain, &privateKey.PublicKey, privateKey, cfg.DataDir+"/certs", caCM.Cert, caPrivKey)
		if err != nil {
			log.Error("Failed to generate server certificate", "error", err)
			return
		}
	}

	edgeTLS := tls.NewEdgeTLS()
	if err := edgeTLS.LoadCertificate(cm.CertPEM, cm.KeyPEM); err != nil {
		log.Error("Failed to load server certificate", "error", err)
		return
	}
	edgeTLS.Config.ClientAuth = tls.RequireAndVerifyClientCert

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCM.CertPEM)
	edgeTLS.Config.ClientCAs = caCertPool

	clientCertPath := cfg.DataDir + "/client-certs/cert.pem"
	var mu sync.Mutex
	var lastLoaded time.Time
	var httpServer *http.Server
	loadClientCert := func() bool {
		mu.Lock()
		defer mu.Unlock()
		clientCertPEM, err := ioutil.ReadFile(clientCertPath)
		if err != nil {
			log.Warn("Client certificate not found, will retry", "error", err)
			return false
		}
		clientCertPool := x509.NewCertPool()
		if clientCertPool.AppendCertsFromPEM(clientCertPEM) {
			now := time.Now()
			if now.Sub(lastLoaded) > 1*time.Minute {
				log.Info("Loaded client certificate into trust pool")
				lastLoaded = now
			}
			edgeTLS.Config.ClientCAs = clientCertPool
			return true
		}
		log.Warn("Failed to parse client certificate")
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "healthy", "timestamp": "%s"}`, time.Now().UTC().Format(time.RFC3339))
		log.Debug("Health check requested")
	})
	mux.HandleFunc("/init-complete", func(w http.ResponseWriter, r *http.Request) {
		if httpServer != nil {
			log.Info("Client initialization complete, shutting down HTTP server")
			go func() {
				if err := httpServer.Close(); err != nil {
					log.Error("Failed to close HTTP server", "error", err)
				}
				httpServer = nil // 防止重复关闭
			}()
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "http_server_closed"}`)
	})

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCM.CertPEM)
		log.Info("CA certificate requested via HTTP")
	})
	httpMux.HandleFunc("/server-cert", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(cm.CertPEM)
		log.Info("Server certificate requested via HTTP")
	})
	httpMux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		csrPEM, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Error("Failed to read CSR", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csrBlock, _ := pem.Decode(csrPEM)
		if csrBlock == nil {
			log.Error("Failed to decode CSR PEM")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			log.Error("Failed to parse CSR", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      csr.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCM.Cert, csr.PublicKey, caPrivKey)
		if err != nil {
			log.Error("Failed to sign certificate", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		clientCertDir := cfg.DataDir + "/client-certs"
		if err := os.MkdirAll(clientCertDir, 0755); err != nil {
			log.Error("Failed to create client-certs dir", "error", err)
		}
		clientCertFile := filepath.Join(clientCertDir, "cert.pem")
		if err := ioutil.WriteFile(clientCertFile, certPEM, 0644); err != nil {
			log.Error("Failed to save client certificate", "error", err)
		} else {
			loadClientCert()
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(certPEM)
		log.Info("Certificate issued", "cn", csr.Subject.CommonName)
	})

	server := &http.Server{
		Addr:      ":" + cfg.Port,
		TLSConfig: edgeTLS.Config,
		Handler:   mux,
	}

	httpServer = &http.Server{
		Addr:    ":" + cfg.HttpPort,
		Handler: httpMux,
	}

	go func() {
		log.Info("Starting HTTP server for initial certificate distribution", "port", cfg.HttpPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server failed", "error", err)
		}
	}()

	go func() {
		for {
			loadClientCert()
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		for {
			renewThreshold := time.Now().Add(30 * 24 * time.Hour)
			if cm.Cert.NotAfter.Before(renewThreshold) {
				log.Info("Server certificate nearing expiry, renewing", "expires", cm.Cert.NotAfter)
				retryDelay := time.Hour
				for i := 0; i < 5; i++ {
					newCM, err := renewServerCertificate(cfg, cm, caCM.Cert, caPrivKey)
					if err != nil {
						log.Error("Failed to renew server certificate", "error", err, "retry_in", retryDelay)
						time.Sleep(retryDelay)
						retryDelay = min(retryDelay*2, 24*time.Hour)
						continue
					}
					cm = newCM
					if err := edgeTLS.LoadCertificate(cm.CertPEM, cm.KeyPEM); err != nil {
						log.Error("Failed to reload renewed server certificate", "error", err)
					} else {
						log.Info("Server certificate renewed successfully", "expires", cm.Cert.NotAfter)
					}
					break
				}
			} else {
				log.Info("Server certificate still valid", "expires", cm.Cert.NotAfter)
			}
			time.Sleep(calculateCheckInterval(cm.Cert.NotAfter))
		}
	}()

	log.Info("Starting mTLS server with HTTPS endpoints", "port", cfg.Port)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Error("Server failed", "error", err)
	}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
