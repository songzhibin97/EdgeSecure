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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/songzhibin97/EdgeSecure/pkg/cert"
	"github.com/songzhibin97/EdgeSecure/pkg/config"
	"github.com/songzhibin97/EdgeSecure/pkg/identity"
	"github.com/songzhibin97/EdgeSecure/pkg/log"
	"github.com/songzhibin97/EdgeSecure/pkg/tls"
)

func fetchCACert(serverAddr, httpPort, dataDir string) ([]byte, error) {
	host := serverAddr
	if strings.Contains(serverAddr, ":") {
		host = strings.Split(serverAddr, ":")[0]
	}
	url := "http://" + host + ":" + httpPort + "/ca"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA certificate: %v", err)
	}
	defer resp.Body.Close()
	caPEM, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}
	caCertFile := filepath.Join(dataDir, "ca-cert.pem")
	if err := ioutil.WriteFile(caCertFile, caPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %v", err)
	}
	return caPEM, nil
}

func fetchServerCert(serverAddr, httpPort, dataDir string) ([]byte, error) {
	host := serverAddr
	if strings.Contains(serverAddr, ":") {
		host = strings.Split(serverAddr, ":")[0]
	}
	url := "http://" + host + ":" + httpPort + "/server-cert"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch server certificate: %v", err)
	}
	defer resp.Body.Close()
	certPEM, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read server certificate: %v", err)
	}
	certDir := filepath.Join(dataDir, "certs")
	os.MkdirAll(certDir, 0755)
	certFile := filepath.Join(certDir, "cert.pem")
	if err := ioutil.WriteFile(certFile, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to save server certificate: %v", err)
	}
	return certPEM, nil
}

func requestCertificate(serverAddr, httpPort, dataDir, deviceID string, client *http.Client) (*cert.CertManager, error) {
	var url string
	if client == nil { // 首次请求使用HTTP
		host := serverAddr
		if strings.Contains(serverAddr, ":") {
			host = strings.Split(serverAddr, ":")[0]
		}
		url = "http://" + host + ":" + httpPort + "/cert"
	} else { // 续期使用HTTPS
		url = "https://" + serverAddr + "/cert"
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	var resp *http.Response
	if client == nil {
		resp, err = http.Post(url, "application/x-pem-file", strings.NewReader(string(csrPEM)))
	} else {
		resp, err = client.Post(url, "application/x-pem-file", strings.NewReader(string(csrPEM)))
	}
	if err != nil {
		return nil, fmt.Errorf("failed to request certificate: %v", err)
	}
	defer resp.Body.Close()
	certPEM, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	_cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	cm := &cert.CertManager{
		CertPEM: certPEM,
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}),
		Cert:    _cert,
	}
	if err := cm.Save(dataDir + "/client-certs"); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %v", err)
	}
	return cm, nil
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
	fmt.Println("EdgeSecure MVP starting...")

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

	if cfg.ClientDomain == "" || cfg.ServerAddr == "" {
		log.Error("Client domain and server address are required")
		return
	}

	device, err := identity.NewDevice(cfg.DataDir)
	if err != nil {
		log.Error("Failed to create/load device", "error", err)
		return
	}
	log.Info("Device created/loaded", "id", device.GetID())

	if !device.Authenticate() {
		log.Error("Device authentication failed")
		return
	}

	if err := device.RotateKeys(); err != nil {
		log.Error("Failed to rotate keys", "error", err)
		return
	}

	var caCM *cert.CertManager
	caCM, err = cert.LoadCACertOnly(cfg.DataDir)
	if err != nil {
		log.Info("CA certificate not found, fetching from server")
		caPEM, err := fetchCACert(cfg.ServerAddr, cfg.HttpPort, cfg.DataDir)
		if err != nil {
			log.Error("Failed to fetch CA certificate", "error", err)
			return
		}
		caBlock, _ := pem.Decode(caPEM)
		if caBlock == nil {
			log.Error("Failed to decode fetched CA certificate PEM")
			return
		}
		caCert, err := x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			log.Error("Failed to parse fetched CA certificate", "error", err)
			return
		}
		caCM = &cert.CertManager{
			CertPEM: caPEM,
			Cert:    caCert,
		}
	}

	cm, err := cert.LoadCertificate(cfg.DataDir + "/client-certs")
	if err != nil {
		log.Info("No existing client certificate found, requesting from server")
		cm, err = requestCertificate(cfg.ServerAddr, cfg.HttpPort, cfg.DataDir, device.GetID(), nil)
		if err != nil {
			log.Error("Failed to request client certificate", "error", err)
			return
		}
	}

	edgeTLS := tls.NewEdgeTLS()
	_cert, err := tls.X509KeyPair(cm.CertPEM, cm.KeyPEM)
	if err != nil {
		log.Error("Failed to parse client certificate/key pair", "error", err)
		return
	}
	edgeTLS.Config.Certificates = []tls.Certificate{_cert}
	edgeTLS.Config.ServerName = "mtlsserver"
	edgeTLS.Config.InsecureSkipVerify = false

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCM.CertPEM)
	serverCertPEM, err := fetchServerCert(cfg.ServerAddr, cfg.HttpPort, cfg.DataDir)
	if err != nil {
		log.Error("Failed to fetch server certificate, strict verification requires it", "error", err)
		return
	}
	if !caCertPool.AppendCertsFromPEM(serverCertPEM) {
		log.Error("Failed to add server certificate to trust pool")
		return
	}
	edgeTLS.Config.RootCAs = caCertPool

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: edgeTLS.Config,
			DialTLS: func(network, addr string) (net.Conn, error) {
				start := time.Now()
				conn, err := edgeTLS.Dial(network, addr)
				if err != nil {
					log.Error("Failed to dial", "addr", addr, "error", err)
				} else {
					duration := time.Since(start).Milliseconds()
					log.Info("TLS connection established",
						"addr", addr,
						"version", fmt.Sprintf("%x", conn.ConnectionState().Version),
						"cipher", fmt.Sprintf("%x", conn.ConnectionState().CipherSuite),
						"resumed", conn.ConnectionState().DidResume,
						"handshake_ms", duration)
				}
				return conn, err
			},
		},
	}

	serverCertPath := filepath.Join(cfg.DataDir, "certs", "cert.pem")
	var mu sync.Mutex
	loadServerCert := func() {
		mu.Lock()
		defer mu.Unlock()
		serverCertPEM, err := ioutil.ReadFile(serverCertPath)
		if err != nil {
			log.Warn("Server certificate not found, will retry", "error", err)
			return
		}
		certPool := x509.NewCertPool()
		if certPool.AppendCertsFromPEM(serverCertPEM) {
			edgeTLS.Config.RootCAs = certPool
			log.Info("Loaded server certificate into trust pool")
		} else {
			log.Warn("Failed to parse server certificate")
		}
	}
	loadServerCert()

	go func() {
		for {
			mu.Lock()
			if edgeTLS.Config.RootCAs == nil {
				mu.Unlock()
				loadServerCert()
			} else {
				mu.Unlock()
				retryDelay := time.Hour
				for i := 0; i < 5; i++ {
					serverCertPEM, err := fetchServerCert(cfg.ServerAddr, cfg.HttpPort, cfg.DataDir)
					if err != nil {
						log.Warn("Failed to fetch updated server certificate", "error", err, "retry_in", retryDelay)
						time.Sleep(retryDelay)
						retryDelay = min(retryDelay*2, 24*time.Hour)
						continue
					}
					mu.Lock()
					certPool := x509.NewCertPool()
					if certPool.AppendCertsFromPEM(serverCertPEM) {
						edgeTLS.Config.RootCAs = certPool
						log.Info("Updated server certificate in trust pool")
					}
					mu.Unlock()
					break
				}
			}
			time.Sleep(calculateCheckInterval(cm.Cert.NotAfter))
		}
	}()

	go func() {
		for {
			needsRenewal, err := device.CheckAndRenewCertificate(cm)
			if err != nil {
				log.Error("Failed to check certificate", "error", err)
			} else if needsRenewal {
				log.Info("Renewing client certificate")
				retryDelay := time.Hour
				for i := 0; i < 5; i++ {
					newCM, err := requestCertificate(cfg.ServerAddr, cfg.HttpPort, cfg.DataDir, device.GetID(), client)
					if err != nil {
						log.Error("Failed to renew certificate", "error", err, "retry_in", retryDelay)
						time.Sleep(retryDelay)
						retryDelay = min(retryDelay*2, 24*time.Hour)
						continue
					}
					cm = newCM
					_cert, err := tls.X509KeyPair(cm.CertPEM, cm.KeyPEM)
					if err != nil {
						log.Error("Failed to reload renewed certificate", "error", err)
					} else {
						mu.Lock()
						edgeTLS.Config.Certificates = []tls.Certificate{_cert}
						mu.Unlock()
						log.Info("Client certificate renewed successfully", "expires", cm.Cert.NotAfter)
					}
					break
				}
			}
			time.Sleep(calculateCheckInterval(cm.Cert.NotAfter))
		}
	}()

	url := "https://" + cfg.ServerAddr + "/health"
	var resp *http.Response
	for i := 0; i < 5; i++ {
		resp, err = client.Get(url)
		if err == nil {
			log.Info("First connection successful")
			resp.Body.Close()
			break
		}
		log.Warn("First connection failed, retrying", "attempt", i+1, "error", err.Error())
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Error("Failed to connect to server after retries", "error", err)
		return
	}

	// 通知服务器初始化完成，关闭HTTP服务器
	initCompleteURL := "https://" + cfg.ServerAddr + "/init-complete"
	resp, err = client.Get(initCompleteURL)
	if err != nil {
		log.Warn("Failed to notify server of initialization completion", "error", err)
	} else {
		log.Info("Notified server of initialization completion")
		resp.Body.Close()
	}

	for i := 0; i < 5; i++ {
		resp, err = client.Get(url)
		if err == nil {
			log.Info("Second connection successful")
			resp.Body.Close()
			break
		}
		log.Warn("Second connection failed, retrying", "attempt", i+1, "error", err.Error())
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Error("Failed to connect to server after retries", "error", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "healthy", "device_id": "%s", "timestamp": "%s"}`, device.GetID(), time.Now().UTC().Format(time.RFC3339))
		log.Debug("Health check requested")
	})

	go func() {
		if err := http.ListenAndServe(":8081", mux); err != nil {
			log.Error("Health check server failed", "error", err)
		}
	}()

	select {}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
