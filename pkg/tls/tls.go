package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/songzhibin97/EdgeSecure/pkg/log"

	"net"
	"time"
)

// 暴露标准库的常量
const (
	VersionTLS13               = tls.VersionTLS13
	RequireAndVerifyClientCert = tls.RequireAndVerifyClientCert
)

// Config 别名标准库的tls.Config
type Config = tls.Config

type CertificateRequestInfo = tls.CertificateRequestInfo

type Certificate = tls.Certificate

func X509KeyPair(certPEM, keyPEM []byte) (Certificate, error) {
	return tls.X509KeyPair(certPEM, keyPEM)
}

// Conn 别名标准库的tls.Conn
type Conn = tls.Conn

type EdgeTLS struct {
	Config *tls.Config
}

// NewEdgeTLS 创建一个优化的TLS配置
func NewEdgeTLS() *EdgeTLS {
	return &EdgeTLS{
		Config: &tls.Config{
			MinVersion: tls.VersionTLS13, // 强制使用TLS 1.3，减少协商开销
			CipherSuites: []uint16{
				tls.TLS_CHACHA20_POLY1305_SHA256, // 优先使用高效加密套件
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519, // 优先使用X25519，性能优于其他曲线
				tls.CurveP256,
			},
			SessionTicketsDisabled:      false,                             // 启用会话票据，支持快速恢复
			ClientSessionCache:          tls.NewLRUClientSessionCache(128), // 增加缓存容量，支持更多会话
			PreferServerCipherSuites:    true,                              // 服务器决定加密套件
			DynamicRecordSizingDisabled: true,                              // 禁用动态记录调整，减少CPU开销
		},
	}
}

// LoadCertificate 加载证书
func (e *EdgeTLS) LoadCertificate(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	e.Config.Certificates = []tls.Certificate{cert}
	return nil
}

// Dial 建立TLS连接，优化握手过程
func (e *EdgeTLS) Dial(network, addr string) (*tls.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second, // 缩短超时时间，提升响应速度
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		log.Error("Failed to dial", "addr", addr, "error", err)
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)
	config := e.Config
	if config.ServerName == "" {
		config.ServerName = host
	}

	tlsConn := tls.Client(conn, config)
	start := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		log.Error("TLS handshake failed", "error", err)
		return nil, err
	}

	state := tlsConn.ConnectionState()
	duration := time.Since(start).Milliseconds()
	log.Info("TLS connection established",
		"addr", addr,
		"version", fmt.Sprintf("%x", state.Version),
		"cipher", fmt.Sprintf("%x", state.CipherSuite),
		"resumed", state.DidResume,
		"handshake_ms", duration)

	return tlsConn, nil
}

// Close 关闭TLS连接
func (e *EdgeTLS) Close(conn *tls.Conn) error {
	if conn != nil {
		return conn.Close()
	}
	return nil
}
