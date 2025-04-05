package tls

import (
	"crypto/tls"
	"log"
	"sync"
)

// sessionCache 实现tls.ClientSessionCache接口
type sessionCache struct {
	cache map[string]*tls.ClientSessionState
	mu    sync.Mutex
}

func (c *sessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	session, ok := c.cache[sessionKey]
	return session, ok
}

func (c *sessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[sessionKey] = cs
}

// initSessionCache 初始化会话缓存
func (e *EdgeTLS) initSessionCache() {
	if e.Config.ClientSessionCache == nil {
		e.Config.ClientSessionCache = &sessionCache{
			cache: make(map[string]*tls.ClientSessionState),
		}
	}
}

func (e *EdgeTLS) OptimizeHandshake() {
	e.Config.DynamicRecordSizingDisabled = true
}

func (e *EdgeTLS) ResumeSession(conn *tls.Conn, addr string) error {
	if err := conn.Handshake(); err != nil {
		return err
	}

	state := conn.ConnectionState()
	if state.DidResume {
		log.Printf("Resumed session for %s", addr)
	} else {
		log.Printf("Performed full handshake for %s", addr)
	}
	return nil
}
