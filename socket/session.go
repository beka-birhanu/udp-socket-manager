package udp

import (
	"crypto/rand"
	"net"

	socket_i "github.com/beka-birhanu/vinom-common/interfaces/socket"
	"github.com/google/uuid"
)

// SessionManager a struct to manage sessions secrets
type SessionManager struct {
	sHMACKey []byte //session random key
	cHMACKey []byte //cookie random key
	HMAC     socket_i.HMAC
}

// NewSessionManager returns a new session manager
// Generates new random secrets for cookies & session IDs
func NewSessionManager(h socket_i.HMAC) (*SessionManager, error) {
	sessionHMAC := make([]byte, 32)
	_, err := rand.Read(sessionHMAC)
	if err != nil {
		return nil, err
	}

	cookieHMAC := make([]byte, 32)
	_, err = rand.Read(cookieHMAC)
	if err != nil {
		return nil, err
	}

	return &SessionManager{
		sHMACKey: sessionHMAC,
		cHMACKey: cookieHMAC,
		HMAC:     h,
	}, nil
}

// GetAddrCookieHMAC generates a cookie for an UDP address with params
func (s *SessionManager) GetAddrCookieHMAC(addr *net.UDPAddr, params ...[]byte) []byte {
	return s.GetCookieHMAC(append([][]byte{addr.IP}, params...)...)
}

// GetCookieHMAC generates a cookie for a byte array with the cookie secret
func (s *SessionManager) GetCookieHMAC(params ...[]byte) []byte {
	return s.HMAC.Sign(s.cHMACKey, params...)
}

// GetSessionHMAC generates a session HMAC with the params
func (s *SessionManager) GetSessionHMAC(params ...[]byte) []byte {
	return s.HMAC.Sign(s.sHMACKey, params...)
}

// GenerateSessionID generate a new random session ID for the address & the user ID
func (s *SessionManager) GenerateSessionID(addr *net.UDPAddr, userID uuid.UUID) ([]byte, error) {
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	if err != nil {
		return nil, err
	}

	return append(s.GetSessionHMAC(addr.IP, []byte(userID.String())), sessionKey...), nil
}
