package udppb

// SetCookie implements udp.HandshakeRecord.
func (x *Handshake) SetCookie(c []byte) {
	x.Cookie = c
}

// SetRandom implements udp.HandshakeRecord.
func (x *Handshake) SetRandom(r []byte) {
	x.Random = r
}

// SetKey implements udp.HandshakeRecord.
func (x *Handshake) SetKey(k []byte) {
	x.Key = k
}

// SetToken implements udp.HandshakeRecord.
func (x *Handshake) SetToken(t []byte) {
	x.Token = t
}

// GetSessionID implements udp.HandshakeRecord.
func (x *Handshake) GetSessionID() []byte {
	return x.SessionId
}

// SetSessionID implements udp.HandshakeRecord.
func (x *Handshake) SetSessionID(sID []byte) {
	x.SessionId = sID
}

// SetTimestamp implements udp.HandshakeRecord.
func (x *Handshake) SetTimestamp(t int64) {
	x.Timestamp = t
}
