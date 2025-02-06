package udppb

// SetSentAt implements udp.PingRecord.
func (x *Ping) SetSentAt(c int64) {
	x.SentAt = c
}
