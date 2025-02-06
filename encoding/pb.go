package udppb

import (
	"errors"

	socket_i "github.com/beka-birhanu/vinom-interfaces/socket"
	"google.golang.org/protobuf/proto"
)

var (
	errInvalidProtobufMessage = errors.New("invalid protobuf message")
)

type Protobuf struct{}

// Marshal implements udp.Encoder.
func (p *Protobuf) Marshal(msg interface{}) ([]byte, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil, errInvalidProtobufMessage
	}
	return proto.Marshal(m)
}

// MarshalHandshake implements udp.Encoder.
func (p *Protobuf) MarshalHandshake(h socket_i.HandshakeRecord) ([]byte, error) {
	msg := &Handshake{
		SessionId: h.GetSessionID(),
		Random:    h.GetRandom(),
		Cookie:    h.GetCookie(),
		Token:     h.GetToken(),
		Key:       h.GetKey(),
		Timestamp: h.GetTimestamp(),
	}
	return proto.Marshal(msg)
}

// MarshalPong implements udp.Encoder.
func (p *Protobuf) MarshalPong(pr socket_i.PongRecord) ([]byte, error) {
	msg := &Pong{
		PingSentAt: pr.GetPingSentAt(),
		ReceivedAt: pr.GetReceivedAt(),
		SentAt:     pr.GetSentAt(),
	}
	return proto.Marshal(msg)
}

// MarshalPing implements udp.Encoder.
func (p *Protobuf) MarshalPing(pr socket_i.PingRecord) ([]byte, error) {
	msg := &Ping{
		SentAt: pr.GetSentAt(),
	}
	return proto.Marshal(msg)
}

// NewHandshakeRecord implements udp.Encoder.
func (p *Protobuf) NewHandshakeRecord() socket_i.HandshakeRecord {
	return &Handshake{}
}

// NewPongRecord implements udp.Encoder.
func (p *Protobuf) NewPongRecord() socket_i.PongRecord {
	return &Pong{}
}

// NewPingRecord implements udp.Encoder.
func (p *Protobuf) NewPingRecord() socket_i.PingRecord {
	return &Ping{}
}

// Unmarshal implements udp.Encoder.
func (p *Protobuf) Unmarshal(raw []byte, msg interface{}) error {
	m, ok := msg.(proto.Message)
	if !ok {
		return errInvalidProtobufMessage
	}
	return proto.Unmarshal(raw, m)
}

// UnmarshalHandshake implements udp.Encoder.
func (p *Protobuf) UnmarshalHandshake(b []byte) (socket_i.HandshakeRecord, error) {
	h := &Handshake{}
	err := proto.Unmarshal(b, h)
	return h, err
}

// UnmarshalPing implements udp.Encoder.
func (p *Protobuf) UnmarshalPing(b []byte) (socket_i.PingRecord, error) {
	pi := &Ping{}
	err := proto.Unmarshal(b, pi)
	return pi, err
}

// UnmarshalPing implements udp.Encoder.
func (p *Protobuf) UnmarshalPong(b []byte) (socket_i.PongRecord, error) {
	po := &Pong{}
	err := proto.Unmarshal(b, po)
	return po, err
}
