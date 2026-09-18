package main

import "testing"

func TestPacketValidation(t *testing.T) {
	packet := Packet{Version: protocolVersion, ID: "id", Type: "message", TTL: defaultTTL}
	if err := validatePacket(packet); err != nil {
		t.Fatal(err)
	}
	packet.Version++
	if err := validatePacket(packet); err == nil {
		t.Fatal("unsupported version accepted")
	}
	packet.Version = protocolVersion
	packet.Payload = string(make([]byte, maxPayloadBytes+1))
	if err := validatePacket(packet); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func FuzzPacketValidation(f *testing.F) {
	f.Add(uint8(protocolVersion), "id", "message", uint8(defaultTTL), "payload")
	f.Fuzz(func(t *testing.T, version uint8, id, packetType string, ttl uint8, payload string) {
		_ = validatePacket(Packet{Version: version, ID: id, Type: packetType, TTL: ttl, Payload: payload})
	})
}
