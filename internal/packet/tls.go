package packet

import (
	"encoding/binary"
	"errors"
)

var (
	ErrMalformedTLS = errors.New("malformed TLS record")
	ErrNoServerName = errors.New("TLS ClientHello has no server name")
)

const (
	tlsRecordHandshake      = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtensionServerName  = 0x0000
	tlsServerNameHostName   = 0x00
)

// ParseTLSClientHello extracts the Server Name Indication (SNI) from a TLS
// ClientHello record, if present. It parses the first record in the payload
// only; a ClientHello split across TCP segments will not be reassembled here.
func ParseTLSClientHello(payload []byte) (string, error) {
	if len(payload) < 5 || payload[0] != tlsRecordHandshake {
		return "", ErrMalformedTLS
	}
	recordLength := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLength < 4 || 5+recordLength > len(payload) {
		return "", ErrMalformedTLS
	}
	handshake := payload[5 : 5+recordLength]
	if handshake[0] != tlsHandshakeClientHello {
		return "", ErrMalformedTLS
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	body := handshake[4:]
	if handshakeLength > len(body) {
		return "", ErrMalformedTLS
	}
	return clientHelloServerName(body[:handshakeLength])
}

func clientHelloServerName(body []byte) (string, error) {
	// legacy_version (2) + random (32)
	const fixedPrefix = 34
	if len(body) < fixedPrefix {
		return "", ErrMalformedTLS
	}
	cursor := fixedPrefix

	// session_id
	if cursor >= len(body) {
		return "", ErrMalformedTLS
	}
	sessionLength := int(body[cursor])
	cursor++
	if cursor+sessionLength > len(body) {
		return "", ErrMalformedTLS
	}
	cursor += sessionLength

	// cipher_suites
	if cursor+2 > len(body) {
		return "", ErrMalformedTLS
	}
	cipherLength := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	if cursor+cipherLength > len(body) {
		return "", ErrMalformedTLS
	}
	cursor += cipherLength

	// compression_methods
	if cursor >= len(body) {
		return "", ErrMalformedTLS
	}
	compressionLength := int(body[cursor])
	cursor++
	if cursor+compressionLength > len(body) {
		return "", ErrMalformedTLS
	}
	cursor += compressionLength

	// extensions (optional)
	if cursor == len(body) {
		return "", ErrNoServerName
	}
	if cursor+2 > len(body) {
		return "", ErrMalformedTLS
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	if cursor+extensionsLength > len(body) {
		return "", ErrMalformedTLS
	}
	return findServerName(body[cursor : cursor+extensionsLength])
}

func findServerName(extensions []byte) (string, error) {
	cursor := 0
	for cursor+4 <= len(extensions) {
		extensionType := binary.BigEndian.Uint16(extensions[cursor : cursor+2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[cursor+2 : cursor+4]))
		cursor += 4
		if cursor+extensionLength > len(extensions) {
			return "", ErrMalformedTLS
		}
		if extensionType == tlsExtensionServerName {
			return parseServerNameExtension(extensions[cursor : cursor+extensionLength])
		}
		cursor += extensionLength
	}
	return "", ErrNoServerName
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrMalformedTLS
	}
	listLength := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLength > len(data) {
		return "", ErrMalformedTLS
	}
	entries := data[2 : 2+listLength]
	for len(entries) >= 3 {
		nameType := entries[0]
		nameLength := int(binary.BigEndian.Uint16(entries[1:3]))
		entries = entries[3:]
		if nameLength > len(entries) {
			return "", ErrMalformedTLS
		}
		if nameType == tlsServerNameHostName {
			return string(entries[:nameLength]), nil
		}
		entries = entries[nameLength:]
	}
	return "", ErrNoServerName
}
