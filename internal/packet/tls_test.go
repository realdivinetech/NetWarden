package packet

import "testing"

func TestParseTLSClientHelloExtractsSNI(t *testing.T) {
	name, err := ParseTLSClientHello(tlsClientHello("secure.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if name != "secure.example.com" {
		t.Fatalf("unexpected SNI: %q", name)
	}
}

func TestParseTLSClientHelloSkipsUnknownExtensions(t *testing.T) {
	record := tlsClientHelloWithExtensions(
		[]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}, // supported_versions before SNI
		tlsServerNameExtension("api.example.com"),
	)
	name, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	if name != "api.example.com" {
		t.Fatalf("unexpected SNI: %q", name)
	}
}

func TestParseTLSClientHelloRejectsMalformed(t *testing.T) {
	valid := tlsClientHello("example.com")

	otherExtension := tlsClientHelloWithExtensions([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})

	for name, payload := range map[string][]byte{
		"empty":            {},
		"not handshake":    append([]byte{0x17}, valid[1:]...),
		"truncated record": valid[:len(valid)-3],
		"no sni extension": otherExtension,
		"short record":     {0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00},
	} {
		if _, err := ParseTLSClientHello(payload); err == nil {
			t.Fatalf("%s: accepted malformed ClientHello", name)
		}
	}
}

func tlsClientHello(name string) []byte {
	return tlsClientHelloWithExtensions(tlsServerNameExtension(name))
}

func tlsClientHelloWithExtensions(extensions ...[]byte) []byte {
	var extensionBlock []byte
	for _, extension := range extensions {
		extensionBlock = append(extensionBlock, extension...)
	}

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                               // session id length
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02) // cipher suites
	body = append(body, 0x01, 0x00)                         // compression methods
	body = append(body, byte(len(extensionBlock)>>8), byte(len(extensionBlock)))
	body = append(body, extensionBlock...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func tlsServerNameExtension(name string) []byte {
	if name == "" {
		return nil
	}
	host := []byte(name)
	entry := append([]byte{0x00, byte(len(host) >> 8), byte(len(host))}, host...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	extension := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}
	return append(extension, list...)
}
