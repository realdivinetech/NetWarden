package gatewayauth

import (
	"context"
	"crypto/md5" //nolint:gosec // RouterOS legacy login mandates MD5
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// MikroTikVerifier authenticates against the RouterOS API on port 8728. The
// web fingerprint (WebFig / MikroTik markers) selects the adapter; the API
// itself speaks a length-prefixed word protocol rather than HTTP.
//
// Both login generations are supported: RouterOS 6.43+ accepts the password
// in the first /login sentence, older releases answer with an MD5 challenge
// that must be answered with md5(0x00 | password | challenge).
type MikroTikVerifier struct{}

// Name implements Verifier.
func (v *MikroTikVerifier) Name() string { return "mikrotik-routeros-api" }

// UsernameRequired implements Verifier.
func (v *MikroTikVerifier) UsernameRequired() bool { return true }

// Match implements Verifier.
func (v *MikroTikVerifier) Match(fp Fingerprint) bool {
	if strings.Contains(strings.ToLower(fp.Header.Get("Server")), "mikrotik") {
		return true
	}
	return fp.BodyContainsAny("mikrotik", "webfig")
}

// mikroTikAPIPort is a variable so tests can point the adapter at an ephemeral
// listener; production always uses the RouterOS default API port.
var mikroTikAPIPort = "8728"

// Verify implements Verifier with a single API login exchange.
func (v *MikroTikVerifier) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.IP, mikroTikAPIPort))
	if err != nil {
		return Result{}, fmt.Errorf("RouterOS API is not reachable on port %s: %v", mikroTikAPIPort, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(8 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = conn.SetDeadline(deadline)

	if err := writeRouterOSWords(conn, "/login", "=name="+creds.Username, "=password="+creds.Password); err != nil {
		return Result{}, fmt.Errorf("talk to RouterOS API: %v", err)
	}
	words, err := readRouterOSWords(conn)
	if err != nil {
		return Result{}, fmt.Errorf("read RouterOS reply: %v", err)
	}
	if len(words) == 0 {
		return Result{}, fmt.Errorf("RouterOS returned an empty reply")
	}

	switch {
	case strings.HasPrefix(words[0], "!fatal"):
		return Result{}, fmt.Errorf("RouterOS disconnected: %s", routerOSMessage(words))
	case routerOSMessage(words) != "" && routerOSAttribute(words, "=ret") == "":
		return Result{}, fmt.Errorf("RouterOS rejected the credentials: %s", routerOSMessage(words))
	}

	if challenge := routerOSAttribute(words, "=ret"); challenge != "" {
		challengeBytes, err := hex.DecodeString(challenge)
		if err != nil {
			return Result{}, fmt.Errorf("RouterOS sent a malformed challenge: %v", err)
		}
		digest := md5.New() //nolint:gosec // mandated by RouterOS legacy login
		digest.Write([]byte{0x00})
		digest.Write([]byte(creds.Password))
		digest.Write(challengeBytes)
		response := "00" + hex.EncodeToString(digest.Sum(nil))
		if err := writeRouterOSWords(conn, "/login", "=name="+creds.Username, "=response="+response); err != nil {
			return Result{}, fmt.Errorf("answer RouterOS challenge: %v", err)
		}
		words, err = readRouterOSWords(conn)
		if err != nil {
			return Result{}, fmt.Errorf("read RouterOS reply: %v", err)
		}
		if len(words) == 0 {
			return Result{}, fmt.Errorf("RouterOS returned an empty reply")
		}
		if strings.HasPrefix(words[0], "!fatal") {
			return Result{}, fmt.Errorf("RouterOS disconnected: %s", routerOSMessage(words))
		}
		if routerOSMessage(words) != "" && words[0] != "!done" {
			return Result{}, fmt.Errorf("RouterOS rejected the credentials: %s", routerOSMessage(words))
		}
		if words[0] != "!done" {
			return Result{}, fmt.Errorf("unexpected RouterOS reply %q", words[0])
		}
		return Result{Verified: true, Strategy: v.Name()}, nil
	}

	if words[0] != "!done" {
		return Result{}, fmt.Errorf("unexpected RouterOS reply %q", words[0])
	}
	return Result{Verified: true, Strategy: v.Name()}, nil
}

func routerOSMessage(words []string) string {
	return routerOSAttribute(words, "=message")
}

func routerOSAttribute(words []string, prefix string) string {
	for _, word := range words {
		if strings.HasPrefix(word, prefix+"=") {
			return strings.TrimPrefix(word, prefix+"=")
		}
		if word == prefix {
			return ""
		}
	}
	return ""
}

// writeRouterOSWords sends one length-prefixed sentence.
func writeRouterOSWords(writer io.Writer, words ...string) error {
	for _, word := range words {
		data := []byte(word)
		if err := writeRouterOSLength(writer, len(data)); err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
	_, err := writer.Write([]byte{0x00}) // end of sentence
	return err
}

func writeRouterOSLength(writer io.Writer, length int) error {
	var header []byte
	switch {
	case length < 0x80:
		header = []byte{byte(length)}
	case length < 0x4000:
		header = []byte{byte(0x80 | (length >> 8)), byte(length & 0xff)}
	case length < 0x200000:
		header = []byte{byte(0xc0 | (length >> 16)), byte((length >> 8) & 0xff), byte(length & 0xff)}
	default:
		header = []byte{byte(0xe0 | (length >> 24)), byte((length >> 16) & 0xff), byte((length >> 8) & 0xff), byte(length & 0xff)}
	}
	_, err := writer.Write(header)
	return err
}

// readRouterOSWords reads one length-prefixed sentence. It reads directly from
// the connection (never buffered) so a second sentence is never swallowed by
// an internal buffer.
func readRouterOSWords(reader io.Reader) ([]string, error) {
	words := make([]string, 0, 4)
	for {
		var prefix [1]byte
		if _, err := io.ReadFull(reader, prefix[:]); err != nil {
			return nil, err
		}
		length, err := routerOSLength(prefix[0], reader)
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return words, nil
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		words = append(words, string(data))
	}
}

func routerOSLength(first byte, reader io.Reader) (int, error) {
	switch {
	case first&0x80 == 0:
		return int(first), nil
	case first&0xc0 == 0x80:
		var extra [1]byte
		if _, err := io.ReadFull(reader, extra[:]); err != nil {
			return 0, err
		}
		return int(first&0x3f)<<8 | int(extra[0]), nil
	case first&0xe0 == 0xc0:
		var extra [2]byte
		if _, err := io.ReadFull(reader, extra[:]); err != nil {
			return 0, err
		}
		return int(first&0x1f)<<16 | int(extra[0])<<8 | int(extra[1]), nil
	case first&0xf0 == 0xe0:
		var extra [3]byte
		if _, err := io.ReadFull(reader, extra[:]); err != nil {
			return 0, err
		}
		return int(first&0x0f)<<24 | int(extra[0])<<16 | int(extra[1])<<8 | int(extra[2]), nil
	default:
		return 0, fmt.Errorf("invalid RouterOS length prefix 0x%02x", first)
	}
}
