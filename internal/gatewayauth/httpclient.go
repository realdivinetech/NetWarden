package gatewayauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// errOffGateway is returned whenever a request would leave the gateway. The
// authorization flow must never follow a router's redirect to another host,
// and must never honour a proxy configured for the user's browser environment.
var errOffGateway = errors.New("refused to contact a host other than the gateway")

const (
	gatewayDialTimeout = 4 * time.Second
	gatewayUseTimeout  = 10 * time.Second
	maxResponseBody    = 1 << 20 // 1 MiB cap for login pages and JSON replies
)

// newPinnedClient returns an HTTP client that can only ever reach the gateway
// address supplied in the target:
//
//   - the dialer rewrites every connection to the pinned gateway IP, so DNS
//     names inside redirects or proxied responses can never escape;
//   - environment proxies are ignored;
//   - redirects to another host are refused;
//   - TLS verification is skipped because LAN gateways ship self-signed
//     certificates and the connection is already pinned to one IP address.
func newPinnedClient(target Target) *http.Client {
	return newPinnedClientWithJar(target, false)
}

// newPinnedClientWithJar returns a pinned client that keeps cookies when asked,
// which vendor form logins (session cookies) require.
func newPinnedClientWithJar(target Target, withJar bool) *http.Client {
	gatewayIP := target.IP
	dialer := &net.Dialer{Timeout: gatewayDialTimeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if host != gatewayIP {
				return nil, fmt.Errorf("%w: %s", errOffGateway, addr)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(gatewayIP, port))
		},
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // pinned to the gateway IP
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  gatewayUseTimeout,
		ExpectContinueTimeout:  time.Second,
		TLSHandshakeTimeout:    gatewayDialTimeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   gatewayUseTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Hostname() != gatewayIP {
				return fmt.Errorf("%w: redirect to %s", errOffGateway, req.URL.Hostname())
			}
			if len(via) >= 4 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	if withJar {
		jar, err := cookiejar.New(nil)
		if err == nil {
			client.Jar = jar
		}
	}
	return client
}

// gatewayURL builds a URL that is always addressed at the gateway itself.
func gatewayURL(scheme string, target Target, path string) string {
	if scheme == "" {
		scheme = "http"
	}
	host := target.IP
	if target.Port != "" {
		host = net.JoinHostPort(target.IP, target.Port)
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: path}).String()
}

// doRequest executes a request against the gateway and returns the response
// with a bounded, readable body. Callers must close the response.
func doRequest(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, []byte, error) {
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return resp, nil, fmt.Errorf("read gateway response: %w", err)
	}
	return resp, body, nil
}
