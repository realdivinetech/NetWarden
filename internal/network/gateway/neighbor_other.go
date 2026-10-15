//go:build !windows

package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// NeighborMAC is only implemented on Windows; other platforms rely on the
// capture driver's own address resolution.
func NeighborMAC(context.Context, netip.Addr) (net.HardwareAddr, error) {
	return nil, errors.New("neighbor table lookup is not supported on this platform")
}
