//go:build windows

package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxPhysAddrLen = 8
	mibNetRowSize  = 4 + 4 + maxPhysAddrLen + 4 + 4
	noErrorCode    = 0
	insufficient   = 122
)

var (
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")
)

// NeighborMAC returns targetIP's hardware address from the operating system's
// IPv4 neighbor (ARP) cache. It first nudges the OS into resolving the address
// through the normal stack, then polls the cache. This is a fallback for
// networks where raw ARP probing through the capture driver is unreliable,
// such as Wi-Fi adapters.
func NeighborMAC(ctx context.Context, targetIP netip.Addr) (net.HardwareAddr, error) {
	targetIP = targetIP.Unmap()
	if !targetIP.Is4() {
		return nil, fmt.Errorf("neighbor lookup requires an IPv4 address")
	}
	triggerNeighborResolution(targetIP)
	deadline := time.Now().Add(2 * time.Second)
	for {
		address, err := readNeighborTable(targetIP)
		if err == nil && address != nil {
			return address, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("no IPv4 neighbor entry for %s", targetIP)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// triggerNeighborResolution sends a single datagram toward the target so the
// kernel populates its neighbor cache. The destination port is irrelevant; only
// the neighbor discovery matters.
func triggerNeighborResolution(targetIP netip.Addr) {
	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(targetIP.AsSlice()), Port: 33434})
	if err != nil {
		return
	}
	_, _ = connection.Write([]byte{0})
	_ = connection.Close()
}

func readNeighborTable(targetIP netip.Addr) (net.HardwareAddr, error) {
	var size uint32
	result, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if uint32(result) == noErrorCode {
		return nil, nil
	}
	if uint32(result) != insufficient || size == 0 {
		return nil, fmt.Errorf("query IPv4 neighbor table: result %d", result)
	}
	buffer := make([]byte, size)
	result, _, _ = procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
	if uint32(result) != noErrorCode {
		return nil, fmt.Errorf("read IPv4 neighbor table: result %d", result)
	}
	entries := binary.LittleEndian.Uint32(buffer[:4])
	want := targetIP.AsSlice()
	offset := 4
	for index := uint32(0); index < entries; index++ {
		if offset+mibNetRowSize > len(buffer) {
			break
		}
		row := buffer[offset : offset+mibNetRowSize]
		length := binary.LittleEndian.Uint32(row[4:8])
		if length == 6 && bytes.Equal(row[16:20], want) {
			address := net.HardwareAddr(append([]byte(nil), row[8:14]...))
			if !isZeroHardwareAddress(address) {
				return address, nil
			}
		}
		offset += mibNetRowSize
	}
	return nil, nil
}

func isZeroHardwareAddress(address net.HardwareAddr) bool {
	if len(address) != 6 {
		return true
	}
	for _, octet := range address {
		if octet != 0 {
			return false
		}
	}
	return true
}
