//go:build windows

package gatewayauth

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protectSecret seals the authorization secret with Windows DPAPI under the
// current user account. Editing config.json on disk therefore cannot forge an
// authorization: the sealed blob only unprotects for the same Windows user on
// the same machine.
func protectSecret(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("empty authorization secret")
	}
	input := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("protect authorization secret: %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Size == 0 {
		return nil, errors.New("protect authorization secret: empty result")
	}
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}

// unprotectSecret reverses protectSecret for the current user.
func unprotectSecret(stored []byte) ([]byte, error) {
	if len(stored) == 0 {
		return nil, errors.New("empty protected secret")
	}
	input := windows.DataBlob{Size: uint32(len(stored)), Data: &stored[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("unprotect authorization secret: %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Size == 0 {
		return nil, errors.New("unprotect authorization secret: empty result")
	}
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}
