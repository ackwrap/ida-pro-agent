//go:build windows

package webmanager

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	ioReparseTagMountPoint = 0xA0000003
	fsctlSetReparsePoint   = 0x000900A4
	fsctlGetReparsePoint   = 0x000900A8
)

func createDirectoryLink(path, target string) (returnError error) {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}

	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_WRITE|windows.DELETE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		if cleanupError := os.Remove(path); cleanupError != nil {
			return errors.Join(err, fmt.Errorf("clean failed skill link directory: %w", cleanupError))
		}
		return err
	}
	created := false
	defer func() {
		if !created {
			if err := markHandleForDeletion(handle); err != nil {
				returnError = errors.Join(returnError, fmt.Errorf("clean failed skill link: %w", err))
			}
		}
		if err := windows.CloseHandle(handle); err != nil {
			returnError = errors.Join(returnError, fmt.Errorf("close skill link handle: %w", err))
		}
	}()

	substitute := `\??\` + target
	if strings.HasPrefix(target, `\\`) {
		substitute = `\??\UNC\` + strings.TrimPrefix(target, `\\`)
	}
	substituteName := utf16.Encode([]rune(substitute))
	printName := utf16.Encode([]rune(target))
	pathBytes := (len(substituteName) + 1 + len(printName) + 1) * 2
	dataLength := 8 + pathBytes
	if dataLength > 0xffff {
		return fmt.Errorf("skill link target is too long")
	}
	buffer := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(buffer[0:4], ioReparseTagMountPoint)
	binary.LittleEndian.PutUint16(buffer[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(buffer[8:10], 0)
	binary.LittleEndian.PutUint16(buffer[10:12], uint16(len(substituteName)*2))
	binary.LittleEndian.PutUint16(buffer[12:14], uint16((len(substituteName)+1)*2))
	binary.LittleEndian.PutUint16(buffer[14:16], uint16(len(printName)*2))
	offset := 16
	for _, value := range substituteName {
		binary.LittleEndian.PutUint16(buffer[offset:offset+2], value)
		offset += 2
	}
	offset += 2
	for _, value := range printName {
		binary.LittleEndian.PutUint16(buffer[offset:offset+2], value)
		offset += 2
	}
	var returned uint32
	if err := windows.DeviceIoControl(
		handle,
		fsctlSetReparsePoint,
		&buffer[0],
		uint32(len(buffer)),
		nil,
		0,
		&returned,
		nil,
	); err != nil {
		return err
	}
	created = true
	return nil
}

func removeManagedDirectoryLink(path, expectedTarget string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	target, err := readJunctionTarget(handle)
	if err != nil {
		return err
	}
	if !samePath(target, expectedTarget) {
		return fmt.Errorf("skill path is not managed by this ida-mcp installation")
	}
	if err := markHandleForDeletion(handle); err != nil {
		return err
	}
	return nil
}

func markHandleForDeletion(handle windows.Handle) error {
	deleteOnClose := []byte{1}
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		&deleteOnClose[0],
		uint32(len(deleteOnClose)),
	)
}

func readJunctionTarget(handle windows.Handle) (string, error) {
	buffer := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var returned uint32
	if err := windows.DeviceIoControl(
		handle,
		fsctlGetReparsePoint,
		nil,
		0,
		&buffer[0],
		uint32(len(buffer)),
		&returned,
		nil,
	); err != nil {
		return "", fmt.Errorf("read skill junction: %w", err)
	}
	if returned < 16 || binary.LittleEndian.Uint32(buffer[0:4]) != ioReparseTagMountPoint {
		return "", fmt.Errorf("skill path is not a directory junction")
	}
	nameOffset := int(binary.LittleEndian.Uint16(buffer[8:10]))
	nameLength := int(binary.LittleEndian.Uint16(buffer[10:12]))
	start := 16 + nameOffset
	end := start + nameLength
	if nameLength%2 != 0 || start < 16 || end > int(returned) {
		return "", fmt.Errorf("skill junction target is invalid")
	}
	name := make([]uint16, 0, nameLength/2)
	for offset := start; offset < end; offset += 2 {
		name = append(name, binary.LittleEndian.Uint16(buffer[offset:offset+2]))
	}
	target := string(utf16.Decode(name))
	if strings.HasPrefix(target, `\??\UNC\`) {
		return `\\` + strings.TrimPrefix(target, `\??\UNC\`), nil
	}
	return strings.TrimPrefix(target, `\??\`), nil
}
