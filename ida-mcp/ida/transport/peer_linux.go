package transport

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func validatePeerIdentity(fd int, pid uint32) error {
	credential, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return err
	}
	if credential.Uid != uint32(os.Getuid()) || uint32(credential.Pid) != pid {
		return errors.New("IDA socket peer identity does not match registry")
	}
	return nil
}
