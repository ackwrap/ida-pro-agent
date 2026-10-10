package transport

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func validatePeerIdentity(fd int, pid uint32) error {
	credential, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return err
	}
	peerPID, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return err
	}
	// XUCRED_VERSION is 0 in Darwin's sys/ucred.h (not exported by x/sys).
	if credential.Version != 0 || credential.Uid != uint32(os.Getuid()) ||
		peerPID <= 0 || uint32(peerPID) != pid {
		return errors.New("IDA socket peer identity does not match registry")
	}
	return nil
}
