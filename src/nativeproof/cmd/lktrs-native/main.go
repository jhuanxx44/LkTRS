package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark/logger"
	"io"
	np "lktrs/nativeproof"
	"os"
	"syscall"
)

const limit = 16 << 20

// The stdio child is a local trusted research helper. Keep accidental runaway
// CPU/address-space use bounded when the host has not installed a stronger
// sandbox. These limits are deliberately conservative and are not a security
// boundary or a substitute for container/cgroup policy.
const (
	childCPUSeconds   = 15 * 60
	childAddressSpace = 4 << 30
)

func applyResourceLimits() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: childCPUSeconds, Max: childCPUSeconds}); err != nil {
		return fmt.Errorf("set CPU limit: %w", err)
	}
	// Darwin may expose RLIMIT_AS but reject it with EINVAL; in that case the
	// host must provide the address-space limit through its own sandbox.
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: childAddressSpace, Max: childAddressSpace}); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("set address-space limit: %w", err)
	}
	return nil
}

func serve() error {
	logger.Disable()
	if err := applyResourceLimits(); err != nil {
		return err
	}
	service := np.NewService()
	if statePath := os.Getenv("LKTRS_STATE_PATH"); statePath != "" {
		loaded, err := np.NewPersistentService(statePath)
		if err != nil {
			return err
		}
		service = loaded
	}
	for {
		var size uint32
		if e := binary.Read(os.Stdin, binary.BigEndian, &size); e != nil {
			if e == io.EOF {
				return nil
			}
			return e
		}
		if size > limit {
			return fmt.Errorf("frame exceeds %d bytes", limit)
		}
		raw := make([]byte, size)
		if _, e := io.ReadFull(os.Stdin, raw); e != nil {
			return e
		}
		response := service.Handle(raw)
		if len(response) > limit {
			return fmt.Errorf("response too large")
		}
		if e := binary.Write(os.Stdout, binary.BigEndian, uint32(len(response))); e != nil {
			return e
		}
		if _, e := os.Stdout.Write(response); e != nil {
			return e
		}
	}
}
func main() {
	if len(os.Args) != 2 || os.Args[1] != "--stdio" {
		fmt.Fprintln(os.Stderr, "usage: lktrs-native --stdio")
		os.Exit(2)
	}
	if e := serve(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
