package main

import (
	"encoding/binary"
	"errors"
	"flag"
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

func serve(setupDir, pinText string) error {
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
	if setupDir != "" || pinText != "" {
		if setupDir == "" || pinText == "" {
			return errors.New("--setup and --manifest-sha256 must be supplied together")
		}
		pin, err := np.ParseDigest(pinText)
		if err != nil {
			return err
		}
		if err := service.LoadSetup(setupDir, pin); err != nil {
			return err
		}
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
	logger.Disable()
	var err error
	if len(os.Args) > 1 && os.Args[1] == "--stdio" {
		flags := flag.NewFlagSet("--stdio", flag.ContinueOnError)
		setup := flags.String("setup", "", "saved setup directory")
		pin := flags.String("manifest-sha256", "", "trusted setup manifest fingerprint")
		err = flags.Parse(os.Args[2:])
		if err == nil && flags.NArg() != 0 {
			err = errors.New("unexpected stdio arguments")
		}
		if err == nil {
			err = serve(*setup, *pin)
		}
	} else {
		err = artifactCommand(os.Args[1:], os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
