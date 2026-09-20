// lktrs-demo is a local research application, not a network signer service.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/consensys/gnark/logger"
)

func main() {
	logger.Disable()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	data := flag.String("data", "local/demo", "private local artifact directory")
	port := flag.Uint("port", 8787, "loopback HTTP port (0 chooses an available port)")
	setup := flag.String("setup", "", "optional locally trusted setup directory")
	pin := flag.String("manifest-sha256", "", "trusted pin, required with --setup")
	cli := flag.String("verifier", "local/demo/bin/lktrs-native", "independent verifier executable")
	flag.Parse()
	if flag.NArg() != 0 || *port > 65535 || (*setup == "") != (*pin == "") {
		return errors.New("invalid arguments; --setup and --manifest-sha256 must be supplied together")
	}
	root, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("demo data directory must be a private directory (mode 0700)")
	}
	lock, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another demo owns this data directory")
	}
	verifier, err := filepath.Abs(*cli)
	if err != nil {
		return err
	}
	info, err = os.Stat(verifier)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("build the independent verifier first, or use scripts/run-demo.sh")
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	defer listener.Close()
	app, err := newApp(config{root: root, setup: *setup, pin: *pin, cli: verifier}, listener.Addr().String())
	if err != nil {
		return err
	}
	fmt.Printf("Lk-TRS sensor cooperative: http://%s\nArtifacts: %s\nLocal research demo; synthetic readings, real proofs. Ctrl+C to stop.\n", listener.Addr(), root)
	server := &http.Server{Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return server.Serve(listener)
}
