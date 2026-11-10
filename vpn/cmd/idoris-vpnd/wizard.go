package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/enroll"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/netdetect"
)

type deps struct {
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	host     fileHost
	detect   func(mode string) (netdetect.Report, error)
	discover func(ctx context.Context, enrollURL, token string, allowInsecure bool) (*enroll.Discovery, error)
	home     func() (string, error)
	hostname func() (string, error)
	br       *bufio.Reader
}

func realDeps() deps {
	return deps{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		host: osHost{}, home: os.UserHomeDir, hostname: os.Hostname,
	}
}

func joinCmd(args []string, d deps) error {
	return errors.New("join: not implemented yet")
}
func gatewayCmd(args []string, d deps) error {
	return errors.New("gateway: not implemented yet")
}

func init() {
	var touch0 deps
	_ = touch0.detect
	_ = touch0.discover
	_ = touch0.br
}
