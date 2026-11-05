// Command hauswart-agent enrolls a device and runs the management service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/philippe/hauswart/internal/agent"
)

const defaultDir = "/var/lib/hauswart"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(ctx, os.Args[2:])
	case "run":
		err = run(ctx, os.Args[2:], log)
	case "version":
		fmt.Println(agent.Version)
	default:
		usage()
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hauswart-agent enroll --server URL --token T --ca-fingerprint F\n       hauswart-agent run\n       hauswart-agent version")
	os.Exit(2)
}

func enroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "state directory")
	server := fs.String("server", "", "server URL")
	token := fs.String("token", "", "one-time enrollment token")
	fingerprint := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the server CA")
	fs.Parse(args)
	if *server == "" || *token == "" || *fingerprint == "" {
		return fmt.Errorf("--server, --token and --ca-fingerprint are required")
	}
	if err := agent.Enroll(ctx, *dir, *server, *token, *fingerprint); err != nil {
		return err
	}
	// Not fatal: the agent pins the CA itself and works without this.
	if err := agent.TrustServerCA(ctx, *dir); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: could not add the server CA to the system store:", err)
	}
	fmt.Println("Enrolled. Start the service with: systemctl enable --now hauswart-agent")
	return nil
}

func run(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "state directory")
	fs.Parse(args)
	a, err := agent.Load(*dir, log)
	if err != nil {
		return err
	}
	a.Run(ctx)
	return nil
}
