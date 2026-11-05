// Command hauswart-server runs the dashboard and the agent endpoints.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/philippe/hauswart/internal/pki"
	"github.com/philippe/hauswart/internal/server"
	"github.com/philippe/hauswart/internal/store"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	addr := flag.String("addr", ":8443", "listen address")
	dataDir := flag.String("data", "/var/lib/hauswart-server", "data directory")
	publicURL := flag.String("url", "https://localhost:8443", "URL under which agents reach this server")
	extraHosts := flag.String("hosts", "", "additional comma-separated DNS names or IPs for the TLS certificate")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	ca, err := pki.LoadOrCreate(filepath.Join(*dataDir, "pki"))
	if err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "hauswart.db"))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := bootstrapAdmin(ctx, st); err != nil {
		return err
	}
	srv, err := server.New(st, ca, *publicURL, log)
	if err != nil {
		return err
	}
	u, err := url.Parse(*publicURL)
	if err != nil {
		return fmt.Errorf("-url: %w", err)
	}
	hosts := []string{"localhost", "127.0.0.1", "::1", u.Hostname()}
	if *extraHosts != "" {
		hosts = append(hosts, strings.Split(*extraHosts, ",")...)
	}
	tlsConfig, err := srv.TLSConfig(hosts)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // must exceed the long-poll wait
		IdleTimeout:       2 * time.Minute,
	}
	go srv.Janitor(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()

	log.Info("listening", "addr", *addr, "url", *publicURL, "ca_fingerprint", ca.Fingerprint())
	if err := httpServer.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// bootstrapAdmin creates the first account. The password is printed once and
// never stored in clear text.
func bootstrapAdmin(ctx context.Context, st *store.Store) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	password := store.RandomToken()[:24]
	hash, err := server.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, "admin", "admin", hash, "admin"); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nFirst start: created user \"admin\" with password %s\nThis is shown only once.\n\n", password)
	return nil
}
