// Command hauswart-server runs the dashboard and the agent endpoints.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/philippe/hauswart/internal/backup"
	"github.com/philippe/hauswart/internal/pki"
	"github.com/philippe/hauswart/internal/server"
	"github.com/philippe/hauswart/internal/store"
)

const (
	initialPasswordFile = "initial-admin-password"
	defaultDataDir      = "/var/lib/hauswart-server"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	command := run
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "backup":
			command = runBackup
		case "restore":
			command = runRestore
		}
	}
	if err := command(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	dataDir := flag.String("data", defaultDataDir, "data directory")
	publicURL := flag.String("url", "https://localhost:8443", "URL under which agents reach this server")
	extraHosts := flag.String("hosts", "", "additional comma-separated DNS names or IPs for the TLS certificate")
	deviceValidity := flag.Duration("device-cert-validity", 0, "testing only: lifetime of device certificates")
	caScope := flag.String("ca-scope", "", "comma-separated domains and CIDR ranges a new CA may issue for, in addition to the server's own addresses; cannot be changed later")
	devHTTP := flag.String("dev-http", "", "development only: also serve the dashboard without TLS on this loopback address")
	notifyEnv := flag.String("notify-env", "/etc/hauswart/notify.env", "file with the credentials for admin notifications, mode 0600")
	oidcEnv := flag.String("oidc-env", "/etc/hauswart/oidc.env", "file with the settings for login through Authentik, mode 0600")
	flag.Parse()

	if *devHTTP != "" && !isLoopback(*devHTTP) {
		return fmt.Errorf("-dev-http must be a loopback address, got %q", *devHTTP)
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
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
	permitted := hosts
	if *caScope != "" {
		permitted = append(slices.Clone(hosts), strings.Split(*caScope, ",")...)
	}
	ca, err := pki.LoadOrCreate(filepath.Join(*dataDir, "pki"), permitted...)
	if err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	ca.DeviceValidity = *deviceValidity
	st, err := store.Open(filepath.Join(*dataDir, "hauswart.db"))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := bootstrapAdmin(ctx, st, *dataDir, log); err != nil {
		return err
	}
	srv, err := server.New(st, ca, *publicURL, log)
	if err != nil {
		return err
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
	if *devHTTP != "" {
		dev := &http.Server{Addr: *devHTTP, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		log.Warn("serving without TLS for development", "addr", *devHTTP)
		go func() {
			if err := dev.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.Error("dev listener failed", "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			dev.Close()
		}()
	}
	srv.StartNotifications(ctx, *notifyEnv)
	srv.StartOIDC(*oidcEnv)
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

// runBackup writes the archive. It holds the CA key, so it is private.
func runBackup(*slog.Logger) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir, "data directory")
	out := fs.String("out", "", "archive to create")
	fs.Parse(os.Args[2:])
	if *out == "" {
		return errors.New("-out is required")
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := backup.Create(context.Background(), *dataDir, f); err != nil {
		f.Close()
		os.Remove(*out)
		return err
	}
	return f.Close()
}

func runRestore(*slog.Logger) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir, "data directory, must not hold a database")
	in := fs.String("in", "", "archive to restore")
	fs.Parse(os.Args[2:])
	if *in == "" {
		return errors.New("-in is required")
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	return backup.Restore(*dataDir, f)
}

// isLoopback keeps the unencrypted development listener off the network.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// bootstrapAdmin creates the first account. The password goes to a file only
// the service can read, because anything printed would stay in the journal.
func bootstrapAdmin(ctx context.Context, st *store.Store, dataDir string, log *slog.Logger) error {
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
	path := filepath.Join(dataDir, initialPasswordFile)
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		return err
	}
	log.Info("created user admin, change the password after the first login", "password_file", path)
	return nil
}
