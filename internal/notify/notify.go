// Package notify tells admins about events through ntfy and email. It sends in
// the background, so a slow or dead mail server never holds up a request.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Two-Play/hauswart/internal/envfile"
)

// Subject is the subject of a mail. It comes from this fixed set, so nothing
// from a request or a device reaches a header.
type Subject string

const (
	SubjectRequest   Subject = "New request in Hauswart"
	SubjectAttention Subject = "Something needs attention in Hauswart"
)

// item is a message on its way.
type item struct {
	subject Subject
	message string
}

const (
	title        = "Hauswart"
	queueSize    = 64
	maxPerHour   = 30
	sendTimeout  = 30 * time.Second
	sendAttempts = 3
	defaultSMTP  = "587"
	tlsStart     = "starttls"
	tlsImplicit  = "tls"
	tlsNone      = "none"
)

// retryDelay is a variable so tests need not wait.
var retryDelay = 10 * time.Second

// Config holds the credentials from notify.env.
type Config struct {
	NtfyURL      string
	NtfyToken    string
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPTo       []string
	SMTPTLS      string
}

// Load reads the file. A missing file means nothing is configured. Anything
// else that is wrong is an error, because a typo should not silently end
// notifications, and neither should credentials be used from a file others can
// read.
func Load(path string) (Config, error) {
	var cfg Config
	found, err := envfile.Read(path, cfg.set)
	if err != nil {
		return Config{}, err
	}
	if !found {
		return cfg, nil
	}
	if err := cfg.check(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) set(key, value string) bool {
	switch key {
	case "NTFY_URL":
		c.NtfyURL = value
	case "NTFY_TOKEN":
		c.NtfyToken = value
	case "SMTP_HOST":
		c.SMTPHost = value
	case "SMTP_PORT":
		c.SMTPPort = value
	case "SMTP_USER":
		c.SMTPUser = value
	case "SMTP_PASSWORD":
		c.SMTPPassword = value
	case "SMTP_FROM":
		c.SMTPFrom = value
	case "SMTP_TO":
		c.SMTPTo = nil
		for _, to := range strings.Split(value, ",") {
			if to = strings.TrimSpace(to); to != "" {
				c.SMTPTo = append(c.SMTPTo, to)
			}
		}
	case "SMTP_TLS":
		c.SMTPTLS = value
	default:
		return false
	}
	return true
}

func (c *Config) check() error {
	if c.NtfyURL != "" {
		u, err := url.Parse(c.NtfyURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return errors.New("NTFY_URL must be an http or https URL with the topic")
		}
		if c.NtfyToken != "" && u.Scheme != "https" && !loopback(u.Hostname()) {
			return errors.New("NTFY_TOKEN needs https")
		}
	}
	if c.SMTPHost == "" {
		return nil
	}
	if c.SMTPPort == "" {
		c.SMTPPort = defaultSMTP
	}
	if c.SMTPTLS == "" {
		c.SMTPTLS = tlsStart
	}
	if c.SMTPTLS != tlsStart && c.SMTPTLS != tlsImplicit && c.SMTPTLS != tlsNone {
		return errors.New("SMTP_TLS must be starttls, tls or none")
	}
	if c.SMTPTLS == tlsNone && c.SMTPPassword != "" && !loopback(c.SMTPHost) {
		return errors.New("SMTP_PASSWORD needs SMTP_TLS starttls or tls")
	}
	if len(c.SMTPTo) == 0 {
		return errors.New("SMTP_TO is missing")
	}
	for _, address := range append([]string{c.SMTPFrom}, c.SMTPTo...) {
		if _, err := mail.ParseAddress(address); err != nil {
			return errors.New("SMTP_FROM and SMTP_TO must be mail addresses")
		}
	}
	return nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// Enabled says whether any channel is configured.
func (c Config) Enabled() bool { return len(c.Channels()) > 0 }

// Channels names the configured channels.
func (c Config) Channels() []string {
	var channels []string
	if c.NtfyURL != "" {
		channels = append(channels, "ntfy")
	}
	if c.SMTPHost != "" {
		channels = append(channels, "email")
	}
	return channels
}

// Notifier delivers messages one after the other.
type Notifier struct {
	cfg    Config
	log    *slog.Logger
	roots  *x509.CertPool
	client *http.Client
	queue  chan item

	mu          sync.Mutex
	windowStart time.Time
	sent        int
}

// New creates a Notifier that trusts roots for TLS.
func New(cfg Config, roots *x509.CertPool, log *slog.Logger) *Notifier {
	return &Notifier{
		cfg:   cfg,
		log:   log,
		roots: roots,
		queue: make(chan item, queueSize),
		client: &http.Client{
			Timeout:   sendTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
			// A token must not follow a redirect somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Send queues a message and returns at once. A member can file requests at any
// rate, so the number of messages is limited, and the dashboard still shows
// everything that is dropped here.
// Send queues a message about a new request.
func (n *Notifier) Send(message string) { n.SendAs(SubjectRequest, message) }

// SendAs queues a message with one of the fixed subjects.
func (n *Notifier) SendAs(subject Subject, message string) {
	if !n.allow(time.Now()) {
		n.log.Warn("too many notifications this hour, dropping one")
		return
	}
	select {
	case n.queue <- item{subject, message}:
	default:
		n.log.Warn("notification queue is full, dropping one")
	}
}

func (n *Notifier) allow(now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if now.Sub(n.windowStart) >= time.Hour {
		n.windowStart, n.sent = now, 0
	}
	if n.sent >= maxPerHour {
		return false
	}
	n.sent++
	return true
}

// Run delivers until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case it := <-n.queue:
			if n.cfg.NtfyURL != "" {
				n.deliver(ctx, "ntfy", func(ctx context.Context) error { return n.sendNtfy(ctx, it.message) })
			}
			if n.cfg.SMTPHost != "" {
				n.deliver(ctx, "email", func(ctx context.Context) error { return n.sendMail(ctx, it.subject, it.message) })
			}
		}
	}
}

func (n *Notifier) deliver(ctx context.Context, channel string, send func(context.Context) error) {
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := send(attemptCtx)
		cancel()
		if err == nil {
			return
		}
		n.log.Warn("sending a notification failed", "channel", channel, "attempt", attempt, "err", loggable(err))
		if attempt == sendAttempts {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
	}
}

// loggable drops the URL from HTTP errors, because an ntfy topic works like a
// password: whoever knows it can read along.
func loggable(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func (n *Notifier) sendNtfy(ctx context.Context, message string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.NtfyURL, strings.NewReader(message))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if n.cfg.NtfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.cfg.NtfyToken)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy answered with status %d", resp.StatusCode)
	}
	return nil
}

// sendMail refuses to go on without TLS when TLS was asked for: a server, or
// someone in between, that leaves out STARTTLS must not get the password.
func (n *Notifier) sendMail(ctx context.Context, subject Subject, message string) error {
	dialer := net.Dialer{}
	address := net.JoinHostPort(n.cfg.SMTPHost, n.cfg.SMTPPort)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	tlsConfig := &tls.Config{ServerName: n.cfg.SMTPHost, RootCAs: n.roots, MinVersion: tls.VersionTLS12}
	if n.cfg.SMTPTLS == tlsImplicit {
		conn = tls.Client(conn, tlsConfig)
	}
	client, err := smtp.NewClient(conn, n.cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()
	if n.cfg.SMTPTLS == tlsStart {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("mail server offers no STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if n.cfg.SMTPUser != "" {
		if err := client.Auth(smtp.PlainAuth("", n.cfg.SMTPUser, n.cfg.SMTPPassword, n.cfg.SMTPHost)); err != nil {
			return err
		}
	}
	from, err := mail.ParseAddress(n.cfg.SMTPFrom)
	if err != nil {
		return err
	}
	if err := client.Mail(from.Address); err != nil {
		return err
	}
	for _, to := range n.cfg.SMTPTo {
		parsed, err := mail.ParseAddress(to)
		if err != nil {
			return err
		}
		if err := client.Rcpt(parsed.Address); err != nil {
			return err
		}
	}
	body, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := body.Write(n.mailText(subject, message)); err != nil {
		return err
	}
	if err := body.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// mailText has a subject from a fixed set, so nothing from a request reaches a header.
func (n *Notifier) mailText(subject Subject, message string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n", n.cfg.SMTPFrom, strings.Join(n.cfg.SMTPTo, ", "),
		subject, time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(message, "\n", "\r\n"))
	b.WriteString("\r\n")
	return b.Bytes()
}
