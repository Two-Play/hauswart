package admintool

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/coder/websocket"
	"golang.org/x/term"

	"github.com/Two-Play/hauswart/internal/api"
)

// terminal signs a live shell and connects to it, as the dashboard does with
// a passkey. Asking for it here is the decision, so it signs without asking
// again, but only what it asked for.
func terminal(args []string) error {
	fs := flag.NewFlagSet("terminal", flag.ExitOnError)
	deviceID := fs.String("device", "", "device ID")
	user := fs.String("user", api.TerminalRoot, "Linux user the shell runs as")
	minutes := fs.Int("minutes", api.DefaultTerminalMinutes, "minutes until the session ends")
	fs.Parse(args)
	if *deviceID == "" {
		usage()
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	key, err := signer(cfg)
	if err != nil {
		return err
	}
	list, err := fetchDevices(cfg)
	if err != nil {
		return err
	}
	var opened struct {
		ID      string `json:"id"`
		Session string `json:"session"`
	}
	if err := cfg.call("POST", "/api/devices/"+*deviceID+"/terminal", map[string]any{"user": *user, "minutes": *minutes}, &opened); err != nil {
		return err
	}
	var queue []queued
	if err := cfg.call("GET", "/api/signing", nil, &queue); err != nil {
		return err
	}
	var task *queued
	for i := range queue {
		if queue[i].ID == opened.ID {
			task = &queue[i]
		}
	}
	if task == nil || task.DeviceID != *deviceID || task.Type != api.TaskTerminalOpen {
		return errors.New("the server did not queue the session it announced")
	}
	item := prepare(cfg, list, *task, nil)
	if item.Problem != "" {
		return errors.New(item.Problem)
	}
	var p api.TerminalPayload
	if err := json.Unmarshal(item.payload, &p); err != nil {
		return err
	}
	if p.User != *user || p.Minutes != *minutes || p.Session != opened.Session {
		return errors.New("the server queued a different session than was asked for, refusing to sign it")
	}
	fmt.Fprintf(os.Stderr, "Device: %s (%s)\n  %s\n", item.DeviceName, item.DeviceID, item.Text)
	if err := signItem(cfg, key, list, item); err != nil {
		return err
	}
	return connectTerminal(cfg, opened.Session)
}

func connectTerminal(cfg *config, session string) error {
	client, err := cfg.client()
	if err != nil {
		return err
	}
	// The session lasts longer than any request.
	client.Timeout = 0
	header := http.Header{}
	header.Add("Cookie", (&http.Cookie{Name: sessionCookie, Value: cfg.Session}).String())
	ctx := context.Background()
	conn, _, err := websocket.Dial(ctx, cfg.Server+"/api/terminal/"+session, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 10)

	stdin := int(os.Stdin.Fd())
	interactive := term.IsTerminal(stdin)
	if interactive {
		state, err := term.MakeRaw(stdin)
		if err != nil {
			return err
		}
		defer term.Restore(stdin, state)
	}
	sendSize := func() {
		cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			return
		}
		raw, _ := json.Marshal(map[string]any{"resize": map[string]int{"cols": cols, "rows": rows}})
		conn.Write(ctx, websocket.MessageText, raw)
	}
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, syscall.SIGWINCH)
	defer signal.Stop(resized)
	go func() {
		for range resized {
			sendSize()
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if conn.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				// Without a terminal, the input may end before the shell
				// does; what it still prints is worth waiting for.
				return
			}
		}
	}()

	exit := -1
	opened := false
	reason := "connection closed"
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) && ce.Reason != "" {
				reason = ce.Reason
			}
			fmt.Fprintf(os.Stderr, "\r\n[session ended: %s]\r\n", clean(reason))
			break
		}
		if kind == websocket.MessageBinary {
			os.Stdout.Write(data)
			continue
		}
		var message struct {
			State string `json:"state"`
			Exit  *int   `json:"exit"`
		}
		if json.Unmarshal(data, &message) != nil {
			continue
		}
		switch {
		case message.State == "waiting":
			fmt.Fprint(os.Stderr, "[waiting for the device]\r\n")
		case message.State == "open":
			opened = true
			sendSize()
		case message.Exit != nil:
			exit = *message.Exit
		}
	}
	if !opened {
		return fmt.Errorf("the device did not open the session: %s", clean(reason))
	}
	if exit > 0 {
		return fmt.Errorf("the shell ended with code %d", exit)
	}
	return nil
}
