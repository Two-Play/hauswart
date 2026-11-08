// Package agentclient talks to the agent on this device, over its socket.
package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// DefaultSocket is where the agent listens.
const DefaultSocket = "/run/hauswart/user.sock"

const timeout = 10 * time.Second

// ErrTooMany says that someone asked too often.
var ErrTooMany = errors.New("too many requests")

// ErrUnreachable says that the agent or its server could not be reached.
var ErrUnreachable = errors.New("not reachable")

// Refused says that the server did not take a request, with its error code.
type Refused struct{ Code string }

func (r Refused) Error() string { return r.Code }

// Client asks the agent. The agent knows who is asking from the kernel, so there
// is nothing to log in with.
type Client struct {
	http *http.Client
}

func New(socket string) *Client {
	return &Client{http: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}}
}

// Status returns what the agent says about the person running this.
func (c *Client) Status() (api.UserStatus, error) {
	var status api.UserStatus
	resp, err := c.http.Get("http://agent/status")
	if err != nil {
		return status, ErrUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return status, fmt.Errorf("status %d", resp.StatusCode)
	}
	return status, json.NewDecoder(resp.Body).Decode(&status)
}

// Request files a request.
// Request files a request and returns its status: approved when a rule approved
// it at once, open when someone still decides.
func (c *Client) Request(r api.UserRequest) (string, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Post("http://agent/request", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", ErrUnreachable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated:
		var answer api.RequestAnswer
		// An older agent sends nothing, which means that someone decides.
		json.NewDecoder(io.LimitReader(resp.Body, 300)).Decode(&answer)
		return answer.Normalized(), nil
	case http.StatusTooManyRequests:
		return "", ErrTooMany
	case http.StatusBadGateway:
		return "", ErrUnreachable
	}
	text, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return "", Refused{Code: strings.TrimSpace(string(text))}
	}
	return "", errors.New(strings.TrimSpace(string(text)))
}
