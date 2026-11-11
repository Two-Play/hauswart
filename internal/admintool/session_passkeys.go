package admintool

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/sign"
)

// PasskeyInfo is a passkey the way the app offers it for pinning.
type PasskeyInfo struct {
	// Key is the credential ID, base64url, the same the dashboard uses.
	Key         string
	ServerID    int64
	Name        string
	Owner       string
	Fingerprint string
	// Problem says why it cannot be pinned. It can still be removed.
	Problem string
	// PinnedOn are the devices it is pinned on from this computer.
	PinnedOn []string
}

// PinTarget is a device a passkey can be pinned on: named here and protected.
type PinTarget struct {
	ID   string
	Name string
}

// PinState is everything the passkeys window shows.
type PinState struct {
	Passkeys []PasskeyInfo
	Devices  []PinTarget
}

// PinChange adds a passkey to devices, or removes it from them.
type PinChange struct {
	Passkey string
	Devices []string
	Remove  bool
}

type pinPlan struct {
	id   string
	pins []sign.Passkey
}

func passkeyKey(credentialID []byte) string {
	return base64.RawURLEncoding.EncodeToString(credentialID)
}

// Pins lists the passkeys of the server and those pinned from here, and the
// devices they can go on.
func (s *Session) Pins() (PinState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return PinState{}, err
	}
	server, err := s.passkeyList()
	if err != nil {
		return PinState{}, err
	}
	list, err := s.devices()
	if err != nil {
		return PinState{}, err
	}
	var state PinState
	seen := map[string]int{}
	for _, p := range server {
		info := PasskeyInfo{
			Key:         passkeyKey(p.CredentialID),
			ServerID:    p.ID,
			Name:        clean(p.Name),
			Owner:       clean(p.Username),
			Fingerprint: sign.PasskeyFingerprint(sign.Passkey{PublicKey: p.PublicKey}),
		}
		if _, err := candidate(s.cfg, p, time.Now().Add(passkeyLifetime)); err != nil {
			info.Problem = clean(err.Error())
		}
		seen[info.Key] = len(state.Passkeys)
		state.Passkeys = append(state.Passkeys, info)
	}
	ids := make([]string, 0, len(s.cfg.Devices))
	for id := range s.cfg.Devices {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		known := s.cfg.Devices[id]
		if d, ok := list[id]; ok && !d.Revoked && d.Report != nil && d.Report.Protected && known.Name != "" {
			state.Devices = append(state.Devices, PinTarget{ID: id, Name: clean(known.Name)})
		}
		// What is pinned from here stays visible, so it can be removed even
		// once the server forgot it.
		for _, p := range known.Passkeys {
			key := passkeyKey(p.CredentialID)
			i, ok := seen[key]
			if !ok {
				i = len(state.Passkeys)
				seen[key] = i
				state.Passkeys = append(state.Passkeys, PasskeyInfo{
					Key:         key,
					Name:        clean(p.Name),
					Fingerprint: sign.PasskeyFingerprint(p),
					Problem:     "no longer on the server",
				})
			}
			state.Passkeys[i].PinnedOn = append(state.Passkeys[i].PinnedOn, id)
		}
	}
	return state, nil
}

// plan works out the new list of every device. It checks what the command line
// checks, and refuses the whole change if one device cannot take it.
func (s *Session) plan(c PinChange, server []serverPasskey, list map[string]serverDevice) ([]pinPlan, error) {
	if len(c.Devices) == 0 {
		return nil, errors.New("no device chosen")
	}
	var pin sign.Passkey
	if !c.Remove {
		i := slices.IndexFunc(server, func(p serverPasskey) bool { return passkeyKey(p.CredentialID) == c.Passkey })
		if i < 0 {
			return nil, errors.New("this passkey is no longer on the server")
		}
		var err error
		if pin, err = candidate(s.cfg, server[i], time.Now().Add(passkeyLifetime)); err != nil {
			return nil, err
		}
	}
	plans := make([]pinPlan, 0, len(c.Devices))
	for _, id := range c.Devices {
		known, err := knownDevice(s.cfg, id)
		if err != nil {
			return nil, err
		}
		if d, ok := list[id]; !ok || d.Revoked {
			return nil, fmt.Errorf("device %s is not on the server", clean(known.Name))
		}
		var pins []sign.Passkey
		if c.Remove {
			pins = slices.DeleteFunc(slices.Clone(known.Passkeys), func(p sign.Passkey) bool {
				return passkeyKey(p.CredentialID) == c.Passkey
			})
		} else if pins, err = withPin(known.Passkeys, pin); err != nil {
			return nil, fmt.Errorf("%s: %w", clean(known.Name), err)
		}
		plans = append(plans, pinPlan{id: id, pins: pins})
	}
	return plans, nil
}

func (s *Session) pinPreview(c PinChange) ([]pinPlan, map[string]serverDevice, string, error) {
	server, err := s.passkeyList()
	if err != nil {
		return nil, nil, "", err
	}
	list, err := s.devices()
	if err != nil {
		return nil, nil, "", err
	}
	plans, err := s.plan(c, server, list)
	if err != nil {
		return nil, nil, "", err
	}
	parts := make([]string, 0, len(plans)+1)
	for _, p := range plans {
		parts = append(parts, pinText(p.id, s.cfg.Devices[p.id], p.pins, list[p.id].Report))
	}
	parts = append(parts, pinWarning)
	return plans, list, strings.Join(parts, "\n"), nil
}

// PinPreview says what signing the change would do, in words.
func (s *Session) PinPreview(c PinChange) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return "", err
	}
	_, _, text, err := s.pinPreview(c)
	return text, err
}

// Pin signs the change, but only if it still reads as shown.
func (s *Session) Pin(c PinChange, shown string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return err
	}
	plans, list, text, err := s.pinPreview(c)
	if err != nil {
		return err
	}
	if text != shown {
		return ErrChanged
	}
	if s.key == nil {
		if s.key, err = s.signer(); err != nil {
			return err
		}
	}
	for _, p := range plans {
		if err := s.pinSend(s.key, list, p.id, p.pins); err != nil {
			s.key = nil
			return fmt.Errorf("%s: %w", clean(s.cfg.Devices[p.id].Name), err)
		}
	}
	return nil
}

// pinFuncs connects the pin methods to the server.
func (s *Session) pinFuncs() {
	cfg := s.cfg
	s.passkeyList = func() ([]serverPasskey, error) {
		var list []serverPasskey
		return list, cfg.call("GET", "/api/passkeys", nil, &list)
	}
	s.pinSend = func(key ssh.Signer, list map[string]serverDevice, id string, pins []sign.Passkey) error {
		return signPins(cfg, key, list, id, pins)
	}
}
