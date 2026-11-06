package admintool

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

// passkeyLifetime ends a pin. Whether the server swapped a passkey when it was
// registered cannot be seen from here, so a pin has to be renewed on purpose.
const passkeyLifetime = 180 * 24 * time.Hour

type serverPasskey struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Name         string `json:"name"`
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
	RPID         string `json:"rp_id"`
	Origin       string `json:"origin"`
}

func passkeys(args []string) error {
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "list":
		return passkeysList()
	case "pin":
		return passkeysPin(args[1:])
	case "unpin":
		return passkeysUnpin(args[1:])
	case "renew":
		return passkeysRenew(args[1:])
	}
	usage()
	return nil
}

func passkeysList() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var list []serverPasskey
	if err := cfg.call("GET", "/api/passkeys", nil, &list); err != nil {
		return err
	}
	fmt.Println("Registered on the server, which proves nothing about them:")
	for _, p := range list {
		pin := sign.Passkey{PublicKey: p.PublicKey}
		fmt.Printf("  %d  %s, owner %s, %s\n", p.ID, clean(p.Name), clean(p.Username), sign.PasskeyFingerprint(pin))
	}
	for id, known := range cfg.Devices {
		if len(known.Passkeys) == 0 {
			continue
		}
		fmt.Printf("Pinned from here on %s (%s):\n", known.Name, id)
		for _, p := range known.Passkeys {
			fmt.Println(describePasskey(p))
		}
	}
	return nil
}

func describePasskey(p sign.Passkey) string {
	return fmt.Sprintf("  %s, %s, until %s", clean(p.Name), sign.PasskeyFingerprint(p), p.NotAfter.Local().Format(time.DateOnly))
}

// candidate turns what the server offers into a pin. The server could have
// swapped the key during registration, which nothing here can notice. What can
// be checked is that it belongs to the server this tool knows, and that the
// device would accept it.
func candidate(cfg *config, p serverPasskey, notAfter time.Time) (sign.Passkey, error) {
	pin := sign.Passkey{
		Name:         p.Name,
		CredentialID: p.CredentialID,
		PublicKey:    p.PublicKey,
		RPID:         p.RPID,
		Origin:       p.Origin,
		NotAfter:     notAfter,
	}
	if err := sign.ValidPasskey(pin); err != nil {
		return sign.Passkey{}, err
	}
	if p.Origin != cfg.Server {
		return sign.Passkey{}, fmt.Errorf("passkey belongs to %s, not to %s", clean(p.Origin), cfg.Server)
	}
	return pin, nil
}

func knownDevice(cfg *config, id string) (*device, error) {
	known := cfg.Devices[id]
	if known == nil || known.Name == "" {
		return nil, fmt.Errorf("device %s has no name here, check it and run hauswart-admin name", id)
	}
	return known, nil
}

func confirm(input io.Reader, question string) (bool, error) {
	fmt.Print(question + " [y/N] ")
	answer, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.ToLower(strings.TrimSpace(answer)) == "y", nil
}

// sendPins signs the complete list of a device and remembers it. keys.set
// replaces what is pinned, so this tool is what remembers it between runs.
func sendPins(cfg *config, id string, known *device, pins []sign.Passkey) error {
	fmt.Printf("Device: %s (%s)\nPasskeys after this change:\n", known.Name, id)
	for _, p := range pins {
		fmt.Println(describePasskey(p))
	}
	if len(pins) == 0 {
		fmt.Println("  none")
	}
	fmt.Println("A passkey can approve packages, Flatpaks, power and notifications on this device.\n" +
		"Do not pin one on the computer you sign on: a Flatpak could reach your signing key there.")
	ok, err := confirm(os.Stdin, "Sign?")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("nothing changed")
	}
	key, err := signer(cfg)
	if err != nil {
		return err
	}
	list, err := fetchDevices(cfg)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(api.KeysPayload{Keys: cfg.Keys, Passkeys: pins})
	if err != nil {
		return err
	}
	if err := api.Validate(api.TaskKeysSet, payload); err != nil {
		return err
	}
	signed, err := seal(cfg, key, id, list[id].Report, api.TaskKeysSet, payload, time.Now().Add(signedLifetime))
	if err != nil {
		return err
	}
	if err := cfg.call("POST", "/api/devices/"+id+"/signed-tasks", map[string]any{"type": api.TaskKeysSet, "signed": signed}, nil); err != nil {
		return err
	}
	known.Passkeys = pins
	return cfg.save()
}

func passkeysPin(args []string) error {
	fs := flag.NewFlagSet("passkeys pin", flag.ExitOnError)
	id := fs.String("device", "", "device ID")
	passkey := fs.Int64("passkey", 0, "number from hauswart-admin passkeys list")
	if err := deviceFlag(fs, args, id); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	known, err := knownDevice(cfg, *id)
	if err != nil {
		return err
	}
	var list []serverPasskey
	if err := cfg.call("GET", "/api/passkeys", nil, &list); err != nil {
		return err
	}
	index := slices.IndexFunc(list, func(p serverPasskey) bool { return p.ID == *passkey })
	if index < 0 {
		return fmt.Errorf("no passkey %d on the server", *passkey)
	}
	pin, err := candidate(cfg, list[index], time.Now().Add(passkeyLifetime))
	if err != nil {
		return err
	}
	pins := slices.DeleteFunc(slices.Clone(known.Passkeys), func(p sign.Passkey) bool {
		return string(p.CredentialID) == string(pin.CredentialID)
	})
	pins = append(pins, pin)
	if len(pins) > sign.MaxPasskeys {
		return fmt.Errorf("at most %d passkeys fit on a device", sign.MaxPasskeys)
	}
	return sendPins(cfg, *id, known, pins)
}

func passkeysUnpin(args []string) error {
	fs := flag.NewFlagSet("passkeys unpin", flag.ExitOnError)
	id := fs.String("device", "", "device ID")
	name := fs.String("name", "", "passkey name, all of them if empty")
	if err := deviceFlag(fs, args, id); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	known, err := knownDevice(cfg, *id)
	if err != nil {
		return err
	}
	pins := slices.DeleteFunc(slices.Clone(known.Passkeys), func(p sign.Passkey) bool {
		return *name == "" || p.Name == *name
	})
	return sendPins(cfg, *id, known, pins)
}

// passkeysRenew extends the pins as this tool recorded them, so a renewal does
// not take anything from the server.
func passkeysRenew(args []string) error {
	fs := flag.NewFlagSet("passkeys renew", flag.ExitOnError)
	id := fs.String("device", "", "device ID")
	if err := deviceFlag(fs, args, id); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	known, err := knownDevice(cfg, *id)
	if err != nil {
		return err
	}
	pins := slices.Clone(known.Passkeys)
	for i := range pins {
		pins[i].NotAfter = time.Now().Add(passkeyLifetime)
	}
	return sendPins(cfg, *id, known, pins)
}
