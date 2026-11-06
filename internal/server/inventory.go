package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

const (
	minSoftwareQuery = 2
	maxSoftwareQuery = 128
)

// minInventoryGap is below the pace of an agent, which looks once a minute.
var minInventoryGap = 30 * time.Second

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/inventory", s.admin(s.handleInventory))
		mux.Handle("GET /api/inventory.csv", s.admin(s.handleInventoryCSV))
		mux.Handle("GET /api/inventory/software", s.admin(s.handleSoftware))
		mux.Handle("GET /api/inventory/{id}", s.admin(s.handleInventoryDevice))
		mux.Handle("PUT /api/inventory/{id}/asset", s.admin(s.handleAsset))
	})
}

// inventoryDevice brings together what a device reports all the time, what it
// reports now and then, and what people added.
type inventoryDevice struct {
	ID           string                 `json:"id"`
	Hostname     string                 `json:"hostname"`
	Revoked      bool                   `json:"revoked"`
	LastSeen     int64                  `json:"last_seen"`
	Distro       string                 `json:"distro,omitempty"`
	Kernel       string                 `json:"kernel,omitempty"`
	CPUs         int                    `json:"cpus,omitempty"`
	MemTotal     uint64                 `json:"mem_total,omitempty"`
	DiskTotal    uint64                 `json:"disk_total,omitempty"`
	AgentVersion string                 `json:"agent_version,omitempty"`
	Updates      *api.UpdateStatus      `json:"updates,omitempty"`
	Inventory    *store.StoredInventory `json:"inventory,omitempty"`
	Asset        api.Asset              `json:"asset"`
	Warnings     []api.Warning          `json:"warnings,omitempty"`
	// Packages is only there for a single device.
	Packages []api.Package `json:"packages,omitempty"`
}

func (s *Server) handleAgentInventory(w http.ResponseWriter, r *http.Request, id string) {
	// The database has one connection, which reports need as well.
	last, err := s.store.InventoryUpdated(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	if time.Since(last) < minInventoryGap {
		fail(w, http.StatusTooManyRequests, api.ErrInventoryTooOften)
		return
	}
	var inventory api.Inventory
	if !readJSON(w, r, &inventory) {
		return
	}
	if err := inventory.Check(); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SaveInventory(r.Context(), id, inventory); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) inventoryDevices(ctx context.Context) ([]inventoryDevice, error) {
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	inventories, err := s.store.Inventories(ctx)
	if err != nil {
		return nil, err
	}
	assets, err := s.store.Assets(ctx)
	if err != nil {
		return nil, err
	}
	list := make([]inventoryDevice, 0, len(devices))
	for _, d := range devices {
		entry := inventoryDevice{ID: d.ID, Hostname: d.Hostname, Revoked: d.Revoked, LastSeen: d.LastSeen,
			Asset: assets[d.ID], Warnings: deviceWarnings(d, assets[d.ID])}
		if report := d.Report; report != nil {
			entry.Distro, entry.Kernel, entry.CPUs = report.Distro, report.Kernel, report.CPUs
			entry.MemTotal, entry.DiskTotal, entry.AgentVersion = report.MemTotal, report.DiskTotal, report.AgentVersion
			entry.Updates = report.Updates
		}
		if stored, ok := inventories[d.ID]; ok {
			entry.Inventory = &stored
		}
		list = append(list, entry)
	}
	return list, nil
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request, _ store.User) {
	list, err := s.inventoryDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleInventoryDevice(w http.ResponseWriter, r *http.Request, _ store.User) {
	list, err := s.inventoryDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	id := r.PathValue("id")
	for _, entry := range list {
		if entry.ID != id {
			continue
		}
		if entry.Packages, err = s.store.DevicePackages(r.Context(), id); err != nil {
			s.internal(w, err)
			return
		}
		writeJSON(w, http.StatusOK, entry)
		return
	}
	fail(w, http.StatusNotFound, api.ErrNoSuchDevice)
}

func (s *Server) handleSoftware(w http.ResponseWriter, r *http.Request, _ store.User) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	result := struct {
		Entries []store.SoftwareEntry `json:"entries"`
		More    bool                  `json:"more"`
	}{Entries: []store.SoftwareEntry{}}
	if len(query) >= minSoftwareQuery && len(query) <= maxSoftwareQuery {
		var err error
		if result.Entries, result.More, err = s.store.FindSoftware(r.Context(), query); err != nil {
			s.internal(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request, u store.User) {
	var asset api.Asset
	if !readJSON(w, r, &asset) {
		return
	}
	if err := asset.Check(); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	id := r.PathValue("id")
	err := s.store.SaveAsset(r.Context(), id, asset, u.Username)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchDevice)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "inventory.asset", id)
	w.WriteHeader(http.StatusNoContent)
}

// formulaStarts are what a spreadsheet reads as the start of a formula, also in
// their wide forms.
const formulaStarts = "=+-@\t\r\n＝＋－＠"

// csvSafe keeps a spreadsheet from reading a value as a formula. A device chooses
// its own name, and the person who opens the file trusts it.
func csvSafe(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed != "" && strings.ContainsRune(formulaStarts, []rune(trimmed)[0]) {
		return "'" + value
	}
	return value
}

// csvLine quotes every field. A German spreadsheet separates at a semicolon, which
// encoding/csv leaves bare, so a name could start a cell of its own.
func csvLine(fields []string) string {
	quoted := make([]string, len(fields))
	for i, field := range fields {
		quoted[i] = `"` + strings.ReplaceAll(field, `"`, `""`) + `"`
	}
	return strings.Join(quoted, ",") + "\r\n"
}

var inventoryColumns = []string{"id", "hostname", "status", "last_seen", "inventory_updated", "tag", "person", "location", "purchased", "warranty_until", "note",
	"vendor", "model", "serial", "bios", "cpu", "cpus", "memory_bytes", "disks", "mac", "ip", "distro", "kernel", "agent_version",
	"disk_encryption", "screen_lock", "firewall", "updates_pending", "packages"}

func inventoryRow(d inventoryDevice) []string {
	status := "active"
	if d.Revoked {
		status = "revoked"
	}
	var stored store.StoredInventory
	if d.Inventory != nil {
		stored = *d.Inventory
	}
	var disks, macs, addresses []string
	for _, disk := range stored.Disks {
		disks = append(disks, strings.TrimSpace(fmt.Sprintf("%s %s %d", disk.Name, disk.Model, disk.Size)))
	}
	for _, card := range stored.Network {
		macs = append(macs, card.MAC)
		addresses = append(addresses, card.Addresses...)
	}
	lastSeen, taken, pending, packages := "", "", "", ""
	if d.LastSeen > 0 {
		lastSeen = time.Unix(d.LastSeen, 0).UTC().Format(time.RFC3339)
	}
	if d.Inventory != nil {
		taken = time.Unix(d.Inventory.UpdatedAt, 0).UTC().Format(time.RFC3339)
	}
	if d.Updates != nil && d.Updates.CheckedAt != nil {
		pending = strconv.Itoa(d.Updates.Pending)
	}
	if d.Inventory != nil {
		packages = strconv.Itoa(stored.PackageCount)
	}
	row := []string{d.ID, d.Hostname, status, lastSeen, taken, d.Asset.Tag, d.Asset.Person, d.Asset.Location, d.Asset.Purchased, d.Asset.WarrantyUntil, d.Asset.Note,
		stored.Hardware.Vendor, stored.Hardware.Model, stored.Hardware.Serial, stored.Hardware.BIOS, stored.Hardware.CPU,
		strconv.Itoa(d.CPUs), strconv.FormatUint(d.MemTotal, 10), strings.Join(disks, "; "), strings.Join(macs, "; "), strings.Join(addresses, "; "),
		d.Distro, d.Kernel, d.AgentVersion, stored.Security.DiskEncryption, stored.Security.ScreenLock, stored.Security.Firewall, pending, packages}
	for i, value := range row {
		row[i] = csvSafe(value)
	}
	return row
}

func (s *Server) handleInventoryCSV(w http.ResponseWriter, r *http.Request, u store.User) {
	list, err := s.inventoryDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "inventory.export", strconv.Itoa(len(list))+" devices")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hauswart-inventory.csv"`)
	// Without the mark, Excel reads the file as an old code page.
	var out strings.Builder
	out.WriteString("\xef\xbb\xbf" + csvLine(inventoryColumns))
	for _, d := range list {
		out.WriteString(csvLine(inventoryRow(d)))
	}
	if _, err := w.Write([]byte(out.String())); err != nil {
		s.log.Warn("writing the inventory failed", "err", err)
	}
}
