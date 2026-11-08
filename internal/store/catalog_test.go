package store

import (
	"context"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestCatalogSearch(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	device(t, s, "a")
	device(t, s, "b")
	catalog := api.NewCatalog([]string{"vim", "vim-enhanced", "neovim", "gvim", "emacs", "vi_m"})
	if ok, err := s.LinkCatalog(ctx, "a", catalog.Hash); err != nil || ok {
		t.Fatalf("linked an unknown catalog: %v %v", ok, err)
	}
	if err := s.SaveCatalog(ctx, "a", catalog); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.LinkCatalog(ctx, "b", catalog.Hash); err != nil || !ok {
		t.Fatalf("second device: %v %v", ok, err)
	}
	if err := s.SaveInventory(ctx, "b", api.Inventory{Packages: []api.Package{
		{Kind: api.PackageSystem, Name: "vim-minimal", Version: "9.1"},
		{Kind: api.PackageFlatpak, Name: "org.vim.Vim", Version: "9.1"},
	}}); err != nil {
		t.Fatal(err)
	}

	hits, err := s.SearchPackages(ctx, Scope{Devices: []string{"a", "b"}}, api.SearchPackage, "vim", 10)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, hit := range hits {
		names = append(names, hit.Name)
		if hit.Installed != (hit.Name == "vim-minimal") {
			t.Errorf("%s installed: %v", hit.Name, hit.Installed)
		}
	}
	want := []string{"vim", "vim-minimal", "vim-enhanced", "gvim", "neovim"}
	if len(names) != len(want) {
		t.Fatalf("got %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got %v, want %v", names, want)
		}
	}

	// The wildcards of LIKE are letters here.
	if hits, _ := s.SearchPackages(ctx, Scope{All: true}, api.SearchPackage, "i_m", 10); len(hits) != 1 || hits[0].Name != "vi_m" {
		t.Fatalf("got %+v", hits)
	}
	if hits, _ := s.SearchPackages(ctx, Scope{Devices: []string{"a"}}, api.SearchFlatpak, "vim", 10); len(hits) != 0 {
		t.Fatalf("flatpak of another device: %+v", hits)
	}
	if hits, _ := s.SearchPackages(ctx, Scope{}, api.SearchPackage, "vim", 10); len(hits) != 0 {
		t.Fatalf("empty scope: %+v", hits)
	}
	installed, err := s.InstalledAmong(ctx, Scope{Devices: []string{"b"}}, api.PackageFlatpak, []string{"org.vim.Vim", "org.gimp.GIMP"})
	if err != nil || !installed["org.vim.Vim"] || installed["org.gimp.GIMP"] {
		t.Fatalf("got %v %v", installed, err)
	}

	// A new list for both drops the old one.
	other := api.NewCatalog([]string{"nano"})
	s.SaveCatalog(ctx, "a", other)
	s.SaveCatalog(ctx, "b", other)
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM catalog_names`).Scan(&count)
	if count != 1 {
		t.Fatalf("old catalog kept: %d names", count)
	}
}

func TestCatalogCheck(t *testing.T) {
	good := api.NewCatalog([]string{"b", "a", "a", "--evil"})
	if err := good.Check(); err != nil || len(good.Names) != 2 {
		t.Fatalf("%v %v", good, err)
	}
	forged := good
	forged.Names = []string{"a", "c"}
	if forged.Check() == nil {
		t.Fatal("names under a foreign hash")
	}
	unsorted := api.PackageCatalog{Names: []string{"b", "a"}}
	unsorted.Hash = api.CatalogHash(unsorted.Names)
	if unsorted.Check() == nil {
		t.Fatal("unsorted names")
	}
}
