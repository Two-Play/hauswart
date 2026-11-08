package api

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
)

const (
	// MaxCatalogNames is far above the packages of any distribution's
	// repositories, which are about 80 000 on Fedora and Debian.
	MaxCatalogNames = 150000
	// MaxCatalogBytes limits a catalog after decompression.
	MaxCatalogBytes = 8 << 20
)

// Search kinds.
const (
	SearchPackage = "package"
	SearchFlatpak = "flatpak"
)

// PackageCatalog is the names of all packages that a device could install. It
// is for searching only: nothing is installed because a name is here.
type PackageCatalog struct {
	Hash  string   `json:"hash"`
	Names []string `json:"names"`
}

// CatalogHash identifies a list of names. The server computes it again, so a
// device cannot put its names under the hash of another device's list.
func CatalogHash(names []string) string {
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewCatalog sorts names, drops what is not a package name, and caps the list.
func NewCatalog(names []string) PackageCatalog {
	names = slices.DeleteFunc(slices.Clone(names), func(name string) bool { return !ValidPackage(name) })
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > MaxCatalogNames {
		names = names[:MaxCatalogNames]
	}
	return PackageCatalog{Hash: CatalogHash(names), Names: names}
}

// Check refuses a catalog that is too large, unsorted, or not what its hash
// says.
func (c PackageCatalog) Check() error {
	if len(c.Names) > MaxCatalogNames {
		return Fail(ErrInvalidCatalog, strconv.Itoa(MaxCatalogNames))
	}
	for i, name := range c.Names {
		if !ValidPackage(name) || i > 0 && c.Names[i-1] >= name {
			return Fail(ErrInvalidCatalog, name)
		}
	}
	if CatalogHash(c.Names) != c.Hash {
		return Fail(ErrInvalidCatalog, "hash")
	}
	return nil
}
