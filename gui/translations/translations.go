// Package translations holds the texts of the desktop apps.
package translations

import (
	"embed"

	"fyne.io/fyne/v2/lang"
)

//go:embed lang/*.json
var files embed.FS

// Load makes the texts known to Fyne, which picks the language of the system.
func Load() error { return lang.AddTranslationsFS(files, "lang") }
