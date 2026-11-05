// Package web embeds the built dashboard into the server binary. Run
// "make build" so that dist contains more than its placeholder.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// FS is the dashboard build output.
var FS = mustSub()

func mustSub() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
