// Package web embeds the dashboard into the server binary.
package web

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS
