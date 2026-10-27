// Package web embeds the built single-page app (web/dist) into xcp-api.
// Build it with `npm ci && npm run build` in this directory before
// `go build`; without it, xcp-api serves a short "UI not built" message.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built UI files.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // "dist" is embedded at compile time; this cannot fail
	}
	return sub
}
