// Package web embeds the built React SPA into the Go binary so the final
// image ships as a single static executable with no separate frontend
// artifact to deploy or serve out-of-band.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// DistFS returns the embedded frontend build rooted at its own top level
// (i.e. dist/index.html appears as index.html), ready to hand to
// http.FileServer / httpapi.New.
func DistFS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
