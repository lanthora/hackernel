// SPDX-License-Identifier: GPL-2.0-only
package web

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

//go:embed webui/*
var staticFS embed.FS

func webui(c *gin.Context) {
	files, _ := fs.Sub(staticFS, "webui")
	serveFrontend(c, files)
}

func serveFrontend(c *gin.Context, files fs.FS) {
	// Unknown APIs and missing assets must not return the SPA document.
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.Status(http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(path.Clean(c.Request.URL.Path), "/")
	if name == "." || name == "" {
		name = "index.html"
	}
	if info, err := fs.Stat(files, name); err == nil && !info.IsDir() {
		if strings.HasPrefix(name, "assets/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			c.Header("Cache-Control", "no-cache")
		}
		serveFile(c, files, name)
		return
	}
	first := strings.Split(name, "/")[0]
	if strings.Contains(path.Base(name), ".") || first == "assets" || first == "auth" || first == "admin" || first == "ctrl" || first == "process" || first == "file" || first == "net" {
		c.Status(http.StatusNotFound)
		return
	}
	if _, err := fs.Stat(files, "index.html"); err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "no-cache")
	serveFile(c, files, "index.html")
}

func serveFile(c *gin.Context, files fs.FS, name string) {
	data, err := fs.ReadFile(files, name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	http.ServeContent(c.Writer, c.Request, name, time.Time{}, bytes.NewReader(data))
}
