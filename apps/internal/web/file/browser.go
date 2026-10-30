// SPDX-License-Identifier: GPL-2.0-only
package file

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lanthora/hackernel/apps/internal/web/render"
)

type directoryEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Directory  bool   `json:"directory"`
	Symlink    bool   `json:"symlink"`
	Selectable bool   `json:"selectable"`
}

// browse lists metadata only, using the Go service's filesystem and OS permissions.
func (w *Worker) browse(c *gin.Context) {
	request := struct {
		Path   string `json:"path" binding:"required,max=4096"`
		After  string `json:"after" binding:"max=255"`
		Search string `json:"search" binding:"max=255"`
	}{}
	if c.ShouldBindJSON(&request) != nil || !filepath.IsAbs(request.Path) || strings.ContainsRune(request.Path, 0) {
		render.Status(c, render.StatusInvalidArgument)
		return
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(request.Path))
	if err != nil {
		render.Status(c, render.StatusFileBrowseFailed)
		return
	}
	entries, err := os.ReadDir(canonical)
	if err != nil {
		render.Status(c, render.StatusFileBrowseFailed)
		return
	}
	const pageSize = 100
	result := make([]directoryEntry, 0, pageSize)
	hasMore := false
	search := strings.ToLower(request.Search)
	for _, entry := range entries {
		if entry.Name() <= request.After || !strings.Contains(strings.ToLower(entry.Name()), search) {
			continue
		}
		if len(result) == pageSize {
			hasMore = true
			break
		}
		name := filepath.Join(canonical, entry.Name())
		item := directoryEntry{Name: entry.Name(), Path: name, Symlink: entry.Type()&os.ModeSymlink != 0}
		info, err := os.Stat(name)
		if err == nil {
			item.Directory = info.IsDir()
			item.Selectable = info.IsDir() || info.Mode().IsRegular()
		}
		result = append(result, item)
	}
	next := ""
	if hasMore {
		next = result[len(result)-1].Name
	}
	render.Success(c, gin.H{"path": canonical, "parent": filepath.Dir(canonical), "entries": result, "nextCursor": next})
}
