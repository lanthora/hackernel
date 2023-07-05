// SPDX-License-Identifier: GPL-2.0-only
package web

import (
	"embed"
	"net/http"
	"path"

	"github.com/gin-gonic/gin"
)

//go:embed webui/*
var staticFS embed.FS

var contentType = map[string]string{
	".html": "text/html; charset=UTF-8",
	".css":  "text/css; charset=UTF-8",
	".js":   "text/javascript; charset=UTF-8",
	".ico":  "image/x-icon",
}

func webui(context *gin.Context) {
	url := context.Request.URL.String()

	filePath := "webui" + url
	if data, err := staticFS.ReadFile(filePath); err == nil {
		context.Header("Cache-Control", "public, max-age=604800")
		context.Data(http.StatusOK, contentType[path.Ext(filePath)], data)
		return
	}

	indexPath := "webui/index.html"
	if data, err := staticFS.ReadFile(indexPath); err == nil {
		context.Data(http.StatusOK, contentType[path.Ext(indexPath)], data)
		return
	}

	context.Status(http.StatusNotFound)
}
