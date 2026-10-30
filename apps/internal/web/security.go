// SPDX-License-Identifier: GPL-2.0-only
package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "same-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			if strings.EqualFold(c.GetHeader("Sec-Fetch-Site"), "cross-site") {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			if origin := c.GetHeader("Origin"); origin != "" {
				parsed, err := url.Parse(origin)
				if err != nil || parsed.Host != c.Request.Host || (parsed.Scheme != "http" && parsed.Scheme != "https") {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
			}
		}
		c.Next()
	}
}
