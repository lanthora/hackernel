// SPDX-License-Identifier: GPL-2.0-only
package ctrl

import (
	"database/sql"
	"strings"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/lanthora/hackernel/apps/internal/web/render"
	"github.com/lanthora/hackernel/apps/internal/web/user"
	"github.com/lanthora/hackernel/apps/pkg/ctrl"
	"github.com/sirupsen/logrus"
)

type Worker struct {
	db *sql.DB
}

var debugEnabled bool

func Init(router *gin.Engine, db *sql.DB) (err error) {
	w := &Worker{
		db: db,
	}
	debugEnabled = false

	ctrlGroup := router.Group("/ctrl")
	ctrlGroup.Use(user.AuthMiddleware())

	ctrlGroup.POST("/shutdown", w.shutdown)
	ctrlGroup.GET("/enableDebug", w.enableDebug)
	ctrlGroup.GET("/disableDebug", w.disableDebug)
	return
}

func (w *Worker) shutdown(context *gin.Context) {
	ctrl.Shutdown()
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) enableDebug(context *gin.Context) {
	debugEnabled = true
	logrus.Info("pprof debug enabled")
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) disableDebug(context *gin.Context) {
	debugEnabled = false
	logrus.Info("pprof debug disabled")
	render.Status(context, render.StatusSuccess)
}

func PProfMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		if strings.HasPrefix(context.Request.URL.Path, pprof.DefaultPrefix) {
			if !debugEnabled {
				context.Abort()
				return
			}
		}
		context.Next()
	}
}
