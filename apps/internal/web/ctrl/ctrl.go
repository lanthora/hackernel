// SPDX-License-Identifier: GPL-2.0-only
package ctrl

import (
	"database/sql"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/lanthora/hackernel/apps/internal/web/render"
	"github.com/lanthora/hackernel/apps/internal/web/user"
	"github.com/lanthora/hackernel/apps/pkg/ctrl"
	"github.com/lanthora/hackernel/apps/pkg/exector"
	"github.com/sirupsen/logrus"
)

type Worker struct {
	db *sql.DB
}

var debugEnabled atomic.Bool

func Init(router *gin.Engine, db *sql.DB) (err error) {
	w := &Worker{
		db: db,
	}
	debugEnabled.Store(false)

	ctrlGroup := router.Group("/ctrl")
	ctrlGroup.Use(user.AuthMiddleware())

	ctrlGroup.POST("/shutdown", w.shutdown)
	ctrlGroup.POST("/status", w.status)
	ctrlGroup.POST("/enableDebug", w.enableDebug)
	ctrlGroup.POST("/disableDebug", w.disableDebug)
	return
}

func (w *Worker) shutdown(context *gin.Context) {
	if !ctrl.Shutdown() {
		render.Status(context, render.StatusUnknownError)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) enableDebug(context *gin.Context) {
	debugEnabled.Store(true)
	logrus.Info("pprof debug enabled")
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) disableDebug(context *gin.Context) {
	debugEnabled.Store(false)
	logrus.Info("pprof debug disabled")
	render.Status(context, render.StatusSuccess)
}

func PProfMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		if strings.HasPrefix(context.Request.URL.Path, pprof.DefaultPrefix) {
			if !debugEnabled.Load() {
				context.AbortWithStatus(404)
				return
			}
		}
		context.Next()
	}
}

func (w *Worker) status(c *gin.Context) {
	reply, err := exector.Exec(`{"type":"user::test::echo","extra":"web-health"}`, time.Second)
	var response struct {
		Type string `json:"type"`
	}
	online := err == nil && json.Unmarshal([]byte(reply), &response) == nil && response.Type == "user::test::echo"
	render.Success(c, gin.H{"coreOnline": online, "debugEnabled": debugEnabled.Load()})
}
