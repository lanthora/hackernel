// SPDX-License-Identifier: GPL-2.0-only
package web

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/lanthora/hackernel/apps/internal/web/ctrl"
	"github.com/lanthora/hackernel/apps/internal/web/file"
	"github.com/lanthora/hackernel/apps/internal/web/net"
	"github.com/lanthora/hackernel/apps/internal/web/process"
	"github.com/lanthora/hackernel/apps/internal/web/user"
	"github.com/sirupsen/logrus"
)

type WebWorker struct {
	addr   string
	server *http.Server
	wg     sync.WaitGroup
	db     *sql.DB
}

func NewWorker(addr string, db *sql.DB) *WebWorker {
	w := WebWorker{
		addr: addr,
		db:   db,
	}
	return &w
}

func (w *WebWorker) serve() {
	defer w.wg.Done()
	if err := w.server.ListenAndServe(); err != http.ErrServerClosed {
		logrus.Error(err)
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}
}

func (w *WebWorker) Init() (err error) {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	if err = user.Init(router, w.db); err != nil {
		return
	}

	if err = process.Init(router, w.db); err != nil {
		return
	}

	if err = file.Init(router, w.db); err != nil {
		return
	}

	if err = net.Init(router, w.db); err != nil {
		return
	}

	if err = ctrl.Init(router, w.db); err != nil {
		return
	}

	router.Use(ctrl.PProfMiddleware())
	pprof.Register(router)

	router.NoRoute(webui)

	w.server = &http.Server{
		Addr:    w.addr,
		Handler: router,
	}
	return
}

func (w *WebWorker) Start() (err error) {
	w.wg.Add(1)
	go w.serve()
	return
}

func (w *WebWorker) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.server.Shutdown(ctx)
	w.wg.Wait()
}
