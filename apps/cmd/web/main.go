// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"database/sql"
	"os"
	"os/signal"
	"syscall"

	"github.com/lanthora/hackernel/apps/internal/common"
	"github.com/lanthora/hackernel/apps/internal/web"
	"github.com/lanthora/hackernel/apps/internal/worker"
	"github.com/lanthora/hackernel/apps/pkg/logger"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	logger.InitLogrusFormat()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	config := viper.New()
	config.SetConfigName("web")
	config.SetConfigType("yaml")
	config.AddConfigPath("/etc/hackernel")
	if err := config.ReadInConfig(); err != nil {
		logrus.Fatal(err)
	}

	listen := config.GetString("listen")
	dataSourceName := common.GetDataSourceNameFromConfig(config)
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		logrus.Fatal(err)
	}
	defer db.Close()

	processWorker := worker.NewProcessWorker(db)
	fileWorker := worker.NewFileWorker(db)
	netWorker := worker.NewNetWorker(db)
	webWorker := web.NewWorker(listen, db)

	if err := processWorker.Init(); err != nil {
		logrus.Fatal(err)
	}

	if err := fileWorker.Init(); err != nil {
		logrus.Fatal(err)
	}

	if err := netWorker.Init(); err != nil {
		logrus.Fatal(err)
	}

	if err := webWorker.Init(); err != nil {
		logrus.Fatal(err)
	}

	if err := processWorker.Start(); err != nil {
		logrus.Fatal(err)
	}

	if err := fileWorker.Start(); err != nil {
		logrus.Fatal(err)
	}

	if err := netWorker.Start(); err != nil {
		logrus.Fatal(err)
	}

	if err := webWorker.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Info("listen: ", listen)

	sig := <-sigchan
	logrus.Info(sig)

	webWorker.Stop()
	processWorker.Stop()
	fileWorker.Stop()
	netWorker.Stop()
}
