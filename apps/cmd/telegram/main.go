// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"database/sql"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/lanthora/hackernel/apps/internal/common"
	"github.com/lanthora/hackernel/apps/internal/telegram"
	"github.com/lanthora/hackernel/apps/internal/worker"
	"github.com/lanthora/hackernel/apps/pkg/logger"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	ErrorInvalidToken = errors.New("the token is empty, please get the token from BotFather")
	ErrorInvalidOwner = errors.New("chat id is 0, please use correct id")
)

func main() {
	logger.InitLogrusFormat()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	config := viper.New()
	config.SetConfigName("telegram")
	config.SetConfigType("yaml")
	config.AddConfigPath("/etc/hackernel")
	if err := config.ReadInConfig(); err != nil {
		logrus.Fatal(err)
	}

	token := config.GetString("token")
	if len(token) == 0 {
		logrus.Fatal(ErrorInvalidToken)
	}
	ownerID := config.GetInt64("id")
	if ownerID == 0 {
		logrus.Fatal(ErrorInvalidOwner)
	}

	dataSourceName := common.GetDataSourceNameFromConfig(config)
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		logrus.Fatal(err)
	}
	defer db.Close()

	telegramWorker := telegram.NewWorker(token, ownerID)
	processWorker := worker.NewProcessWorker(db)

	if err := telegram.SetStandaloneMode(db); err != nil {
		logrus.Fatal(err)
	}

	if err := processWorker.Init(); err != nil {
		logrus.Fatal(err)
	}

	if err := telegramWorker.Start(); err != nil {
		logrus.Fatal(err)
	}
	if err := processWorker.Start(); err != nil {
		logrus.Fatal(err)
	}

	sig := <-sigchan
	logrus.Info(sig)

	telegramWorker.Stop()
	processWorker.Stop()
}
