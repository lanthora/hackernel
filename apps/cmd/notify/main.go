package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/lanthora/hackernel/apps/internal/notify"
	"github.com/lanthora/hackernel/apps/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	logger.InitLogrusFormat()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	config := viper.New()
	config.SetConfigName("notify")
	config.SetConfigType("yaml")
	config.AddConfigPath("$HOME/.config/hackernel")

	if err := config.ReadInConfig(); err != nil {
		logrus.Fatal(err)
	}

	cacheFilePath := fmt.Sprintf("%s/.cache/hackernel/notify.yaml", os.Getenv("HOME"))
	cache := viper.New()
	cache.SetConfigName("notify")
	cache.SetConfigType("yaml")
	cache.AddConfigPath(filepath.Dir(cacheFilePath))
	cache.SetDefault("process-event-offset", int64(0))
	os.MkdirAll(filepath.Dir(cacheFilePath), os.ModePerm)

	if err := cache.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logrus.Info("The cache file was not found, it will be created when the process exits")
		} else {
			logrus.Fatal(err)
		}
	}

	server := config.GetString("server")
	username := config.GetString("username")
	password := config.GetString("password")
	processEventOffset := cache.GetInt64("process-event-offset")
	fileEventOffset := cache.GetInt64("file-event-offset")
	netEventOffset := cache.GetInt64("net-event-offset")

	notifier := notify.NewWorker(server, username, password, processEventOffset, fileEventOffset, netEventOffset)
	notifier.Start()

	sig := <-sigchan
	logrus.Info(sig)

	notifier.Stop()

	cache.Set("process-event-offset", notifier.ProcessEventOffset)
	cache.Set("file-event-offset", notifier.FileEventOffset)
	cache.Set("net-event-offset", notifier.NetEventOffset)
	if err := cache.WriteConfigAs(cacheFilePath); err != nil {
		logrus.Error(err)
	}
}
