// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/lanthora/hackernel/apps/internal/sample"
	"github.com/lanthora/hackernel/apps/pkg/logger"
	"github.com/sirupsen/logrus"
)

func main() {
	logger.InitLogrusFormat()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	sampleWorker := sample.NewWorker()
	sampleWorker.Start()

	sig := <-sigchan
	logrus.Info(sig)

	sampleWorker.Stop()
}
