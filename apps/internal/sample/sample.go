// SPDX-License-Identifier: GPL-2.0-only
package sample

import (
	"sync"
	"syscall"
	"time"

	"github.com/lanthora/hackernel/apps/pkg/connector"
	"github.com/sirupsen/logrus"
)

type SampleWorker struct {
	running bool
	wg      sync.WaitGroup
	conn    *connector.Connector
}

func NewWorker() *SampleWorker {
	w := SampleWorker{
		conn: connector.New(),
	}
	return &w
}

func (w *SampleWorker) Start() {
	logrus.Debug("Start")
	w.running = true
	err := w.conn.Connect()
	if err != nil {
		logrus.Fatal(err)
	}
	err = w.conn.Send(`{"type":"user::proc::enable"}`)
	if err != nil {
		logrus.Fatal(err)
	}
	err = w.conn.Send(`{"type":"user::msg::sub","section":"kernel::proc::report"}`)
	if err != nil {
		logrus.Fatal(err)
	}
	err = w.conn.Send(`{"type":"user::msg::sub","section":"osinfo::report"}`)
	if err != nil {
		logrus.Fatal(err)
	}
	w.wg.Add(1)
	go w.run()
}

func (w *SampleWorker) run() {
	defer w.wg.Done()
	for w.running {
		msg, err := w.conn.Recv()

		if !w.running {
			break
		}

		if err != nil {
			logrus.Error(err)
			syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			continue
		}

		logrus.Debugf("msg=[%s]", msg)
	}
}

func (w *SampleWorker) Stop() {
	w.conn.Send(`{"type":"user::proc::disable"}`)
	w.conn.Send(`{"type":"user::msg::unsub","section":"kernel::proc::report"}`)
	w.conn.Send(`{"type":"user::msg::unsub","section":"osinfo::report"}`)
	time.Sleep(time.Second)
	w.running = false
	err := w.conn.Shutdown(time.Now())
	if err != nil {
		logrus.Fatal(err)
	}
	w.wg.Wait()
	w.conn.Close()
	logrus.Debug("Stop")
}
