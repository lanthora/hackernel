// SPDX-License-Identifier: GPL-2.0-only
package telegram

import (
	"database/sql"
	"encoding/json"
	"sync"
	"syscall"
	"time"

	"github.com/lanthora/hackernel/apps/internal/config"
	"github.com/lanthora/hackernel/apps/pkg/connector"
	"github.com/lanthora/hackernel/apps/pkg/process"
	"github.com/sirupsen/logrus"
)

type TelegramWorker struct {
	running bool
	wg      sync.WaitGroup
	conn    *connector.Connector
	bot     *Bot
}

func NewWorker(token string, ownerID int64) *TelegramWorker {
	w := TelegramWorker{
		bot:  NewBot(token, ownerID),
		conn: connector.New(),
	}
	return &w
}

func SetStandaloneMode(db *sql.DB) (err error) {
	cfg, err := config.New(db)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = cfg.SetInteger(config.ProcessModuleStatus, process.StatusEnable)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = cfg.SetInteger(config.ProcessProtectionMode, process.StatusJudgeAudit)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = cfg.SetInteger(config.ProcessCmdDefaultStatus, process.StatusTrusted)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *TelegramWorker) Start() (err error) {
	w.running = true
	err = w.conn.Connect()
	if err != nil {
		return
	}
	err = w.bot.Connect()
	if err != nil {
		return
	}
	err = w.conn.Send(`{"type":"user::msg::sub","section":"audit::proc::report"}`)
	if err != nil {
		return
	}
	w.wg.Add(1)
	go w.runReportToOwner()
	return
}

func (w *TelegramWorker) Stop() {
	err := w.conn.Send(`{"type":"user::msg::unsub","section":"audit::proc::report"}`)
	if err != nil {
		logrus.Fatal(err)
	}
	time.Sleep(time.Second)
	w.running = false
	err = w.conn.Shutdown(time.Now())
	if err != nil {
		logrus.Fatal(err)
	}
	w.wg.Wait()
	w.conn.Close()
}

func (w *TelegramWorker) runReportToOwner() {
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

		doc := map[string]interface{}{}
		err = json.Unmarshal([]byte(msg), &doc)
		if err != nil {
			logrus.Error(err)
			continue
		}
		html := ""
		switch doc["type"].(string) {
		case "audit::proc::report":
			html = RenderAuditProcReport(msg)
		case "user::msg::sub":
			html = RenderUserMsgSub(msg)
		case "user::msg::unsub":
			html = RenderUserMsgUnsub(msg)
		case "kernel::proc::enable":
			html = RenderKernelProcEnable(msg)
		case "kernel::proc::disable":
			html = RenderKernelProcDisable(msg)
		}
		if html != "" {
			w.bot.SendHtmlToOwner(html)
		} else {
			w.bot.SendTextToOwner(msg)
		}
	}

}
