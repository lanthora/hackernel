// SPDX-License-Identifier: GPL-2.0-only
package worker

import (
	"database/sql"
	"encoding/json"
	"sync"
	"syscall"
	"time"

	"github.com/lanthora/hackernel/apps/internal/config"
	"github.com/lanthora/hackernel/apps/pkg/connector"
	"github.com/lanthora/hackernel/apps/pkg/process"
	"github.com/lanthora/hackernel/apps/pkg/watchdog"
	"github.com/sirupsen/logrus"
)

const (
	sqlCreateProcessTable    = `create table if not exists process_event(id integer primary key autoincrement, workdir text not null, binary text not null, argv text not null, count integer not null, judge integer not null, status integer not null)`
	sqlUpdateProcessCount    = `update process_event set count=count+1,judge=?,status=? where workdir=? and binary=? and argv=?`
	sqlInsertProcessEvent    = `insert into process_event(workdir,binary,argv,count,judge,status) values(?,?,?,1,?,?)`
	sqlQueryAllowedProcesses = `select workdir,binary,argv from process_event where status=2`
)

type ProcessWorker struct {
	db *sql.DB

	running bool
	wg      sync.WaitGroup
	conn    *connector.Connector
	config  *config.Config
	dog     *watchdog.Watchdog
}

func NewProcessWorker(db *sql.DB) *ProcessWorker {
	w := ProcessWorker{
		db:   db,
		conn: connector.New(),
	}
	return &w
}

func (w *ProcessWorker) Init() (err error) {
	err = w.initDB()
	if err != nil {
		return
	}

	w.config, err = config.New(w.db)
	if err != nil {
		logrus.Error(err)
		return
	}

	err = w.initTrustedCmd()
	if err != nil {
		return
	}

	status, err := w.config.GetInteger(config.ProcessModuleStatus)
	if err != nil {
		err = nil
		status = process.StatusDisable
	}

	switch status {
	case process.StatusEnable:
		if ok := process.Enable(); !ok {
			err = process.ErrorEnable
			return
		}
	default:
		if ok := process.Disable(); !ok {
			err = process.ErrorEnable
			return
		}
	}

	judge, err := w.config.GetInteger(config.ProcessProtectionMode)
	if err != nil {
		err = nil
		judge = process.StatusJudgeDisable
	}

	if ok := process.UpdateJudge(judge); !ok {
		err = process.ErrorUpdateJudge
		return
	}

	return
}

func (w *ProcessWorker) Start() (err error) {
	w.running = true
	err = w.conn.Connect()
	if err != nil {
		return
	}

	err = w.conn.Send(`{"type":"user::msg::sub","section":"audit::proc::report"}`)
	if err != nil {
		return
	}
	err = w.conn.Send(`{"type":"user::msg::sub","section":"osinfo::report"}`)
	if err != nil {
		return
	}

	w.wg.Add(1)
	go w.run()
	return
}

func (w *ProcessWorker) Stop() {
	err := w.conn.Send(`{"type":"user::msg::unsub","section":"audit::proc::report"}`)
	if err != nil {
		logrus.Error(err)
	}
	err = w.conn.Send(`{"type":"user::msg::unsub","section":"osinfo::report"}`)
	if err != nil {
		logrus.Error(err)
	}

	if ok := process.Disable(); !ok {
		logrus.Error(process.ErrorDisable)
	}

	if ok := process.ClearPolicy(); !ok {
		logrus.Error(process.ErrorClearPolicy)
	}

	time.Sleep(time.Second)
	w.running = false
	err = w.conn.Shutdown(time.Now())
	if err != nil {
		logrus.Error(err)
	}
	w.wg.Wait()
	w.conn.Close()
}

func (w *ProcessWorker) initDB() (err error) {
	_, err = w.db.Exec(sqlCreateProcessTable)
	if err != nil {
		logrus.Error(err)
		return
	}

	return
}

func (w *ProcessWorker) initTrustedCmd() (err error) {
	if ok := process.ClearPolicy(); !ok {
		logrus.Error(process.ErrorClearPolicy)
		return
	}

	stmt, err := w.db.Prepare(sqlQueryAllowedProcesses)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		logrus.Error(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		workdir := ""
		binary := ""
		argv := ""
		err = rows.Scan(&workdir, &binary, &argv)
		if err != nil {
			return
		}
		process.SetTrustedCmd(workdir, binary, argv)
	}
	err = rows.Err()
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *ProcessWorker) updateCmd(workdir, binary, argv string, judge int) (err error) {
	status, err := w.config.GetInteger(config.ProcessCmdDefaultStatus)
	if err != nil {
		status = process.StatusPending
	}

	if judge == process.StatusJudgeDefense {
		status = process.StatusUntrusted
	}

	if status == process.StatusTrusted {
		process.SetTrustedCmd(workdir, binary, argv)
	}

	stmt, err := w.db.Prepare(sqlUpdateProcessCount)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(judge, status, workdir, binary, argv)
	if err != nil {
		logrus.Error(err)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		logrus.Error(err)
		return
	}

	if affected != 0 {
		return
	}

	stmt, err = w.db.Prepare(sqlInsertProcessEvent)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(workdir, binary, argv, judge, status)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *ProcessWorker) handleMsg(msg string) {
	event := struct {
		Type    string `json:"type"`
		Workdir string `json:"workdir"`
		Binary  string `json:"binary"`
		Argv    string `json:"argv"`
		Judge   int    `json:"judge"`
	}{}

	err := json.Unmarshal([]byte(msg), &event)
	if err != nil {
		logrus.Error(err)
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
		return
	}
	switch event.Type {
	case "audit::proc::report":
		err = w.updateCmd(event.Workdir, event.Binary, event.Argv, event.Judge)
		if err != nil {
			logrus.Error(err)
		}
	default:
	}
}

func (w *ProcessWorker) run() {
	defer w.wg.Done()
	w.dog = watchdog.New(10*time.Second, func() {
		logrus.Error("osinfo::report timeout")
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	})
	defer w.dog.Stop()
	for w.running {
		msg, err := w.conn.Recv()

		if !w.running {
			logrus.Info("process worker exit")
			break
		}

		if err != nil {
			logrus.Error(err)
			continue
		}
		w.dog.Kick()
		go w.handleMsg(msg)
	}
}
