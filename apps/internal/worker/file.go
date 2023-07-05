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
	"github.com/lanthora/hackernel/apps/pkg/file"
	"github.com/lanthora/hackernel/apps/pkg/watchdog"
	"github.com/sirupsen/logrus"
)

const (
	sqlCreateFilePolicyTable       = `create table if not exists file_policy(id integer primary key autoincrement, path text not null, fsid integer, ino integer, perm integer not null, timestamp integer not null, status integer not null)`
	sqlCreateFileEventTable        = `create table if not exists file_event(id integer primary key autoincrement, path text not null, fsid integer, ino integer, perm integer not null, timestamp integer not null, policy integer not null, status integer not null)`
	sqlQueryFilePolicy             = `select id,path,fsid,ino,perm from file_policy`
	sqlUpdateFilePolicyFsidInoById = `update file_policy set fsid=?,ino=?,timestamp=? where id=?`
	sqlUpdateFilePolicyStatusById  = `update file_policy set status=? where id=?`
	sqlQueryFilePolicyIdByFsidIno  = `select id from file_policy where fsid=? and ino=? and status=0`
	sqlInsertFileEvent             = `insert into file_event(path,fsid,ino,perm,timestamp,policy,status) values(?,?,?,?,?,?,?)`
)

type FileWorker struct {
	db *sql.DB

	running bool
	wg      sync.WaitGroup
	conn    *connector.Connector
	config  *config.Config
	dog     *watchdog.Watchdog
}

func NewFileWorker(db *sql.DB) *FileWorker {
	w := FileWorker{
		db:   db,
		conn: connector.New(),
	}
	return &w
}

func (w *FileWorker) Init() (err error) {
	err = w.initDB()
	if err != nil {
		logrus.Error(err)
		return
	}

	w.config, err = config.New(w.db)
	if err != nil {
		return
	}

	if err = w.initFilePolicy(); err != nil {
		logrus.Error(err)
		return
	}

	status, err := w.config.GetInteger(config.FileModuleStatus)
	if err != nil {
		err = nil
		status = file.StatusDisable
	}

	switch status {
	case file.StatusEnable:
		if ok := file.Enable(); !ok {
			err = file.ErrorEnable
			logrus.Error(err)
			return
		}
	default:
		if ok := file.Disable(); !ok {
			err = file.ErrorDisable
			logrus.Error(err)
			return
		}
	}

	return
}
func (w *FileWorker) Start() (err error) {
	w.running = true
	err = w.conn.Connect()
	if err != nil {
		logrus.Error(err)
		return
	}

	err = w.conn.Send(`{"type":"user::msg::sub","section":"kernel::file::report"}`)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = w.conn.Send(`{"type":"user::msg::sub","section":"osinfo::report"}`)
	if err != nil {
		logrus.Error(err)
		return
	}

	w.wg.Add(1)
	go w.run()
	return
}

func (w *FileWorker) Stop() {
	err := w.conn.Send(`{"type":"user::msg::unsub","section":"kernel::proc::report"}`)
	if err != nil {
		logrus.Error(err)
	}
	err = w.conn.Send(`{"type":"user::msg::unsub","section":"osinfo::report"}`)
	if err != nil {
		logrus.Error(err)
	}

	if ok := file.Disable(); !ok {
		logrus.Error(file.ErrorDisable)
	}

	if ok := file.ClearPolicy(); !ok {
		logrus.Error(file.ErrorClearPolicy)
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

func (w *FileWorker) handleMsg(msg string) {
	event := struct {
		Type string `json:"type"`
		Path string `json:"name"`
		Fsid uint64 `json:"fsid"`
		Ino  uint64 `json:"ino"`
		Perm int    `json:"perm"`
	}{}

	err := json.Unmarshal([]byte(msg), &event)
	if err != nil {
		logrus.Error(err)
		return
	}
	switch event.Type {
	case "kernel::file::report":
		err = w.handleFileEvent(event.Path, int64(event.Fsid), int64(event.Ino), event.Perm)
		if err != nil {
			logrus.Error(err)
		}
	default:
	}
}

func (w *FileWorker) run() {
	defer w.wg.Done()
	w.dog = watchdog.New(10*time.Second, func() {
		logrus.Error("osinfo::report timeout")
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	})
	defer w.dog.Stop()
	for w.running {
		msg, err := w.conn.Recv()

		if !w.running {
			logrus.Info("file worker exit")
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

func (w *FileWorker) initDB() (err error) {
	_, err = w.db.Exec(sqlCreateFilePolicyTable)
	if err != nil {
		logrus.Error(err)
		return
	}

	_, err = w.db.Exec(sqlCreateFileEventTable)
	if err != nil {
		logrus.Error(err)
		return
	}

	return
}

func (w *FileWorker) setPolicyThenGetExceptionPolicies() (policies []file.Policy, err error) {
	stmt, err := w.db.Prepare(sqlQueryFilePolicy)
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
		policy := file.Policy{}
		fsid := int64(0)
		ino := int64(0)
		status := int(0)

		err = rows.Scan(&policy.ID, &policy.Path, &policy.Fsid, &policy.Ino, &policy.Perm)
		if err != nil {
			logrus.Error(err)
			return
		}

		fsid, ino, status, err = file.SetPolicy(policy.Path, policy.Perm, file.FlagNew)
		if err != nil {
			logrus.Error(err)
			return
		}
		if policy.Fsid != fsid || policy.Ino != ino || policy.Status != status {
			policy.Fsid = fsid
			policy.Ino = ino
			policy.Status = status
			policies = append(policies, policy)
		}
	}
	err = rows.Err()
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *FileWorker) initFilePolicy() (err error) {
	if ok := file.ClearPolicy(); !ok {
		logrus.Error(file.ErrorClearPolicy)
		return
	}

	policies, err := w.setPolicyThenGetExceptionPolicies()
	if err != nil {
		logrus.Error(err)
		return
	}
	for _, policy := range policies {
		err = w.updateFilePolcyFsidInoById(policy.Fsid, policy.Ino, policy.ID)
		if err != nil {
			logrus.Error(err)
			return
		}
		err = w.updateFilePolcyStatusById(policy.Status, policy.ID)
		if err != nil {
			logrus.Error(err)
			return
		}
	}
	return
}

func (w *FileWorker) updateFilePolcyFsidInoById(fsid, ino, id int64) (err error) {
	stmt, err := w.db.Prepare(sqlUpdateFilePolicyFsidInoById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(int64(fsid), int64(ino), time.Now().Unix(), id)
	if err != nil {
		logrus.Error(err)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		logrus.Error(err)
		return
	}
	if affected != 1 {
		logrus.Errorf("id=%d, fsid=%d, ino=%d, affected=%d", id, fsid, ino, affected)
	}
	return
}

func (w *FileWorker) updateFilePolcyStatusById(status int, id int64) (err error) {
	stmt, err := w.db.Prepare(sqlUpdateFilePolicyStatusById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(status, id)
	if err != nil {
		logrus.Error(err)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		logrus.Error(err)
		return
	}
	if affected != 1 {
		logrus.Errorf("id=%d, status=%d, affected=%d", id, status, affected)
	}
	return
}

func (w *FileWorker) handleFileEvent(path string, fsid, ino int64, perm int) (err error) {
	stmt, err := w.db.Prepare(sqlQueryFilePolicyIdByFsidIno)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	policyId := int64(0)
	err = stmt.QueryRow(fsid, ino).Scan(&policyId)
	if err != nil {
		logrus.Error(err)
		return
	}

	stmt, err = w.db.Prepare(sqlInsertFileEvent)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(path, fsid, ino, perm, time.Now().Unix(), policyId, file.StatusEventUnread)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}
