// SPDX-License-Identifier: GPL-2.0-only
package file

import (
	"time"

	"github.com/lanthora/hackernel/apps/pkg/file"
	"github.com/sirupsen/logrus"
)

const (
	sqlInsertFilePolicy           = `insert into file_policy(path,fsid,ino,perm,timestamp,status) values(?,?,?,?,?,?)`
	sqlUpdateFilePolicyById       = `update file_policy set fsid=?,ino=?,perm=?,timestamp=?,status=? where id=?`
	sqlQueryFileEventLimitOffset  = `select id,path,fsid,ino,perm,timestamp,policy,status from file_event where id>? limit ?`
	sqlQueryFilePolicyById        = `select id,path,fsid,ino,perm,timestamp,status from file_policy where id=?`
	sqlQueryFilePolicyLimitOffset = `select id,path,fsid,ino,perm,timestamp,status from file_policy where id>? limit ?`
	sqlDeleteFilePolicyById       = `delete from file_policy where id=?`
	sqlDeleteFileEventById        = `delete from file_event where id=?`
	sqlUpdateFileEventStatusById  = `update file_event set status=? where id=?`
	sqlQueryFileNormalPolicyCount = `select count(*) from file_policy where status=0`
	sqlQueryFileUnreadEventCount  = `select count(*) from file_event where status=0`
)

func (w *Worker) insertFilePolicy(path string, fsid, ino int64, perm, status int) (err error) {
	stmt, err := w.db.Prepare(sqlInsertFilePolicy)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(path, int64(fsid), int64(ino), perm, time.Now().Unix(), status)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) updateFilePolicyById(fsid, ino int64, perm, status, id int) (err error) {
	stmt, err := w.db.Prepare(sqlUpdateFilePolicyById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(fsid, ino, perm, time.Now().Unix(), status, id)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) queryFileEventOffsetLimit(limit, offset int) (events []file.Event, err error) {
	stmt, err := w.db.Prepare(sqlQueryFileEventLimitOffset)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query(offset, limit)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		e := file.Event{}
		err = rows.Scan(&e.ID, &e.Path, &e.Fsid, &e.Ino, &e.Perm, &e.Timestamp, &e.Policy, &e.Status)
		if err != nil {
			logrus.Error(err)
			return
		}
		events = append(events, e)
	}
	err = rows.Err()
	return
}

func (w *Worker) queryFilePolicyById(id int) (event file.Policy, err error) {
	stmt, err := w.db.Prepare(sqlQueryFilePolicyById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(id).Scan(&event.ID, &event.Path, &event.Fsid, &event.Ino, &event.Perm, &event.Timestamp, &event.Status)
	if err != nil {
		logrus.Error(err)
	}
	return
}

func (w *Worker) queryFilePolicyLimitOffset(limit, offset int) (policies []file.Policy, err error) {
	stmt, err := w.db.Prepare(sqlQueryFilePolicyLimitOffset)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()
	rows, err := stmt.Query(offset, limit)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		policy := file.Policy{}
		err = rows.Scan(&policy.ID, &policy.Path, &policy.Fsid, &policy.Ino, &policy.Perm, &policy.Timestamp, &policy.Status)
		if err != nil {
			logrus.Error(err)
			return
		}
		policies = append(policies, policy)
	}
	err = rows.Err()
	if err != nil {
		logrus.Error(err)
	}
	return
}

func (w *Worker) deleteFilePolicyById(id int) (err error) {
	stmt, err := w.db.Prepare(sqlDeleteFilePolicyById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) deleteFileEventById(id int) (err error) {
	stmt, err := w.db.Prepare(sqlDeleteFileEventById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	// TODO: 数据不存在时错误提示
	_, err = stmt.Exec(id)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) updateFileEventStatusById(status, id int) (err error) {
	stmt, err := w.db.Prepare(sqlUpdateFileEventStatusById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	// TODO: 数据不存在时错误提示
	_, err = stmt.Exec(status, id)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) queryFileNormalPolicyCount() (count int, err error) {
	stmt, err := w.db.Prepare(sqlQueryFileNormalPolicyCount)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&count)
	if err != nil {
		logrus.Error(err)
	}
	return
}

func (w *Worker) queryFileUnreadEventCount() (count int, err error) {
	stmt, err := w.db.Prepare(sqlQueryFileUnreadEventCount)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&count)
	if err != nil {
		logrus.Error(err)
	}
	return
}
