// SPDX-License-Identifier: GPL-2.0-only
package process

import (
	"github.com/sirupsen/logrus"
)

const (
	sqlQueryProcessLimitOffset      = `select id,workdir,binary,argv,count,judge,status from process_event where id>? limit ?`
	sqlUpdateProcessStatus          = `update process_event set status=? where id=?`
	sqlQueryProcessCmdById          = `select workdir,binary,argv from process_event where id=?`
	sqlQueryProcessPolicyCount      = `select count(*) from process_event`
	sqlQueryProcessUnreadEventCount = `select count(*) from process_event where status=0`
)

func (w *Worker) queryLimitOffset(limit, offset int) (events []Event, err error) {
	stmt, err := w.db.Prepare(sqlQueryProcessLimitOffset)
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
		e := Event{}
		err = rows.Scan(&e.ID, &e.Workdir, &e.Binary, &e.Argv, &e.Count, &e.Judge, &e.Status)
		if err != nil {
			logrus.Error(err)
			return
		}
		events = append(events, e)
	}
	err = rows.Err()
	if err != nil {
		logrus.Error(err)
	}
	return
}

func (w *Worker) updateStatus(id int64, status int) bool {
	stmt, err := w.db.Prepare(sqlUpdateProcessStatus)
	if err != nil {
		logrus.Error(err)
		return false
	}
	defer stmt.Close()

	result, err := stmt.Exec(status, id)
	if err != nil {
		logrus.Error(err)
		return false
	}
	affected, err := result.RowsAffected()
	if err != nil {
		logrus.Error(err)
		return false
	}
	return affected == 1
}

func (w *Worker) queryCmdById(id int) (workdir, binary, argv string, err error) {
	stmt, err := w.db.Prepare(sqlQueryProcessCmdById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(id).Scan(&workdir, &binary, &argv)
	return
}

func (w *Worker) queryProcessPolicyCount() (count int, err error) {
	stmt, err := w.db.Prepare(sqlQueryProcessPolicyCount)
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

func (w *Worker) queryProcessUnreadEventCount() (count int, err error) {
	stmt, err := w.db.Prepare(sqlQueryProcessUnreadEventCount)
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
