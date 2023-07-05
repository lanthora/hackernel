// SPDX-License-Identifier: GPL-2.0-only
package net

import (
	"github.com/lanthora/hackernel/apps/pkg/net"
	"github.com/sirupsen/logrus"
)

const (
	sqlInsertNetPolicy           = `insert into net_policy(priority,addr_src_begin,addr_src_end,addr_dst_begin,addr_dst_end,protocol_begin,protocol_end,port_src_begin,port_src_end,port_dst_begin,port_dst_end,flags,response) values(?,?,?,?,?,?,?,?,?,?,?,?,?)`
	sqlDeleteNetPolicyById       = `delete from net_policy where id=?`
	sqlQueryNetPolicyLimitOffset = `select id,priority,addr_src_begin,addr_src_end,addr_dst_begin,addr_dst_end,protocol_begin,protocol_end,port_src_begin,port_src_end,port_dst_begin,port_dst_end,flags,response from net_policy where id>? limit ?`
	sqlQueryNetEventLimitOffset  = `select id,protocol,saddr,daddr,sport,dport,timestamp,policy,status from net_event where id>? limit ?`
	sqlDeleteNetEventById        = `delete from net_event where id=?`
	sqlUpdateNetEventStatusById  = `update net_event set status=? where id=?`
	sqlQueryNetPolicyCount       = `select count(*) from net_policy`
	sqlQueryNetUnreadEventCount  = `select count(*) from net_event where status=0`
)

func (w *Worker) insertNetPolicy(policy *net.Policy) (id int64, err error) {
	stmt, err := w.db.Prepare(sqlInsertNetPolicy)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(policy.Priority,
		policy.Addr.Src.Begin, policy.Addr.Src.End,
		policy.Addr.Dst.Begin, policy.Addr.Dst.End,
		policy.Protocol.Begin, policy.Protocol.End,
		policy.Port.Src.Begin, policy.Port.Src.End,
		policy.Port.Dst.Begin, policy.Port.Dst.End,
		policy.Flags, policy.Response)
	if err != nil {
		logrus.Error(err)
		return
	}
	id, err = result.LastInsertId()
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) deleteNetPolicyById(id int) (err error) {
	stmt, err := w.db.Prepare(sqlDeleteNetPolicyById)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(id)
	if err != nil {
		logrus.Error(err)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		logrus.Error(err)
		return
	}
	if affected == 0 {
		err = net.ErrorPolicyNotExist
		logrus.Error(err)
		return
	}
	return
}

func (w *Worker) queryNetPolicyLimitOffset(limit, offset int) (policies []net.Policy, err error) {
	stmt, err := w.db.Prepare(sqlQueryNetPolicyLimitOffset)
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
		policy := net.Policy{}
		err = rows.Scan(&policy.ID, &policy.Priority,
			&policy.Addr.Src.Begin, &policy.Addr.Src.End,
			&policy.Addr.Dst.Begin, &policy.Addr.Dst.End,
			&policy.Protocol.Begin, &policy.Protocol.End,
			&policy.Port.Src.Begin, &policy.Port.Src.End,
			&policy.Port.Dst.Begin, &policy.Port.Dst.End,
			&policy.Flags, &policy.Response)
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

func (w *Worker) queryNetEventOffsetLimit(limit, offset int) (events []net.Event, err error) {
	stmt, err := w.db.Prepare(sqlQueryNetEventLimitOffset)
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
		e := net.Event{}
		err = rows.Scan(&e.ID,
			&e.Protocol, &e.SrcAddr, &e.DstAddr, &e.SrcPort, &e.DstPort,
			&e.Timestamp, &e.Policy, &e.Status)
		if err != nil {
			logrus.Error(err)
			return
		}
		events = append(events, e)
	}
	err = rows.Err()
	return
}

func (w *Worker) deleteNetEventById(id int) (err error) {
	stmt, err := w.db.Prepare(sqlDeleteNetEventById)
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

func (w *Worker) updateNetEventStatusById(status, id int) (err error) {
	stmt, err := w.db.Prepare(sqlUpdateNetEventStatusById)
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

func (w *Worker) queryNetPolicyCount() (count int, err error) {
	stmt, err := w.db.Prepare(sqlQueryNetPolicyCount)
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

func (w *Worker) queryNetUnreadEventCount() (count int, err error) {
	stmt, err := w.db.Prepare(sqlQueryNetUnreadEventCount)
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
