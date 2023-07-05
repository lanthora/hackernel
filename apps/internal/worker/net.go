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
	"github.com/lanthora/hackernel/apps/pkg/net"
	"github.com/lanthora/hackernel/apps/pkg/watchdog"
	"github.com/sirupsen/logrus"
)

const (
	sqlCreateNetPolicyTable = `create table if not exists net_policy(id integer primary key autoincrement, priority integer, addr_src_begin text, addr_src_end text, addr_dst_begin text, addr_dst_end text, protocol_begin integer, protocol_end integer, port_src_begin integer, port_src_end integer, port_dst_begin integer, port_dst_end integer, flags integer, response integer)`
	sqlCreateNetEventTable  = `create table if not exists net_event(id integer primary key autoincrement, protocol integer, saddr text, daddr text, sport integer, dport integer, timestamp integer not null, policy integer, status integer not null)`
	sqlQueryNetPolicy       = `select id,priority,addr_src_begin,addr_src_end,addr_dst_begin,addr_dst_end,protocol_begin,protocol_end,port_src_begin,port_src_end,port_dst_begin,port_dst_end,flags,response from net_policy`
	sqlInsertNetEvent       = `insert into net_event(protocol,saddr,daddr,sport,dport,timestamp,policy,status) values(?,?,?,?,?,?,?,?)`
)

type NetWorker struct {
	db *sql.DB

	running bool
	wg      sync.WaitGroup
	conn    *connector.Connector
	config  *config.Config
	dog     *watchdog.Watchdog
}

func NewNetWorker(db *sql.DB) *NetWorker {
	w := NetWorker{
		db:   db,
		conn: connector.New(),
	}
	return &w
}

func (w *NetWorker) Init() (err error) {
	err = w.initDB()
	if err != nil {
		return
	}

	w.config, err = config.New(w.db)
	if err != nil {
		logrus.Error(err)
		return
	}

	if err = w.initNetPolicy(); err != nil {
		logrus.Error(err)
		return
	}

	status, err := w.config.GetInteger(config.NetModuleStatus)
	if err != nil {
		err = nil
		status = net.StatusDisable
	}

	switch status {
	case net.StatusEnable:
		if ok := net.Enable(); !ok {
			err = net.ErrorEnable
			logrus.Error(err)
			return
		}
	default:
		if ok := net.Disable(); !ok {
			err = net.ErrorDisable
			logrus.Error(err)
			return
		}
	}

	return
}
func (w *NetWorker) Start() (err error) {

	w.running = true
	err = w.conn.Connect()
	if err != nil {
		logrus.Error(err)
		return
	}

	err = w.conn.Send(`{"type":"user::msg::sub","section":"osinfo::report"}`)
	if err != nil {
		return
	}

	err = w.conn.Send(`{"type":"user::msg::sub","section":"kernel::net::report"}`)
	if err != nil {
		logrus.Error(err)
		return
	}

	w.wg.Add(1)
	go w.run()
	return
}

func (w *NetWorker) Stop() {
	err := w.conn.Send(`{"type":"user::msg::unsub","section":"osinfo::report"}`)
	if err != nil {
		logrus.Error(err)
	}

	err = w.conn.Send(`{"type":"user::msg::unsub","section":"kernel::net::report"}`)
	if err != nil {
		logrus.Error(err)
	}

	if ok := net.Disable(); !ok {
		logrus.Error(net.ErrorDisable)
	}

	if ok := net.ClearPolicy(); !ok {
		logrus.Error(net.ErrorClearPolicy)
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

func (w *NetWorker) initDB() (err error) {
	_, err = w.db.Exec(sqlCreateNetPolicyTable)
	if err != nil {
		logrus.Error(err)
		return
	}

	_, err = w.db.Exec(sqlCreateNetEventTable)
	if err != nil {
		logrus.Error(err)
		return
	}

	return
}

func (w *NetWorker) initNetPolicy() (err error) {
	if ok := net.ClearPolicy(); !ok {
		logrus.Error(net.ErrorClearPolicy)
		return
	}

	stmt, err := w.db.Prepare(sqlQueryNetPolicy)
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
		if ok := net.AddPolicy(policy); !ok {
			logrus.Error(err)
			return
		}
	}
	err = rows.Err()
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *NetWorker) handleNetEvent(protocol int, saddr, daddr string, sport, dport int, policy int) (err error) {
	stmt, err := w.db.Prepare(sqlInsertNetEvent)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(protocol, saddr, daddr, sport, dport, time.Now().Unix(), policy, net.StatusEventUnread)
	if err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (w *NetWorker) handleMsg(msg string) {
	event := struct {
		Type     string `json:"type"`
		Protocol int    `json:"protocol"`
		SrcAddr  string `json:"saddr"`
		DstAddr  string `json:"daddr"`
		SrcPort  int    `json:"sport"`
		DstPort  int    `json:"dport"`
		Policy   int    `json:"policy"`
	}{}

	err := json.Unmarshal([]byte(msg), &event)
	if err != nil {
		logrus.Error(err)
		return
	}
	switch event.Type {
	case "kernel::net::report":
		err = w.handleNetEvent(event.Protocol,
			event.SrcAddr, event.DstAddr,
			event.SrcPort, event.DstPort,
			event.Policy)
		if err != nil {
			logrus.Error(err)
		}
	default:
	}
}

func (w *NetWorker) run() {
	defer w.wg.Done()
	w.dog = watchdog.New(10*time.Second, func() {
		logrus.Error("osinfo::report timeout")
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	})
	defer w.dog.Stop()
	for w.running {
		msg, err := w.conn.Recv()

		if !w.running {
			logrus.Info("net worker exit")
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
