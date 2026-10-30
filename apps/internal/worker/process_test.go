// SPDX-License-Identifier: GPL-2.0-only
package worker

import (
	"database/sql"
	"github.com/lanthora/hackernel/apps/internal/config"
	_ "github.com/mattn/go-sqlite3"
	"testing"
)

func TestRepeatedEventPreservesUserDecision(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(sqlCreateProcessTable); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("insert into process_event(workdir,binary,argv,count,judge,status) values('/tmp','/bin/tool','tool',1,1,2)"); err != nil {
		t.Fatal(err)
	}
	w := &ProcessWorker{db: db, config: cfg}
	if err = w.updateCmd("/tmp", "/bin/tool", "tool", 1); err != nil {
		t.Fatal(err)
	}
	var status, count int
	if err = db.QueryRow("select status,count from process_event").Scan(&status, &count); err != nil {
		t.Fatal(err)
	}
	if status != 2 || count != 2 {
		t.Fatalf("status=%d count=%d; trusted decision should survive a repeated report", status, count)
	}
}
