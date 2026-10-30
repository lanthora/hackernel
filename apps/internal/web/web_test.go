// SPDX-License-Identifier: GPL-2.0-only
package web

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

type testCore struct {
	conn  *net.UnixConn
	code  atomic.Int32
	delay atomic.Int64
}

func startTestCore(t *testing.T) *testCore {
	t.Helper()
	name := filepath.Join(t.TempDir(), "c.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HACKERNEL_SOCKET", name)
	core := &testCore{conn: conn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFromUnix(buffer)
			if err != nil {
				return
			}
			var message map[string]any
			if json.Unmarshal(buffer[:n], &message) != nil {
				continue
			}
			time.Sleep(time.Duration(core.delay.Load()))
			message["code"] = core.code.Load()
			message["fsid"] = 1
			message["ino"] = 2
			reply, _ := json.Marshal(message)
			conn.WriteToUnix(reply, addr)
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return core
}

type response struct {
	Status int             `json:"status"`
	Data   json.RawMessage `json:"data"`
}
type testClient struct {
	t       *testing.T
	handler http.Handler
	cookie  *http.Cookie
}

func (c *testClient) post(path string, body any, expected int) response {
	c.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		c.t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		c.t.Fatalf("%s: HTTP %d %s", path, rec.Code, rec.Body.String())
	}
	var result response
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		c.t.Fatalf("%s: %v: %s", path, err, rec.Body.String())
	}
	if result.Status != expected {
		c.t.Fatalf("%s: status %d, want %d: %s", path, result.Status, expected, rec.Body.String())
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "session" {
			c.cookie = cookie
		}
	}
	return result
}
func testServer(t *testing.T) (*sql.DB, http.Handler) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, schema := range testSchema {
		if _, err := db.Exec(schema); err != nil {
			t.Fatal(err)
		}
	}
	w := NewWorker("127.0.0.1:0", db)
	if err := w.Init(); err != nil {
		t.Fatal(err)
	}
	return db, w.server.Handler
}
func execSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
func scalar(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestManagementWorkflow(t *testing.T) {
	core := startTestCore(t)
	db, handler := testServer(t)
	c := &testClient{t: t, handler: handler}
	c.post("/process/listEvents", gin.H{"limit": 25, "offset": 0}, 100)
	c.post("/auth/login", gin.H{"username": "admin", "password": "test-password"}, 0)
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie must be HttpOnly and SameSite Strict")
	}
	var hash string
	db.QueryRow("select password from user where username='admin'").Scan(&hash)
	if !strings.HasPrefix(hash, "$2") {
		t.Fatal("password was not hashed with bcrypt")
	}
	c.post("/auth/showCurrentUserInfo", gin.H{}, 0)
	health := c.post("/ctrl/status", gin.H{}, 0)
	if !bytes.Contains(health.Data, []byte(`"coreOnline":true`)) {
		t.Fatal(string(health.Data))
	}
	c.post("/process/enableModule", gin.H{}, 0)
	core.code.Store(-1)
	c.post("/process/disableModule", gin.H{}, 201)
	if scalar(t, db, "select integer from config where key='process module status'") != 1 {
		t.Fatal("failed core command changed config")
	}
	c.post("/process/updateWorkMode", gin.H{"judge": 2}, 202)
	if scalar(t, db, "select count(*) from config where key='process protection mode'") != 0 {
		t.Fatal("rejected mode was saved")
	}
	core.code.Store(0)
	c.post("/process/updateWorkMode", gin.H{}, 2)
	c.post("/process/updateWorkMode", gin.H{"judge": 1}, 0)
	c.post("/process/updateDefaultEventStatus", gin.H{"status": 0}, 0)
	for i := 1; i <= 30; i++ {
		execSQL(t, db, "insert into process_event(workdir,binary,argv,count,judge,status) values('/tmp','/bin/test',?,1,1,0)", i)
	}
	result := c.post("/process/listEvents", gin.H{"limit": 25, "offset": 0}, 0)
	var events []struct {
		ID int `json:"id"`
	}
	json.Unmarshal(result.Data, &events)
	if len(events) != 25 || events[0].ID != 1 || events[24].ID != 25 {
		t.Fatal(string(result.Data))
	}
	result = c.post("/process/listEvents", gin.H{"limit": 25, "offset": 25}, 0)
	json.Unmarshal(result.Data, &events)
	if len(events) != 5 || events[0].ID != 26 {
		t.Fatal(string(result.Data))
	}
	c.post("/process/listEvents", gin.H{"limit": 0}, 2)
	c.post("/process/listEvents", gin.H{"limit": 201}, 2)
	c.post("/process/updateEventStatus", gin.H{"id": 1, "status": 2}, 0)
	c.post("/process/deleteEvents", gin.H{"id": 1}, 2)
	core.code.Store(-1)
	c.post("/process/updateEventStatus", gin.H{"id": 1, "status": 1}, 203)
	if scalar(t, db, "select status from process_event where id=1") != 2 {
		t.Fatal("rejected trust command was persisted")
	}
	core.code.Store(0)
	c.post("/process/updateEventStatus", gin.H{"id": 1, "status": 1}, 0)
	c.post("/process/deleteEvents", gin.H{"id": 1}, 0)
	c.post("/file/addPolicy", gin.H{"path": "/etc/example", "perm": 14}, 0)
	c.post("/file/updatePolicy", gin.H{"id": 1, "perm": 240}, 0)
	if scalar(t, db, "select perm from file_policy where id=1") != 240 {
		t.Fatal("file policy update failed")
	}
	c.post("/file/listPolicies", gin.H{"limit": 25}, 0)
	c.post("/file/addPolicy", gin.H{"path": "/etc/example", "perm": 256}, 2)
	execSQL(t, db, "insert into file_event(path,perm,timestamp,policy,status) values('/etc/example',16,1,1,0)")
	c.post("/file/updateEventStatus", gin.H{"id": 1, "status": 1}, 0)
	c.post("/file/updateEventStatus", gin.H{"id": 999, "status": 1}, 313)
	c.post("/file/deleteEvent", gin.H{"id": 1}, 0)
	c.post("/file/clearPolicies", gin.H{}, 0)
	if scalar(t, db, "select count(*) from file_policy") != 0 {
		t.Fatal("file policies not cleared")
	}
	policy := gin.H{"priority": -1, "addr": gin.H{"src": gin.H{"begin": "0.0.0.0", "end": "255.255.255.255"}, "dst": gin.H{"begin": "127.0.0.1", "end": "127.0.0.1"}}, "protocol": gin.H{"begin": 6, "end": 6}, "port": gin.H{"src": gin.H{"begin": 0, "end": 65535}, "dst": gin.H{"begin": 22, "end": 22}}, "flags": 1, "response": 3}
	c.post("/net/addPolicy", policy, 0)
	core.code.Store(-1)
	c.post("/net/addPolicy", policy, 402)
	if scalar(t, db, "select count(*) from net_policy") != 1 {
		t.Fatal("rejected network rule persisted")
	}
	c.post("/net/deletePolicy", gin.H{"id": 1}, 404)
	if scalar(t, db, "select count(*) from net_policy") != 1 {
		t.Fatal("failed deletion removed saved rule")
	}
	core.code.Store(0)
	c.post("/net/deletePolicy", gin.H{"id": 1}, 0)
	policy["flags"] = 0
	c.post("/net/addPolicy", policy, 2)
	c.post("/admin/addUser", gin.H{"username": "reader", "password": "reader-password", "aliasName": "Reader", "permissions": "{/process/listEvents,/ctrl/status}"}, 0)
	reader := &testClient{t: t, handler: handler}
	reader.post("/auth/login", gin.H{"username": "reader", "password": "reader-password"}, 0)
	reader.post("/auth/showCurrentUserInfo", gin.H{}, 0)
	reader.post("/process/listEvents", gin.H{"limit": 25}, 0)
	reader.post("/process/disableModule", gin.H{}, 101)
	c.post("/admin/updateUserInfo", gin.H{"userID": 2, "username": "reader", "password": "changed-password", "aliasName": "Reader", "permissions": "{/ctrl/status}"}, 0)
	reader.post("/ctrl/status", gin.H{}, 100)
	c.post("/admin/deleteUser", gin.H{"userID": 1}, 2)
	c.post("/admin/updateUserInfo", gin.H{"userID": 1, "username": "admin", "password": "updated-password", "aliasName": "Admin", "permissions": "{*}"}, 0)
	c.post("/auth/showCurrentUserInfo", gin.H{}, 0)
	c.post("/auth/logout", gin.H{}, 0)
	c.post("/ctrl/status", gin.H{}, 100)
	c.post("/auth/login", gin.H{"username": "admin", "password": "test-password"}, 102)
	c.post("/auth/login", gin.H{"username": "admin", "password": "updated-password"}, 0)
	core.conn.Close()
	health = c.post("/ctrl/status", gin.H{}, 0)
	if !bytes.Contains(health.Data, []byte(`"coreOnline":false`)) {
		t.Fatal("offline core reported online")
	}
}

func TestFrontendRoutingAndOriginProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	files := fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}, "assets/app.js": {Data: []byte("console.log('app')")}}
	router := gin.New()
	router.Use(securityHeaders())
	router.POST("/auth/login", func(c *gin.Context) { c.Status(200) })
	router.NoRoute(func(c *gin.Context) { serveFrontend(c, files) })
	for _, tc := range []struct {
		path     string
		code     int
		fragment string
	}{{"/overview", 200, "console"}, {"/events?module=file", 200, "console"}, {"/assets/app.js?v=1", 200, "console.log"}, {"/assets/missing.js", 404, ""}, {"/auth/missing", 404, ""}, {"/favicon.ico", 404, ""}} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.fragment) {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body.String())
		}
	}
	for _, origin := range []string{"http://evil.example", "null", "https://example.com"} {
		req := httptest.NewRequest("POST", "http://localhost/auth/login", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("allowed cross origin %s", origin)
		}
	}
	req := httptest.NewRequest("POST", "http://localhost/auth/login", nil)
	req.Header.Set("Origin", "http://localhost")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal("same-origin request rejected")
	}
}

func TestLegacyPasswordUpgrade(t *testing.T) {
	db, handler := testServer(t)
	sum := sha256.Sum256([]byte("salt" + "legacy-password"))
	execSQL(t, db, "insert into user(username,salt,password,alias,permissions) values(?,?,?,?,?)", "legacy", "salt", hex.EncodeToString(sum[:]), "Legacy", "{*}")
	c := &testClient{t: t, handler: handler}
	c.post("/auth/login", gin.H{"username": "legacy", "password": "legacy-password"}, 0)
	var hash string
	if err := db.QueryRow("select password from user where username='legacy'").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatal("legacy password was not upgraded")
	}
}

func TestSlowKernelControlResponse(t *testing.T) {
	core := startTestCore(t)
	_, handler := testServer(t)
	c := &testClient{t: t, handler: handler}
	c.post("/auth/login", gin.H{"username": "admin", "password": "test-password"}, 0)
	// RCU hook removal can legitimately outlast the former one-second deadline.
	core.delay.Store(int64(1200 * time.Millisecond))
	c.post("/file/enableModule", gin.H{}, 0)
	c.post("/file/disableModule", gin.H{}, 0)
}
