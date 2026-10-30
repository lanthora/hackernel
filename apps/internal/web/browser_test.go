// SPDX-License-Identifier: GPL-2.0-only
package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestManagedFilesystemBrowser(t *testing.T) {
	_, handler := testServer(t)
	c := &testClient{t: t, handler: handler}
	root := t.TempDir()
	c.post("/file/browse", gin.H{"path": root}, 100)
	c.post("/auth/login", gin.H{"username": "admin", "password": "test-password"}, 0)
	for i := 0; i < 105; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%03d", i)), []byte("never exposed in listing"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	folder := filepath.Join(root, "folder")
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(folder, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "absent"), filepath.Join(root, "broken")); err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Name       string
		Path       string
		Directory  bool
		Symlink    bool
		Selectable bool
	}
	type listing struct {
		Path       string
		Parent     string
		Entries    []entry
		NextCursor string
	}
	result := c.post("/file/browse", gin.H{"path": root}, 0)
	var first listing
	if err := json.Unmarshal(result.Data, &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 100 || first.NextCursor == "" {
		t.Fatalf("invalid first page: %s", result.Data)
	}
	if first.Entries[0].Name != "broken" || first.Entries[0].Selectable {
		t.Fatal("broken symlink should not be selectable")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Path != canonical {
		t.Fatal("directory path should be canonical")
	}
	result = c.post("/file/browse", gin.H{"path": root, "after": first.NextCursor}, 0)
	var second listing
	json.Unmarshal(result.Data, &second)
	if len(second.Entries) != 8 || second.NextCursor != "" {
		t.Fatalf("invalid next page: %s", result.Data)
	}
	if second.Entries[0].Name <= first.NextCursor {
		t.Fatal("pages overlap")
	}
	result = c.post("/file/browse", gin.H{"path": root, "search": "FILE-104"}, 0)
	var filtered listing
	json.Unmarshal(result.Data, &filtered)
	if len(filtered.Entries) != 1 || filtered.Entries[0].Name != "file-104" || !filtered.Entries[0].Selectable {
		t.Fatal(string(result.Data))
	}
	result = c.post("/file/browse", gin.H{"path": filepath.Join(root, "link")}, 0)
	var link listing
	json.Unmarshal(result.Data, &link)
	if link.Path != filepath.Join(canonical, "folder") || len(link.Entries) != 0 {
		t.Fatal(string(result.Data))
	}
	c.post("/file/browse", gin.H{"path": "relative"}, 2)
	c.post("/file/browse", gin.H{"path": filepath.Join(root, "absent")}, 315)
	c.post("/file/browse", gin.H{"path": filepath.Join(root, "file-001")}, 315)
	c.post("/admin/addUser", gin.H{"username": "reader", "password": "reader-password", "aliasName": "Reader", "permissions": "{/file/list*}"}, 0)
	reader := &testClient{t: t, handler: handler}
	reader.post("/auth/login", gin.H{"username": "reader", "password": "reader-password"}, 0)
	reader.post("/file/browse", gin.H{"path": root}, 101)
}
