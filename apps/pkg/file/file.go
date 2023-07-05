// SPDX-License-Identifier: GPL-2.0-only
package file

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/lanthora/hackernel/apps/pkg/exector"
	"github.com/sirupsen/logrus"
)

const (
	StatusDisable = 0
	StatusEnable  = 1
)

const (
	FlagAny    = 0
	FlagNew    = 1
	FlagUpdate = 2
)

const (
	StatusPolicyNormal       = 0
	StatusPolicyUnknown      = 1
	StatusPolicyConflict     = 2
	StatusPolicyFileNotExist = 3
)

const (
	StatusEventUnread = 0
	StatusEventRead   = 1
)

var (
	ErrorEnable      = errors.New("file protection enable failed")
	ErrorDisable     = errors.New("file protection disable failed")
	ErrorClearPolicy = errors.New("clear file policy failed")
)

type Policy struct {
	ID        int64  `json:"id"`
	Path      string `json:"path"`
	Fsid      int64  `json:"fsid"`
	Ino       int64  `json:"ino"`
	Perm      int    `json:"perm"`
	Timestamp int64  `json:"timestamp"`
	Status    int    `json:"status"`
}

type Event struct {
	ID        int64  `json:"id"`
	Path      string `json:"path"`
	Fsid      int64  `json:"fsid"`
	Ino       int64  `json:"ino"`
	Perm      int    `json:"perm"`
	Timestamp int64  `json:"timestamp"`
	Policy    int64  `json:"policy"`
	Status    int    `json:"status"`
}

func SetPolicy(path string, perm, flag int) (fsid, ino int64, status int, err error) {
	request := map[string]interface{}{
		"type": "user::file::set",
		"path": path,
		"perm": perm,
		"flag": flag,
	}

	bytes, err := json.Marshal(request)
	if err != nil {
		return
	}

	tmp, err := exector.Exec(string(bytes), time.Second)
	if err != nil {
		return
	}

	response := struct {
		Code int    `json:"code"`
		Fsid uint64 `json:"fsid"`
		Ino  uint64 `json:"ino"`
	}{}
	if err = json.Unmarshal([]byte(tmp), &response); err != nil {
		logrus.Error(err)
		return
	}

	fsid = (int64)(response.Fsid)
	ino = (int64)(response.Ino)

	switch response.Code {
	case 0:
		status = StatusPolicyNormal
	case -2:
		status = StatusPolicyFileNotExist
	case -17:
		status = StatusPolicyConflict
	default:
		status = StatusPolicyUnknown
	}
	return
}

func Enable() bool {
	tmp, err := exector.Exec(`{"type":"user::file::enable"}`, time.Second)
	if err != nil {
		return false
	}

	response := struct {
		Code  int         `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(tmp), &response); err != nil {
		return false
	}
	return response.Code == 0
}

func Disable() bool {
	tmp, err := exector.Exec(`{"type":"user::file::disable"}`, time.Second)
	if err != nil {
		return false
	}

	response := struct {
		Code  int         `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(tmp), &response); err != nil {
		return false
	}
	return response.Code == 0
}

func ClearPolicy() bool {
	tmp, err := exector.Exec(`{"type":"user::file::clear"}`, time.Second)
	if err != nil {
		return false
	}

	response := struct {
		Code  int         `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(tmp), &response); err != nil {
		return false
	}
	return response.Code == 0
}
