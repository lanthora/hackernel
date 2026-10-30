// SPDX-License-Identifier: GPL-2.0-only
package process

import (
	"encoding/json"
	"errors"

	"github.com/lanthora/hackernel/apps/pkg/exector"
	"github.com/sirupsen/logrus"
)

const (
	StatusDisable = 0
	StatusEnable  = 1
)

const (
	StatusJudgeDisable = 0
	StatusJudgeAudit   = 1
	StatusJudgeDefense = 2
)

const (
	StatusPending   = 0
	StatusUntrusted = 1
	StatusTrusted   = 2
)

var (
	ErrorEnable      = errors.New("process protection enable failed")
	ErrorDisable     = errors.New("process protection disable failed")
	ErrorUpdateJudge = errors.New("process protection update Judge failed")
	ErrorInvalidCmd  = errors.New("invalid cmd")
	ErrorClearPolicy = errors.New("clear process policy failed")
)

func UpdateJudge(judge int) bool {
	request := map[string]interface{}{
		"type":  "user::proc::judge",
		"judge": judge,
	}

	bytes, err := json.Marshal(request)
	if err != nil || len(bytes) > 1024 {
		return false
	}

	responseStr, err := exector.Exec(string(bytes), exector.ControlTimeout)
	if err != nil {
		return false
	}

	response := struct {
		Code  *int        `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(responseStr), &response); err != nil {
		return false
	}
	return response.Code != nil && *response.Code == 0
}

func Enable() bool {
	responseStr, err := exector.Exec(`{"type":"user::proc::enable"}`, exector.ControlTimeout)
	if err != nil {
		return false
	}

	response := struct {
		Code  *int        `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(responseStr), &response); err != nil {
		return false
	}
	return response.Code != nil && *response.Code == 0
}

func Disable() bool {
	responseStr, err := exector.Exec(`{"type":"user::proc::disable"}`, exector.ControlTimeout)
	if err != nil {
		return false
	}

	response := struct {
		Code  *int        `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(responseStr), &response); err != nil {
		return false
	}
	return response.Code != nil && *response.Code == 0
}

func ClearPolicy() bool {
	responseStr, err := exector.Exec(`{"type":"user::proc::trusted::clear"}`, exector.ControlTimeout)
	if err != nil {
		return false
	}

	response := struct {
		Code  *int        `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err := json.Unmarshal([]byte(responseStr), &response); err != nil {
		return false
	}
	return response.Code != nil && *response.Code == 0
}

func SetTrustedCmd(workdir, binary, argv string) (err error) {
	data := map[string]string{
		"type":    "user::proc::trusted::insert",
		"workdir": workdir,
		"binary":  binary,
		"argv":    argv,
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}

	var reply string
	reply, err = exector.Exec(string(b), exector.ControlTimeout)
	if err != nil {
		logrus.Error(err)
		return
	}
	if err == nil {
		err = checkReply(reply)
	}
	return
}

func SetUntrustedCmd(workdir, binary, argv string) (err error) {
	data := map[string]string{
		"type":    "user::proc::trusted::delete",
		"workdir": workdir,
		"binary":  binary,
		"argv":    argv,
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}

	var reply string
	reply, err = exector.Exec(string(b), exector.ControlTimeout)
	if err != nil {
		logrus.Error(err)
		return
	}
	if err == nil {
		err = checkReply(reply)
	}
	return
}

func checkReply(reply string) error {
	var result struct {
		Code *int `json:"code"`
	}
	if err := json.Unmarshal([]byte(reply), &result); err != nil {
		return err
	}
	if result.Code == nil || *result.Code != 0 {
		return errors.New("core rejected process policy")
	}
	return nil
}
