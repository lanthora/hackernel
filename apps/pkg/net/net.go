// SPDX-License-Identifier: GPL-2.0-only
package net

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/lanthora/hackernel/apps/pkg/exector"
)

const (
	StatusDisable = 0
	StatusEnable  = 1
)

const (
	StatusEventUnread = 0
	StatusEventRead   = 1
)

var (
	ErrorEnable         = errors.New("net protection enable failed")
	ErrorDisable        = errors.New("net protection disable failed")
	ErrorClearPolicy    = errors.New("clear net policy failed")
	ErrorPolicyNotExist = errors.New("net policy does not exist")
)

type Policy struct {
	ID       int64 `json:"id"`
	Priority int8  `json:"priority"`
	Addr     struct {
		Src struct {
			Begin string `json:"begin"`
			End   string `json:"end"`
		} `json:"src"`
		Dst struct {
			Begin string `json:"begin"`
			End   string `json:"end"`
		} `json:"dst"`
	} `json:"addr"`
	Protocol struct {
		Begin uint8 `json:"begin"`
		End   uint8 `json:"end"`
	} `json:"protocol"`
	Port struct {
		Src struct {
			Begin uint16 `json:"begin"`
			End   uint16 `json:"end"`
		} `json:"src"`
		Dst struct {
			Begin uint16 `json:"begin"`
			End   uint16 `json:"end"`
		} `json:"dst"`
	} `json:"port"`
	Flags    int32  `json:"flags"`
	Response uint32 `json:"response"`
}

type Event struct {
	ID        int64  `json:"id"`
	Protocol  int    `json:"protocol"`
	SrcAddr   string `json:"saddr"`
	DstAddr   string `json:"daddr"`
	SrcPort   int    `json:"sport"`
	DstPort   int    `json:"dport"`
	Timestamp int64  `json:"timestamp"`
	Policy    int64  `json:"policy"`
	Status    int    `json:"status"`
}

func AddPolicy(policy Policy) bool {
	request := struct {
		Type string `json:"type"`
		*Policy
	}{
		Type:   "user::net::insert",
		Policy: &policy,
	}

	bytes, err := json.Marshal(request)
	if err != nil {
		return false
	}

	tmp, err := exector.Exec(string(bytes), time.Second)
	if err != nil {
		return false
	}

	response := struct {
		Code  int         `json:"code"`
		Extra interface{} `json:"extra"`
	}{}
	if err = json.Unmarshal([]byte(tmp), &response); err != nil {
		return false
	}
	return response.Code == 0
}

func DeletePolicy(id int) bool {
	request := struct {
		Type string `json:"type"`
		ID   int    `json:"id"`
	}{
		Type: "user::net::delete",
		ID:   id,
	}

	bytes, err := json.Marshal(request)
	if err != nil {
		return false
	}

	tmp, err := exector.Exec(string(bytes), time.Second)
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

func Enable() bool {
	tmp, err := exector.Exec(`{"type":"user::net::enable"}`, time.Second)
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
	tmp, err := exector.Exec(`{"type":"user::net::disable"}`, time.Second)
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
	tmp, err := exector.Exec(`{"type":"user::net::clear"}`, time.Second)
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
