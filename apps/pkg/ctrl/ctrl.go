// SPDX-License-Identifier: GPL-2.0-only
package ctrl

import (
	"encoding/json"
	"github.com/lanthora/hackernel/apps/pkg/exector"
	"time"
)

func Shutdown() bool {
	reply, err := exector.Exec(`{"type":"user::ctrl::exit"}`, time.Second)
	if err != nil {
		return false
	}
	var result struct {
		Code *int `json:"code"`
	}
	return json.Unmarshal([]byte(reply), &result) == nil && result.Code != nil && *result.Code == 0
}
