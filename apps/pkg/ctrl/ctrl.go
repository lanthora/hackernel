// SPDX-License-Identifier: GPL-2.0-only
package ctrl

import "github.com/lanthora/hackernel/apps/pkg/exector"

func Shutdown() bool {
	exector.Exec(`{"type":"user::ctrl::exit"}`, 0)
	return true
}
