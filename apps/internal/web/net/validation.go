// SPDX-License-Identifier: GPL-2.0-only
package net

import (
	"bytes"
	"net"

	policy "github.com/lanthora/hackernel/apps/pkg/net"
)

func validPolicy(p policy.Policy) bool {
	validAddr := func(begin, end string) bool {
		a, b := net.ParseIP(begin).To4(), net.ParseIP(end).To4()
		return a != nil && b != nil && bytes.Compare(a, b) <= 0
	}
	return validAddr(p.Addr.Src.Begin, p.Addr.Src.End) && validAddr(p.Addr.Dst.Begin, p.Addr.Dst.End) && p.Protocol.Begin <= p.Protocol.End && p.Port.Src.Begin <= p.Port.Src.End && p.Port.Dst.Begin <= p.Port.Dst.End && p.Flags >= 1 && p.Flags <= 15 && p.Flags&3 != 0 && p.Response <= 3
}
