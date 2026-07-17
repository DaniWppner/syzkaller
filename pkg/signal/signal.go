// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package signal provides types for working with feedback signal.
package signal

import (
	"fmt"
	"maps"
	"strings"
)

type (
	ElemType uint64
	PrioType int8
)

// Signal was hard to refactor when we enabled recvcheck.
type Signal map[ElemType]PrioType // nolint: recvcheck

func (s Signal) Len() int {
	return len(s)
}

func (s Signal) Empty() bool {
	return len(s) == 0
}

func (s Signal) Copy() Signal {
	c := make(Signal, len(s))
	maps.Copy(c, s)
	return c
}

func RawPreview(raw []uint64) string {
	if len(raw) > 0 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range raw {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (s Signal) SignalPreview() string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func FromRaw(raw []uint64, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[ElemType(e)] = PrioType(prio)
	}
	return s
}

func (s Signal) DiffRaw(raw []uint64, prio uint8) Signal {
	var res Signal
	for _, e := range raw {
		if p, ok := s[ElemType(e)]; ok && p >= PrioType(prio) {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[ElemType(e)] = PrioType(prio)
	}
	return res
}

func (s Signal) IntersectsWith(other Signal) bool {
	for e, p := range s {
		if p1, ok := other[e]; ok && p1 >= p {
			return true
		}
	}
	return false
}

func (s Signal) Intersection(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	res := make(Signal, len(s))
	for e, p := range s {
		if p1, ok := s1[e]; ok && p1 >= p {
			res[e] = p
		}
	}
	return res
}

func (s *Signal) Merge(s1 Signal) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

func (s Signal) ToRaw() []uint64 {
	var raw []uint64
	for e := range s {
		raw = append(raw, uint64(e))
	}
	return raw
}
