// This files provides types for working with function pointer state coverage information (pairs of <PC, Stored Function Pointer>).
package cover

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// We'd like to ignore the value of StoreAddress for now
type FuncPointerPCEntry struct {
	PC         uint64
	StoreValue uint64
}

// This copies signal.Signal so it will have the same linter problem
type FuncPointerCover map[FuncPointerPCEntry]struct{} // nolint: recvcheck
type FuncPointerCoverRaw []*flatrpc.FuncPointerStore

func (fpcov FuncPointerCover) Len() int {
	return len(fpcov)
}

func (fpcov FuncPointerCover) Empty() bool {
	return len(fpcov) == 0
}

func (fpcov FuncPointerCover) Copy() (FuncPointerCover, time.Duration) {
	start := time.Now()
	res := make(FuncPointerCover, len(fpcov))
	for store := range fpcov {
		res[store] = struct{}{}
	}
	return res, time.Since(start)
}

func (fpcov FuncPointerCover) Preview() string {
	if len(fpcov) > 0 {
		var sb strings.Builder
		sb.WriteByte('[')
		i := 0
		for store := range fpcov {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "{\"PC\": \"0x%x\", \"StoredValue\": \"0x%x\"}",
				store.PC, store.StoreValue)
			i++
		}
		sb.WriteByte(']')
		return sb.String()
	}
	return ""
}

func FPCoverFromRaw(raw FuncPointerCoverRaw) (FuncPointerCover, time.Duration) {
	start := time.Now()
	if len(raw) == 0 {
		return nil, time.Since(start)
	}
	fpcov := make(FuncPointerCover, len(raw))
	for _, entry := range raw {
		fpcov[FuncPointerPCEntry{
			PC:         entry.Pc,
			StoreValue: entry.StoreValue}] = struct{}{}
	}
	return fpcov, time.Since(start)
}

func (fpcov FuncPointerCover) DiffRaw(raw FuncPointerCoverRaw) (FuncPointerCover, time.Duration) {
	start := time.Now()
	var res FuncPointerCover
	for _, entry := range raw {
		store := FuncPointerPCEntry{PC: entry.Pc, StoreValue: entry.StoreValue}
		if _, ok := fpcov[store]; ok {
			continue
		}
		if res == nil {
			res = make(FuncPointerCover)
		}
		res[store] = struct{}{}
	}
	return res, time.Since(start)
}

func (fpcov FuncPointerCover) IntersectsWith(other FuncPointerCover) (bool, time.Duration) {
	start := time.Now()
	for store := range fpcov {
		if _, ok := other[store]; ok {
			return true, time.Since(start)
		}
	}
	return false, time.Since(start)
}

func (fpcov FuncPointerCover) Intersection(other FuncPointerCover) (FuncPointerCover, time.Duration) {
	start := time.Now()
	if other.Empty() {
		return nil, time.Since(start)
	}
	res := make(FuncPointerCover, len(fpcov))
	for store := range fpcov {
		if _, ok := other[store]; ok {
			res[store] = struct{}{}
		}
	}
	return res, time.Since(start)
}

func (fpcov *FuncPointerCover) Merge(new FuncPointerCover) time.Duration {
	start := time.Now()
	if new.Empty() {
		return time.Since(start)
	}
	fpc := *fpcov
	if fpc == nil {
		fpc = make(FuncPointerCover, len(new))
		*fpcov = fpc
	}
	for store := range new {
		fpc[store] = struct{}{}
	}
	return time.Since(start)
}
