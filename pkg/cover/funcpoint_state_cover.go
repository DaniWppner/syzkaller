// This files provides types for working with function pointer state coverage information (pairs of <PC, Stored Function Pointer>).
package cover

import (
	"fmt"
	"strings"

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

func (fpcov FuncPointerCover) Copy() FuncPointerCover {
	res := make(FuncPointerCover, len(fpcov))
	for store := range fpcov {
		res[store] = struct{}{}
	}
	return res
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

func FPCoverFromRaw(raw FuncPointerCoverRaw) FuncPointerCover {
	if len(raw) == 0 {
		return nil
	}
	fpcov := make(FuncPointerCover, len(raw))
	for _, entry := range raw {
		fpcov[FuncPointerPCEntry{
			PC:         entry.Pc,
			StoreValue: entry.StoreValue}] = struct{}{}
	}
	return fpcov
}

func (fpcov FuncPointerCover) DiffRaw(raw FuncPointerCoverRaw) FuncPointerCover {
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
	return res
}

func (fpcov FuncPointerCover) IntersectsWith(other FuncPointerCover) bool {
	for store := range fpcov {
		if _, ok := other[store]; ok {
			return true
		}
	}
	return false
}

func (fpcov FuncPointerCover) Intersection(other FuncPointerCover) FuncPointerCover {
	if other.Empty() {
		return nil
	}
	res := make(FuncPointerCover, len(fpcov))
	for store := range fpcov {
		if _, ok := other[store]; ok {
			res[store] = struct{}{}
		}
	}
	return res
}

func (fpcov *FuncPointerCover) Merge(new FuncPointerCover) {
	if new.Empty() {
		return
	}
	fpc := *fpcov
	if fpc == nil {
		fpc = make(FuncPointerCover, len(new))
		*fpcov = fpc
	}
	for store := range new {
		fpc[store] = struct{}{}
	}
}
