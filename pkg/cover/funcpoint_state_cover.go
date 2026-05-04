// This files provides types for working with function pointer state coverage information (pairs of <PC, Stored Function Pointer>).
package cover

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// This copies signal.Signal so it will have the same linter problem
type FuncPointerCover map[flatrpc.FuncPointerStore]struct{} // nolint: recvcheck
type FuncPointerCoverRaw []*flatrpc.FuncPointerStore
type FuncPointerCoverFlat []flatrpc.FuncPointerStore

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

func StorePreview(raw FuncPointerCoverRaw) string {
	if len(raw) > 0 {
		var sb strings.Builder
		sb.WriteByte('[')
		for i, entry := range raw {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "{\"PC\": \"0x%x\", \"StoreAddr\": \"0x%x\", \"StoredValue\": \"0x%x\"}",
				entry.Pc, entry.StoreAddr, entry.StoreValue)
		}
		sb.WriteByte(']')
		return sb.String()
	}
	return ""
}

func (fpcov FuncPointerCover) DiffRaw(raw FuncPointerCoverRaw) FuncPointerCover {
	var res FuncPointerCover
	for _, store := range raw {
		if _, ok := fpcov[*store]; ok {
			continue
		}
		if res == nil {
			res = make(FuncPointerCover)
		}
		res[*store] = struct{}{}
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
