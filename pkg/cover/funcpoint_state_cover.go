// This files provides types for working with function pointer state coverage information (pairs of <PC, Stored Function Pointer>).
package cover

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
)

type FuncPointerCover map[flatrpc.FuncPointerStore]struct{}
type FuncPointerCoverRaw []*flatrpc.FuncPointerStore
type FuncPointerCoverFlat []flatrpc.FuncPointerStore

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
