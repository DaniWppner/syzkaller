// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"sort"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/signal"
)

func (corpus *Corpus) Minimize(coverFlag bool) {
	corpus.mu.Lock()
	defer corpus.mu.Unlock()

	inputs := make([]*Item, 0, len(corpus.progsMap))
	for _, inp := range corpus.progsMap {
		inputs = append(inputs, inp)
	}

	// Note: inputs are unsorted (based on map iteration).
	// This gives some intentional non-determinism during minimization.
	// However, we want to give preference to non-squashed inputs,
	// so let's sort by this criteria.
	// We also want to give preference to smaller corpus programs:
	// - they are faster to execute,
	// - minimization occasionally fails, so we need to clean it up over time.
	sort.SliceStable(inputs, func(i, j int) bool {
		first := inputs[i]
		second := inputs[j]
		if first.HasAny != second.HasAny {
			return !first.HasAny
		}
		return len(first.Prog.Calls) < len(second.Prog.Calls)
	})

	type ContextPrio struct {
		prio signal.PrioType
		idx  int
	}
	coveredSignal := make(map[signal.ElemType]ContextPrio)
	coveredFuncPointer := make(map[cover.FuncPointerPCEntry]int)

	for i, inp := range inputs {
		for e, p := range inp.Signal {
			if prev, ok := coveredSignal[e]; !ok || p > prev.prio {
				coveredSignal[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
		for e := range inp.FuncPointerCover {
			if _, ok := coveredFuncPointer[e]; !ok {
				coveredFuncPointer[e] = i
			}
		}
	}

	indices := make(map[int]struct{}, len(inputs))
	for _, cp := range coveredSignal {
		indices[cp.idx] = struct{}{}
	}
	for _, idx := range coveredFuncPointer {
		indices[idx] = struct{}{}
	}

	corpus.progsMap = make(map[string]*Item)

	// Overwrite the program lists.
	corpus.ProgramsList = &ProgramsList{}
	for _, area := range corpus.focusAreas {
		area.ProgramsList = &ProgramsList{}
	}
	for idx := range indices {
		inp := inputs[idx]
		corpus.progsMap[inp.Sig] = inp
		corpus.saveProgram(inp.Prog, inp.Signal)
		for area := range inp.areas {
			area.saveProgram(inp.Prog, inp.Signal)
		}
	}
}
