// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
)

// Cover keeps track of the signal known to the fuzzer.
type Cover struct {
	signalMu            sync.RWMutex
	funcPointerMu       sync.RWMutex
	maxSignal           signal.Signal          // max signal ever observed (including flakes)
	newSignal           signal.Signal          // newly identified max signal
	maxFuncPointerCover cover.FuncPointerCover // max function pointer state coverage observed (including flakes)

	coveredFunctionsMu sync.RWMutex
	coveredFunctions   map[uint64]struct{}
	reportGenerator    func() (*cover.ReportGenerator, error)
}

func newCover(reportGenerator func() (*cover.ReportGenerator, error)) *Cover {
	cover := new(Cover)
	cover.reportGenerator = reportGenerator
	stat.New("max signal", "Maximum fuzzing signal (including flakes)",
		stat.Graph("signal"), stat.LenOf(&cover.maxSignal, &cover.signalMu))
	return cover
}

func (cover *Cover) addRawMaxSignal(signal []uint64, prio uint8) signal.Signal {
	cover.signalMu.Lock()
	defer cover.signalMu.Unlock()
	diff := cover.maxSignal.DiffRaw(signal, prio)
	if diff.Empty() {
		return diff
	}
	cover.maxSignal.Merge(diff)
	cover.newSignal.Merge(diff)
	return diff
}

func (cover *Cover) addRawFuncPointerCover(newRaw cover.FuncPointerCoverRaw) (cover.FuncPointerCover, time.Duration) {
	start := time.Now()
	cover.funcPointerMu.Lock()
	defer cover.funcPointerMu.Unlock()
	diff, _ := cover.maxFuncPointerCover.DiffRaw(newRaw)
	cover.maxFuncPointerCover.Merge(diff)
	return diff, time.Since(start)
}

func (cover *Cover) CopyMaxSignal() signal.Signal {
	cover.signalMu.RLock()
	defer cover.signalMu.RUnlock()
	return cover.maxSignal.Copy()
}

func (cover *Cover) GrabSignalDelta() signal.Signal {
	cover.signalMu.Lock()
	defer cover.signalMu.Unlock()
	plus := cover.newSignal
	cover.newSignal = nil
	return plus
}

func (coverObj *Cover) UpdateCoveredFunctions(newPCs []uint64) ([]byte, error) {
	if coverObj.reportGenerator == nil {
		return nil, nil
	}

	coverObj.coveredFunctionsMu.Lock()
	defer coverObj.coveredFunctionsMu.Unlock()

	if coverObj.coveredFunctions == nil {
		coverObj.coveredFunctions = make(map[uint64]struct{})
	}

	rg, err := coverObj.reportGenerator()
	if err != nil {
		return nil, err
	}
	type funcLog struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Line int    `json:"line"`
	}
	var newLogs []funcLog
	pcsToSymbolize := make(map[*vminfo.KernelModule][]uint64)
	pcToSym := make(map[uint64]*backend.Symbol)

	for _, pc := range newPCs {
		idx := sort.Search(len(rg.Symbols), func(i int) bool {
			return pc < rg.Symbols[i].End
		})
		if idx < len(rg.Symbols) {
			sym := rg.Symbols[idx]
			if pc >= sym.Start && pc <= sym.End {
				if _, ok := coverObj.coveredFunctions[sym.Start]; !ok {
					coverObj.coveredFunctions[sym.Start] = struct{}{}

					pcsToSymbolize[sym.Module] = append(pcsToSymbolize[sym.Module], sym.Start)
					pcToSym[sym.Start] = sym
				}
			}
		}
	}

	if len(pcsToSymbolize) > 0 {
		frames, err := rg.Symbolize(pcsToSymbolize)
		if err == nil {
			for _, frame := range frames {
				sym := pcToSym[frame.PC]
				if sym != nil {
					newLogs = append(newLogs, funcLog{
						Name: sym.Name,
						Path: frame.Path,
						Line: frame.StartLine,
					})
					delete(pcToSym, frame.PC)
				}
			}
		}

		for _, sym := range pcToSym {
			path := ""
			if sym.Unit != nil {
				path = sym.Unit.Path
			}
			newLogs = append(newLogs, funcLog{
				Name: sym.Name,
				Path: path,
				Line: 0,
			})
		}
	}

	if len(newLogs) > 0 {
		return json.Marshal(newLogs)
	}
	return nil, nil
}

func (coverObj *Cover) HasUncoveredFuncPointers(fpcov cover.FuncPointerCover) bool {
	coverObj.coveredFunctionsMu.RLock()
	defer coverObj.coveredFunctionsMu.RUnlock()

	if coverObj.coveredFunctions == nil {
		// If map hasn't been initialized/populated, all pointers are uncovered
		return !fpcov.Empty()
	}

	for entry := range fpcov {
		if _, ok := coverObj.coveredFunctions[entry.StoreValue]; !ok {
			return true // Found at least one uncovered function pointer
		}
	}
	return false
}
