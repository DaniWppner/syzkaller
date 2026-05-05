// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
)

// Cover keeps track of the signal known to the fuzzer.
type Cover struct {
	signalMu            sync.RWMutex
	funcPointerMu       sync.RWMutex
	maxSignal           signal.Signal          // max signal ever observed (including flakes)
	newSignal           signal.Signal          // newly identified max signal
	maxFuncPointerCover cover.FuncPointerCover // max function pointer state coverage observed
}

func newCover() *Cover {
	cover := new(Cover)
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

func (cover *Cover) getNewFuncPointerCover(newRaw cover.FuncPointerCoverRaw) cover.FuncPointerCover {
	cover.funcPointerMu.RLock()
	defer cover.funcPointerMu.RUnlock()
	diff := cover.maxFuncPointerCover.DiffRaw(newRaw)
	return diff
}

func (cover *Cover) addFuncPointerCover(new cover.FuncPointerCover) cover.FuncPointerCover {
	cover.funcPointerMu.Lock()
	defer cover.funcPointerMu.Unlock()
	cover.maxFuncPointerCover.Merge(new)
	return cover.maxFuncPointerCover
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
