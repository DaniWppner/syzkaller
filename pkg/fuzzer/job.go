// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type JobType string

const (
	JobTriage          JobType = "triage"
	JobCandidateTriage JobType = "candidate_triage"
	JobSmash           JobType = "smash"
	JobHints           JobType = "hints"
)

type job interface {
	run(fuzzer *Fuzzer)
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name   string
	Calls  []string
	Type   JobType
	Execs  atomic.Int32
	ProgId string
	// debug counter of the amount of times a testcase execution was triggered
	// due to functionPointerCoverage and in general.
	// This is slightly duplicate with job.info.Execs
	ExecBecauseFPCov atomic.Int32

	ExecTimeTotal          atomic.Int64
	ExecTimeBecauseOfFPCov atomic.Int64
	ExecsTimeLapses        syncTimePairArray
	ExecsTimeLapsesFPCov   syncTimePairArray

	FromFPCovOrigin bool

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		fuzzer.RecommendedCalls(),
		fuzzer.ChoiceTable())
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	newP := p.Clone()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	return &queue.Request{
		Prog:     newP,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
	}
}

func filteredCoverage(slice []uint64, set map[uint64]struct{}) []uint64 {
	res := make([]uint64, 0, len(slice))
	if len(slice) == 0 || len(set) == 0 {
		return res
	}
	for _, v := range slice {
		if _, ok := set[v]; ok {
			res = append(res, v)
		}
	}
	return res
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p        *prog.Prog
	executor queue.ExecutorID
	flags    ProgFlags
	fuzzer   *Fuzzer
	queue    queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall

	info *JobInfo
}

type triageCall struct {
	errno               int32
	newSignal           signal.Signal
	newFuncPointerCover cover.FuncPointerCover

	// Filled after deflake:
	signals                   [deflakeNeedRuns]signal.Signal
	stableSignal              signal.Signal
	newStableSignal           signal.Signal
	funcPointerCovers         [deflakeNeedRuns]cover.FuncPointerCover
	stableFuncPointerCover    cover.FuncPointerCover
	newStableFuncPointerCover cover.FuncPointerCover
	cover                     cover.Cover
	rawCover                  []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	// Make sure to spread the fromFPCovOrigin taint into the requests
	if job.info.FromFPCovOrigin {
		req.FromFPCovOrigin = true
	}

	execStart := time.Now()
	execResult := job.fuzzer.executeWithFlags(job.queue, req, flags)
	execEnd := time.Now()
	execTime := execEnd.Sub(execStart)

	job.info.ExecTimeTotal.Add(int64(execTime))
	job.info.ExecsTimeLapses.AppendAtomic(execStart, execEnd)
	if req.FromFPCovOrigin {
		job.info.ExecBecauseFPCov.Add(1)
		job.info.ExecTimeBecauseOfFPCov.Add(int64(execTime))
		job.info.ExecsTimeLapsesFPCov.AppendAtomic(execStart, execEnd)
	}

	return execResult
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), info.newSignal.SignalPreview())

		job.info.Logf("call #%d [%s]: |new stored function pointers|=%d%s",
			call, job.p.CallName(call), info.newFuncPointerCover.Len(), info.newFuncPointerCover.Preview())

		filteredRawSignal := filteredCoverage(info.newSignal.ToRaw(), job.fuzzer.Config.DebugFilters)
		if len(filteredRawSignal) > 0 {
			job.info.Logf("call #%d [%s]: |new filtered signal|=%d%s",
				call, job.p.CallName(call), len(filteredRawSignal), signal.RawPreview(filteredRawSignal))
		}
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		return
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Go(func() {
			job.handleCall(call, info)
		})
	}
	wg.Wait()
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	if info.newStableSignal.Empty() && info.newStableFuncPointerCover.Empty() {
		return
	}
	p := job.p
	// skip minimization
	if job.flags&ProgMinimized != 0 {
		job.info.Logf("call #%d [%s]: skip minimize", call, p.CallName(call))
		job.doHandleCall(p, call, info, false)
		return
	}
	// else: do minimization
	minimizedProgs, callIdxs, minimizationSplitted := job.minimize(call, info)
	// idx 0 --> Minimize keeping signal
	pSignal := minimizedProgs[0]
	callSignal := callIdxs[0]
	// idx 1 --> Minimize keeping FuncPointerCover
	pFPCov := minimizedProgs[1]
	callFPCov := callIdxs[1]

	// If both are nil, we couldn't minimize either
	if pSignal == nil && pFPCov == nil {
		return
	}

	// we had to minimize both criteria and we got the same result for both
	if !minimizationSplitted && pSignal != nil && pFPCov != nil {
		// pick any
		job.info.Logf("call #%d [%s]: minimization yielded same prog for signal and stored function pointers", call, p.CallName(call))
		job.doHandleCall(pSignal, callSignal, info, false)
	}

	// minimization either splitted or we were only minimizing signal in the first place
	if (minimizationSplitted || pFPCov == nil) && pSignal != nil {
		// we cannot guarantee stableFuncPointerCover anymore, since minimizing signal
		// might have deleted calls necessary for the registered FuncPointerCover
		signalInfo := new(triageCall)
		*signalInfo = *info
		signalInfo.stableFuncPointerCover = nil
		signalInfo.newStableFuncPointerCover = nil
		job.info.Logf("call #%d [%s]: minimization yielded prog for signal different from stored function pointers. New prog (call #%d):\n%s",
			call, p.CallName(call), callSignal, pSignal.Serialize())
		job.doHandleCall(pSignal, callSignal, signalInfo, false)
	}

	// analogous case for only minimizing FuncPointerCover
	if (minimizationSplitted || pSignal == nil) && pFPCov != nil {
		// see above
		fPCovInfo := new(triageCall)
		*fPCovInfo = *info
		fPCovInfo.stableSignal = nil
		fPCovInfo.newStableSignal = nil
		job.info.Logf("call #%d [%s]: minimization yielded prog for stored function pointers different from signal. New prog (call #%d):\n%s",
			call, p.CallName(call), callFPCov, pFPCov.Serialize())
		job.doHandleCall(pFPCov, callFPCov, fPCovInfo, true)
	}
}

func (job *triageJob) doHandleCall(p *prog.Prog, call int, info *triageCall, fPCovOrigin bool) {
	if p == nil {
		panic(fmt.Sprintf("%s\ndoHandleCall called on nil program. call #%d, [prog-%s]", string(job.info.Bytes()), call, job.info.ProgId))
	}
	callName := p.CallName(call)

	filteredRaw := filteredCoverage(info.cover.Serialize(), job.fuzzer.Config.DebugFilters)
	if len(filteredRaw) > 0 {
		job.info.Logf("handle call #%d [%s] with flagged coverage: %s", call, callName, signal.RawPreview(filteredRaw))
	}

	if !job.fuzzer.Config.NewInputFilter(callName) {
		return
	}
	// Reset the FromFPCovOrigin tag; don't propagate it into the children processes.
	// Instead, tag the children as FromFPCovOrigin if during this triage
	// the individual call was kept due to funcPointerCoverage only.
	smashJobQueue := job.fuzzer.smashQueue
	if fPCovOrigin {
		smashJobQueue = job.fuzzer.fPCovSmashQueue
	}
	if job.flags&ProgSmashed == 0 {
		job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
			exec: smashJobQueue,
			p:    p.Clone(),
			info: &JobInfo{
				Name:            p.String(),
				Type:            JobSmash,
				Calls:           []string{p.CallName(call)},
				ProgId:          job.info.ProgId,
				FromFPCovOrigin: fPCovOrigin,
			},
		})
		if job.fuzzer.Config.Comparisons && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec: smashJobQueue,
				p:    p.Clone(),
				call: call,
				info: &JobInfo{
					Name:            p.String(),
					Type:            JobHints,
					Calls:           []string{p.CallName(call)},
					ProgId:          job.info.ProgId,
					FromFPCovOrigin: fPCovOrigin,
				},
			})
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: smashJobQueue,
				p:    p.Clone(),
				call: call,
				info: &JobInfo{
					Name:            p.String(),
					Type:            "fault-injection",
					Calls:           []string{p.CallName(call)},
					ProgId:          job.info.ProgId,
					FromFPCovOrigin: fPCovOrigin,
				},
			})
		}
	}
	job.info.Logf("added new input for #%d [%s] to the corpus with program:\n%s", call, callName, p.Serialize())
	job.info.Logf("total cover for call #%d [%s]:\n%s", call, callName, signal.RawPreview(info.cover.Serialize()))
	input := corpus.NewInput{
		Prog:             p,
		Call:             call,
		Signal:           info.stableSignal,
		Cover:            info.cover.Serialize(),
		RawCover:         info.rawCover,
		FuncPointerCover: info.stableFuncPointerCover,
	}
	newPCs := job.fuzzer.Config.Corpus.Save(input)
	if len(newPCs) > 0 {
		go job.fuzzer.updateCoveredFunctions(newPCs)
	}
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	job.info.Logf("deflake started")

	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}
	prevTotalNewSignal := 0
	prevTotalNewFPCover := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		totalNewFPCover := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
			totalNewFPCover += info.newFuncPointerCover.Len()
		}
		shouldStop := job.stopDeflake(run, needRuns,
			prevTotalNewSignal == totalNewSignal,
			prevTotalNewFPCover == totalNewFPCover)
		if shouldStop == 0 {
			break
		}
		prevTotalNewSignal = totalNewSignal
		prevTotalNewFPCover = totalNewFPCover
		nextRequest := &queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}
		if shouldStop == 2 {
			nextRequest.FromFPCovOrigin = true
		}
		result := exec(nextRequest, progInTriage)
		if result.Stop() {
			return true
		}
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			if len(filteredCoverage(res.Cover, job.fuzzer.Config.DebugFilters)) > 0 {
				job.info.Logf("call #%d [%s] triggered flagged coverage during deflake", call, job.p.CallName(call))
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			// Repeat most of the existing signal logic, but with FuncPointerCover
			newFuncPointerCover, _ := job.fuzzer.Cover.addRawFuncPointerCover(res.FuncStores)
			info.newFuncPointerCover.Merge(newFuncPointerCover)
			thisFuncPointerCover, _ := cover.FPCoverFromRaw(res.FuncStores)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
				// Similar as with signal, store in position run the cumulative intersection
				// of functionPointerCovers 0 to run
				fPCoverIntersect, _ := info.funcPointerCovers[j-1].Intersection(thisFuncPointerCover)
				info.funcPointerCovers[j].Merge(fPCoverIntersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]

		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		info.stableFuncPointerCover = info.funcPointerCovers[needRuns-1]
		newStableFuncPointerCover, _ := info.newFuncPointerCover.Intersection(info.stableFuncPointerCover)
		info.newStableFuncPointerCover = newStableFuncPointerCover
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			info.newStableSignal.SignalPreview())

		newStableFilteredSignal := filteredCoverage(info.newStableSignal.ToRaw(), job.fuzzer.Config.DebugFilters)
		stableFilteredSignal := filteredCoverage(info.stableSignal.ToRaw(), job.fuzzer.Config.DebugFilters)
		job.info.Logf("call #%d [%s]: |stable stored function pointers|=%d, |new stable stored function pointers|=%d%s",
			call, job.p.CallName(call), info.stableFuncPointerCover.Len(), info.newStableFuncPointerCover.Len(),
			info.newStableFuncPointerCover.Preview())

		if len(stableFilteredSignal) > 0 {
			job.info.Logf("call #%d [%s]: |stable filtered signal|=%d, |new stable filtered signal|=%d%s",
				call, job.p.CallName(call), len(stableFilteredSignal), len(newStableFilteredSignal), signal.RawPreview(newStableFilteredSignal))
		}
	}
	return false
}

// choose whether deflake requires another exec.
// Returns:
//
//		0 --> false
//		1 --> true, because of signal and possibly FPCov
//	 2 --> true, because of FPCov exclusively
func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool, noNewFPCover bool) int {
	if job.fuzzer.Config.Snapshot {
		if run >= needRuns+1 {
			return 0
		}
		return 1
	}
	haveSignal := true
	haveFPCover := true
	// all existing logic for signal is blindly followed by newFPCover
	for _, call := range job.calls {
		if !call.newSignal.IntersectsWith(call.signals[needRuns-1]) {
			haveSignal = false
		}
		intersectsFpCov, _ := call.newFuncPointerCover.IntersectsWith(call.funcPointerCovers[needRuns-1])
		if !intersectsFpCov {
			haveFPCover = false
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return 0
		}
		noChanceSignal := true
		noChanceFPCov := true
		runsLeft := deflakeMaxRuns - run
		for _, call := range job.calls {
			if runsLeft >= needRuns {
				noChanceFPCov = false
				noChanceSignal = false
			} else {
				if call.newSignal.IntersectsWith(call.signals[needRuns-runsLeft-1]) {
					noChanceSignal = false
				}
				if intersects, _ := call.newFuncPointerCover.IntersectsWith(call.funcPointerCovers[needRuns-runsLeft-1]); intersects {
					noChanceFPCov = false
				}
			}
		}
		// stop if both criteria finished or one finished and the other one has no chance.
		if haveSignal && haveFPCover || noChanceSignal && noChanceFPCov ||
			haveFPCover && noChanceSignal || haveSignal && noChanceFPCov {
			return 0
		}
		// continue due to Signal if there's chance to get the stableSignal
		if !noChanceSignal && !haveSignal {
			return 1
		}
		// continue specifically due to FPCov if there's a chance to get stableFPCov
		// and Signal is telling us to stop.
		if !noChanceFPCov && (haveSignal || noChanceSignal) {
			return 2
		}
		panic(fmt.Sprintf(
			"unreachable in stopDeflake.\nhaveSignal: %t haveFPCover: %t, noChanceSignal: %t, noChanceFPCov: %t",
			haveSignal, haveFPCover, noChanceSignal, noChanceFPCov))
	} else {
		if run >= deflakeTotalCorpusRuns ||
			noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) ||
			noNewFPCover && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveFPCover) {
			// For programs from the corpus we use a different condition b/c we want to extract
			// as much flaky signal from them as possible. They have large coverage and run
			// in the beginning, gathering flaky signal on them allows to grow max signal quickly
			// and avoid lots of useless executions later. Any bit of flaky coverage discovered
			// later will lead to triage, and if we are unlucky to conclude it's stable also
			// to minimization+smash+hints (potentially thousands of runs).
			// So we run them at least 5 times, or while we are still getting any new signal.
			return 0
		}
		// we don't really care about why we're repeating this request during corpus triage
		return 1
	}
	panic("unreachable in stopDeflake during triage")
}

// minimize tries to preserve both newStableSignal and newStableFuncPointerCover.
// Returns a boolean value indicating if the result was unified and an array of minimized progs and call indexes.
// position 0 --> Signal.
// position 1 --> FuncPointerCover.
//
//	Returns (nil, 0) if test execution crashed on the last minimization step for that criteria.
//	Returns (nil, 0) if stableCoverage is empty for that criteria.
//	Returns (p, call) with the last pair that preserved the stableCoverage (the original pair if no minimization step succeeded).
func (job *triageJob) minimize(call int, info *triageCall) ([2]*prog.Prog, [2]int, bool) {
	var skipFuncPointer bool
	var skipSignal bool
	var lastProgSignal *prog.Prog
	var lastProgFuncPointer *prog.Prog
	var lastCallSignal int
	var lastCallFuncPointer int
	didSplit := false
	if info.newStableSignal.Empty() {
		job.info.Logf("call #%d [%s]: skip minimize of empty new stable signal", call, job.p.CallName(call))
		skipSignal = true
	}
	if info.newStableFuncPointerCover.Empty() {
		job.info.Logf("call #%d [%s]: skip minimize of empty new stable stored function pointers", call, job.p.CallName(call))
		skipFuncPointer = true
	}
	if skipFuncPointer && skipSignal {
		return [2]*prog.Prog{nil, nil}, [2]int{0, 0}, false
	}
	job.info.Logf("call #%d [%s]: minimize started", call, job.p.CallName(call))
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}

	funcPointerSuccessLambda := func(mergedFPointerCover *cover.FuncPointerCover, p1 *prog.Prog, call1 int, thisFPointerCover *cover.FuncPointerCover) bool {
		mergedFPointerCover.Merge(*thisFPointerCover)
		fPCoverIntersection, _ := info.newStableFuncPointerCover.Intersection(*mergedFPointerCover)
		if fPCoverIntersection.Len() == info.newStableFuncPointerCover.Len() {
			job.info.Logf("call #%d [%s]: minimization step (funcPointerCover) success (|calls| = %d)",
				call, job.p.CallName(call), len(p1.Calls))
			lastCallFuncPointer = call1
			lastProgFuncPointer = p1
			return true
		}
		return false
	}

	signalSuccessLambda := func(mergedSignal *signal.Signal, p1 *prog.Prog, call1 int, thisSignal *signal.Signal) bool {
		mergedSignal.Merge(*thisSignal)
		if info.newStableSignal.Intersection(*mergedSignal).Len() == info.newStableSignal.Len() {
			job.info.Logf("call #%d [%s]: minimization step (signal) success (|calls| = %d)",
				call, job.p.CallName(call), len(p1.Calls))
			lastCallSignal = call1
			lastProgSignal = p1
			return true
		}
		return false
	}
	// declare the inner closure to allow for recursion
	var minimizeFactory func(bool, bool, *prog.Prog, int)
	// now define its implementation
	minimizeFactory = func(doSignal bool, doFuncPointer bool, initProg *prog.Prog, initCall int) {
		if !doSignal && !doFuncPointer {
			panic("At least one of the coverage criteria must be enabled!")
		}
		stop := false
		mode := prog.MinimizeCorpus
		if job.fuzzer.Config.PatchTest {
			mode = prog.MinimizeCallsOnly
		}
		// This is technically only necessary the first time this function is called
		if doSignal {
			lastCallSignal = initCall
			lastProgSignal = initProg
		}
		if doFuncPointer {
			lastCallFuncPointer = initCall
			lastProgFuncPointer = initProg
		}
		minimizationStepJudge := func(p1 *prog.Prog, call1 int) bool {
			if stop {
				return false
			}
			var mergedSignal signal.Signal
			var mergedFPointerCover cover.FuncPointerCover
			var successSignal bool
			var successFuncPointer bool

			for range minimizeAttempts {
				nextRequest := queue.Request{
					Prog:            p1,
					ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
					ReturnAllSignal: []int{call1},
					Stat:            job.fuzzer.statExecMinimize,
				}
				if doFuncPointer && !doSignal {
					nextRequest.FromFPCovOrigin = true
				}
				result := job.execute(&nextRequest, 0)
				if result.Stop() {
					stop = true
					return false
				}
				if !reexecutionSuccess(result.Info, info.errno, call1) {
					// The call was not executed or failed.
					continue
				}
				thisSignal, thisFPointerCover := job.getSignalAndCover(p1, result.Info, call1)
				if doSignal {
					successSignal = successSignal || signalSuccessLambda(&mergedSignal, p1, call1, &thisSignal)
				}
				if doFuncPointer {
					successFuncPointer = successFuncPointer || funcPointerSuccessLambda(&mergedFPointerCover, p1, call1, &thisFPointerCover)
				}
				if doSignal && doFuncPointer {
					if successSignal && successFuncPointer {
						return true
					}
				} else if (doSignal && successSignal) || (doFuncPointer && successFuncPointer) {
					return true
				}
			}
			// if signal and funcPointer disagree, we have to split the process.
			if doSignal && doFuncPointer {
				if !successSignal && !successFuncPointer {
					job.info.Logf("call #%d [%s]: minimization step failure", call, job.p.CallName(call))
					return false
				}
				// else, one of them was true and not the other.
				// We want to split the minimization process in two.
				//
				// Spawn two children that will minimize independently and wait for each of them.
				// When the children are done, we must kill this onging minimization process that split in two.
				// We can do so by knowing this process is wrapped into a goroutine and exiting with runtime.Goexit.
				var wg sync.WaitGroup
				wg.Add(2)
				job.info.Logf("call #%d [%s]: minimization step splitted", call, job.p.CallName(call))
				didSplit = true
				go func() {
					//signal
					defer wg.Done()
					// This will write to lastProgSignal, lastCallSignal
					minimizeFactory(true, false, lastProgSignal, lastCallSignal)
				}()
				go func() {
					//funcPointerCover
					defer wg.Done()
					// This will write to lastProgFuncPointer, lastCallFuncPointer
					minimizeFactory(false, true, lastProgFuncPointer, lastCallFuncPointer)
				}()
				wg.Wait()
				runtime.Goexit()
			}
			//else: only one of signal and funcPointerCover was enabled, and the minimization step was unsuccesful
			job.info.Logf("call #%d [%s]: minimization step failure", call, job.p.CallName(call))
			return false
		}
		// prog.Minimize returns minimized (p, call) when minimizationStepJudge stops returning true.
		// We ignore this and instead save to lastProg and lastCall as part of the SuccessLambdas ourselves.
		// This REQUIRES that prog.Minimize incrementally updates the (p, call) pair each time the lambda returns true.
		prog.Minimize(initProg, initCall, mode, minimizationStepJudge)
		if stop {
			// previously this meant returning nil, 0.
			// here we instead override the result to be nil, 0 for the criteria we're currently minimizing
			if doFuncPointer {
				lastCallFuncPointer = 0
				lastProgFuncPointer = nil
			}
			if doSignal {
				lastCallSignal = 0
				lastProgSignal = nil
			}
		}
	}
	var wgOuter sync.WaitGroup
	wgOuter.Add(1)
	go func() {
		defer wgOuter.Done()
		// This will write to lastProgFuncPointer, lastCallFuncPointer, lastProgSignal, lastCallSignal
		minimizeFactory(!skipSignal, !skipFuncPointer, job.p, call)
	}()
	wgOuter.Wait()
	return [2]*prog.Prog{lastProgSignal, lastProgFuncPointer}, [2]int{lastCallSignal, lastCallFuncPointer}, didSplit
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func (job *triageJob) getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) (signal.Signal, cover.FuncPointerCover) {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil, nil
	}
	resSignal := signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
	resFPCover, _ := cover.FPCoverFromRaw(inf.FuncStores)
	return resSignal, resFPCover
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	info *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	job.info.Logf("smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	const iters = 25
	rnd := fuzzer.rand()
	for range iters {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:            p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:            fuzzer.statExecSmash,
			FromFPCovOrigin: job.info.FromFPCovOrigin,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if job.info.FromFPCovOrigin {
			job.info.ExecBecauseFPCov.Add(1)
		}
	}
}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		job.info.Logf("injecting fault into call #%d [%s], step %v",
			job.call, job.p.CallName(job.call), nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

func (job *faultInjectionJob) getInfo() *JobInfo {
	return job.info
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	var comps prog.CompMap
	for i := range 3 {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncTimePairArray struct {
	mu  sync.RWMutex
	arr [][2]time.Time
}

func (stpa *syncTimePairArray) AppendAtomic(start time.Time, end time.Time) {
	stpa.mu.Lock()
	defer stpa.mu.Unlock()
	stpa.arr = append(stpa.arr, [2]time.Time{start, end})
}

func (stpa *syncTimePairArray) AsJson() ([]byte, error) {
	stpa.mu.RLock()
	defer stpa.mu.RUnlock()
	// array where each position has 2 maps from string to string
	mapFormatted := []map[string]string{}
	for _, startEnd := range stpa.arr {
		entry := map[string]string{}
		entry["TimeStart"] = startEnd[0].Format(time.DateTime)
		entry["TimeEnd"] = startEnd[1].Format(time.DateTime)
		entry["DurationSeconds"] = fmt.Sprintf("%f", startEnd[1].Sub(startEnd[0]).Seconds())
		mapFormatted = append(mapFormatted, entry)
	}
	return json.Marshal(mapFormatted)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (ji *JobInfo) Logf(logFmt string, args ...any) {
	ji.mu.Lock()
	defer ji.mu.Unlock()
	fmt.Fprintf(&ji.buf, "%s [%s-%s] [prog-%s]: ", time.Now().Format(time.DateTime), ji.Type, ji.ID(), ji.ProgId)
	if ji.FromFPCovOrigin {
		fmt.Fprintf(&ji.buf, "[fpcov-orig] ")
	}
	fmt.Fprintf(&ji.buf, logFmt, args...)
	ji.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}
