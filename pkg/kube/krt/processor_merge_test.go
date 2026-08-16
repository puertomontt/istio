// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package krt

import (
	"fmt"
	"sync"
	"testing"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
)

func namedEvent(name string) Event[Named] {
	n := Named{Namespace: "ns", Name: name}
	return Event[Named]{New: &n, Event: controllers.EventAdd}
}

// batchRecorder captures the batches a listener delivers, and can be held inside the handler so
// a backlog builds up behind it.
type batchRecorder struct {
	mu      sync.Mutex
	batches [][]string
	release chan struct{}
}

func newBatchRecorder() *batchRecorder {
	return &batchRecorder{release: make(chan struct{})}
}

func (r *batchRecorder) handle(events []Event[Named]) {
	<-r.release
	names := make([]string, 0, len(events))
	for _, e := range events {
		names = append(names, e.Latest().Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, names)
}

func (r *batchRecorder) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

func (r *batchRecorder) flatten() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{}
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

// TestProcessorListenerMergesBacklog is the point of the change: while the handler is busy, a
// burst of sends collapses into few batches instead of being delivered one at a time.
// Collections dedupe changed keys within a batch but not across batches, so the batch count is
// what decides how many times a dependent object gets recomputed.
func TestProcessorListenerMergesBacklog(t *testing.T) {
	stop := test.NewStop(t)
	r := newBatchRecorder()
	l := newProcessListener(r.handle, alwaysSynced{}, stop)
	go l.run()
	go l.pop()

	const burst = 100
	want := make([]string, 0, burst+1)

	// The first send occupies the handler, which then blocks on release.
	l.send([]Event[Named]{namedEvent("first")}, false)
	want = append(want, "first")
	// Everything after this piles up behind the blocked handler.
	for i := range burst {
		name := fmt.Sprintf("burst-%d", i)
		l.send([]Event[Named]{namedEvent(name)}, false)
		want = append(want, name)
	}

	close(r.release)
	assert.EventuallyEqual(t, r.flatten, want)

	// Every event still arrives, in order, but in far fewer batches than sends. The exact count
	// is timing dependent -- pop may dispatch a few before the backlog forms -- so assert the
	// property rather than a number.
	if got := r.batchCount(); got > burst/4 {
		t.Fatalf("expected backlog to merge into few batches, got %d for %d sends", got, burst+1)
	}
	t.Logf("delivered %d events in %d batches", len(want), r.batchCount())
}

// TestProcessorListenerMergePreservesOrder guards the property the merge must not break: events
// must stay in send order, since a reordered add/delete for one key would invert the outcome.
func TestProcessorListenerMergePreservesOrder(t *testing.T) {
	stop := test.NewStop(t)
	r := newBatchRecorder()
	l := newProcessListener(r.handle, alwaysSynced{}, stop)
	go l.run()
	go l.pop()

	want := []string{"blocker"}
	l.send([]Event[Named]{namedEvent("blocker")}, false)
	// Multi-event sends, to check we concatenate rather than interleave.
	for i := range 20 {
		a, b := fmt.Sprintf("%d-a", i), fmt.Sprintf("%d-b", i)
		l.send([]Event[Named]{namedEvent(a), namedEvent(b)}, false)
		want = append(want, a, b)
	}

	close(r.release)
	assert.EventuallyEqual(t, r.flatten, want)
}

// TestProcessorListenerMergeIsNotAQuietPeriod pins that merging never withholds events waiting
// for more to arrive. Unlike a debounce, it only combines what has already piled up, so an idle
// handler still sees one batch per send and latency is unchanged.
func TestProcessorListenerMergeIsNotAQuietPeriod(t *testing.T) {
	stop := test.NewStop(t)
	r := newBatchRecorder()
	close(r.release) // never block
	l := newProcessListener(r.handle, alwaysSynced{}, stop)
	go l.run()
	go l.pop()

	for i := range 5 {
		l.send([]Event[Named]{namedEvent(fmt.Sprintf("e-%d", i))}, false)
		// Wait for delivery before the next send, so no backlog can form.
		want := i + 1
		assert.EventuallyEqual(t, func() int { return len(r.flatten()) }, want)
	}
	assert.Equal(t, r.batchCount(), 5, "an idle handler must see one batch per send")
}

// TestEventSetMergeRespectsInitialList checks the syncTracker invariant. run() calls Finished
// only for initial-list sets, so an initial set must never merge with a non-initial one, or the
// counter unbalances and HasSynced reports the wrong thing.
func TestEventSetMergeRespectsInitialList(t *testing.T) {
	initial := eventSet[Named]{event: []Event[Named]{namedEvent("a")}, isInInitialList: true}
	later := eventSet[Named]{event: []Event[Named]{namedEvent("b")}, isInInitialList: false}

	if _, ok := initial.merge(later); ok {
		t.Fatal("initial-list set must not merge with a non-initial one")
	}
	if _, ok := later.merge(initial); ok {
		t.Fatal("non-initial set must not merge with an initial-list one")
	}

	merged, ok := initial.merge(eventSet[Named]{event: []Event[Named]{namedEvent("c")}, isInInitialList: true})
	assert.Equal(t, ok, true)
	assert.Equal(t, len(merged.event), 2)
	assert.Equal(t, merged.isInInitialList, true, "merged set stays an initial-list set")
}

// TestEventSetMergeDoesNotAliasCallerSlice covers the subtle failure mode: send() takes the
// caller's slice, so the first merge must copy rather than append into its spare capacity.
func TestEventSetMergeDoesNotAliasCallerSlice(t *testing.T) {
	caller := make([]Event[Named], 1, 8) // spare capacity is what makes in-place append unsafe
	caller[0] = namedEvent("a")

	merged, ok := eventSet[Named]{event: caller}.merge(eventSet[Named]{event: []Event[Named]{namedEvent("b")}})
	assert.Equal(t, ok, true)
	assert.Equal(t, len(merged.event), 2)

	// The caller's backing array must be untouched past its own length.
	if got := caller[:2][1].New; got != nil {
		t.Fatalf("merge wrote %v into the caller's backing array", got.Name)
	}
	// Once owned, further merges may reuse the slice.
	again, ok := merged.merge(eventSet[Named]{event: []Event[Named]{namedEvent("c")}})
	assert.Equal(t, ok, true)
	assert.Equal(t, len(again.event), 3)
}

// TestProcessorListenerMergeKeepsSyncedAccurate exercises the tracker end to end: a backlog of
// initial-list events that merge must still drive HasSynced exactly once, after all are handled.
func TestProcessorListenerMergeKeepsSyncedAccurate(t *testing.T) {
	stop := test.NewStop(t)
	hs := newHandlerSet[Named]()
	r := newBatchRecorder()

	initial := []Event[Named]{namedEvent("init")}
	reg := hs.Insert(r.handle, alwaysSynced{}, initial, stop)
	assert.Equal(t, reg.HasSynced(), false, "not synced until the initial list is handled")

	want := []string{"init"}
	for i := range 30 {
		name := fmt.Sprintf("more-%d", i)
		hs.Distribute([]Event[Named]{namedEvent(name)}, true)
		want = append(want, name)
	}

	close(r.release)
	assert.EventuallyEqual(t, r.flatten, want)
	assert.EventuallyEqual(t, reg.HasSynced, true)
}
