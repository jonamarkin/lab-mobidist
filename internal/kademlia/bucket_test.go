package kademlia

import (
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

// fakePinger answers pings from a table of who is alive and counts them.
type fakePinger struct {
	mu    sync.Mutex
	dead  map[KademliaID]bool
	pings atomic.Int64
	gate  chan struct{} // if non-nil, each ping waits for a value from it
}

func newFakePinger() *fakePinger { return &fakePinger{dead: make(map[KademliaID]bool)} }

func (p *fakePinger) ping(c Contact) bool {
	p.pings.Add(1)
	if p.gate != nil {
		<-p.gate
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.dead[c.ID]
}

func (p *fakePinger) kill(id KademliaID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dead[id] = true
}

// contactInBucket returns a contact that falls in bucket i of me's table.
func contactInBucket(me KademliaID, i int, r *rand.Rand) Contact {
	return NewContact(RandomIDInBucket(me, i, r), testAddr(r.IntN(1<<24)))
}

func ids(cs []Contact) []KademliaID {
	out := make([]KademliaID, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

func TestBucketPlacement(t *testing.T) {
	r := rand.New(rand.NewPCG(20, 20))
	me := testContact(0)
	rt := NewBucketRoutingTable(me, 10, newFakePinger().ping)
	for _, i := range []int{0, 7, 128, 255} {
		rt.AddContact(contactInBucket(me.ID, i, r))
	}
	rt.AddContact(me) // ignored
	for i, b := range rt.Buckets() {
		want := 0
		if i == 0 || i == 7 || i == 128 || i == 255 {
			want = 1
		}
		if len(b) != want {
			t.Errorf("bucket %d has %d contacts, want %d", i, len(b), want)
		}
	}
}

// Re-adding a known contact moves it to the tail (most recently seen).
func TestBucketMoveToTail(t *testing.T) {
	r := rand.New(rand.NewPCG(21, 21))
	me := testContact(0)
	rt := NewBucketRoutingTable(me, 10, newFakePinger().ping)
	a, b, c := contactInBucket(me.ID, 200, r), contactInBucket(me.ID, 200, r), contactInBucket(me.ID, 200, r)
	rt.AddContact(a)
	rt.AddContact(b)
	rt.AddContact(c)
	rt.AddContact(a)

	if got, want := ids(rt.Buckets()[200]), ids([]Contact{b, c, a}); !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}

// fullBucket returns a table whose bucket 200 holds k contacts.
func fullBucket(t *testing.T, k int, p *fakePinger) (*BucketRoutingTable, []Contact, *rand.Rand) {
	t.Helper()
	r := rand.New(rand.NewPCG(22, 22))
	me := testContact(0)
	rt := NewBucketRoutingTable(me, k, p.ping)
	var cs []Contact
	for range k {
		c := contactInBucket(me.ID, 200, r)
		cs = append(cs, c)
		rt.AddContact(c)
	}
	return rt, cs, r
}

// Full bucket, oldest contact alive: keep it (moved to the tail), discard
// the newcomer. This is the paper's preference for long-lived nodes.
func TestBucketFullOldestAlive(t *testing.T) {
	p := newFakePinger()
	rt, cs, r := fullBucket(t, 3, p)
	newcomer := contactInBucket(rt.me.ID, 200, r)
	rt.AddContact(newcomer)
	rt.checks.Wait()

	want := ids([]Contact{cs[1], cs[2], cs[0]})
	if got := ids(rt.Buckets()[200]); !slices.Equal(got, want) {
		t.Errorf("bucket %v, want %v", got, want)
	}
	if p.pings.Load() != 1 {
		t.Errorf("%d pings, want 1", p.pings.Load())
	}
}

// Full bucket, oldest contact dead: evict it, insert the newcomer at the tail.
func TestBucketFullOldestDead(t *testing.T) {
	p := newFakePinger()
	rt, cs, r := fullBucket(t, 3, p)
	p.kill(cs[0].ID)
	newcomer := contactInBucket(rt.me.ID, 200, r)
	rt.AddContact(newcomer)
	rt.checks.Wait()

	want := ids([]Contact{cs[1], cs[2], newcomer})
	if got := ids(rt.Buckets()[200]); !slices.Equal(got, want) {
		t.Errorf("bucket %v, want %v", got, want)
	}
}

// While a check runs, further newcomers for the same bucket are discarded
// without another ping; other buckets are unaffected.
func TestBucketOneCheckAtATime(t *testing.T) {
	p := newFakePinger()
	p.gate = make(chan struct{})
	rt, cs, r := fullBucket(t, 3, p)
	p.kill(cs[0].ID)

	first, second := contactInBucket(rt.me.ID, 200, r), contactInBucket(rt.me.ID, 200, r)
	rt.AddContact(first)  // starts a check, which waits at the gate
	rt.AddContact(second) // discarded: a check is already running
	other := contactInBucket(rt.me.ID, 100, r)
	rt.AddContact(other) // a different bucket: added directly

	p.gate <- struct{}{} // let the ping finish
	rt.checks.Wait()

	if got := rt.Buckets()[200]; slices.Contains(got, second) || !slices.Contains(got, first) {
		t.Errorf("bucket 200 = %v", got)
	}
	if !slices.Contains(rt.Buckets()[100], other) || p.pings.Load() != 1 {
		t.Errorf("bucket 100 = %v, pings = %d", rt.Buckets()[100], p.pings.Load())
	}
}

// If the oldest contact was removed (or re-added) while it was being
// pinged, the check still leaves a consistent bucket.
func TestBucketChangedDuringCheck(t *testing.T) {
	p := newFakePinger()
	p.gate = make(chan struct{})
	rt, cs, r := fullBucket(t, 3, p)
	p.kill(cs[0].ID)

	newcomer := contactInBucket(rt.me.ID, 200, r)
	rt.AddContact(newcomer)
	rt.RemoveContact(cs[0].ID) // removed by someone else meanwhile
	rt.AddContact(newcomer)    // and the newcomer got the free slot directly
	p.gate <- struct{}{}
	rt.checks.Wait()

	if got := rt.Buckets()[200]; len(got) != 3 || !slices.Contains(got, newcomer) {
		t.Errorf("bucket 200 = %v", got)
	}
}

func TestBucketRemoveContact(t *testing.T) {
	r := rand.New(rand.NewPCG(23, 23))
	me := testContact(0)
	rt := NewBucketRoutingTable(me, 10, newFakePinger().ping)
	a := contactInBucket(me.ID, 50, r)
	rt.AddContact(a)
	rt.RemoveContact(a.ID)
	rt.RemoveContact(a.ID)  // unknown: no effect
	rt.RemoveContact(me.ID) // ourselves: no effect
	if len(rt.Buckets()[50]) != 0 {
		t.Error("contact not removed")
	}
}

// No bucket ever holds more than k contacts, and FindClosestContacts is
// correct with respect to what the table holds.
func TestBucketTableMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewPCG(24, 24))
	me := testContact(0)
	rt := NewBucketRoutingTable(me, 10, newFakePinger().ping)
	for i := 1; i <= 2000; i++ {
		rt.AddContact(testContact(i))
	}
	rt.checks.Wait()

	var held []Contact
	for i, b := range rt.Buckets() {
		if len(b) > 10 {
			t.Errorf("bucket %d holds %d contacts", i, len(b))
		}
		held = append(held, b...)
	}
	for range 50 {
		target := NewRandomKademliaID(r)
		if got, want := rt.FindClosestContacts(target, 10), bruteForceClosest(held, target, 10); !slices.Equal(got, want) {
			t.Fatalf("got %v\nwant %v", got, want)
		}
	}
	if rt.FindClosestContacts(me.ID, 0) != nil {
		t.Error("count 0 returned contacts")
	}
}

// Run with -race.
func TestBucketTableConcurrent(t *testing.T) {
	p := newFakePinger()
	rt := NewBucketRoutingTable(testContact(0), 3, p.ping)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 50 {
				c := testContact(1 + g*50 + i)
				rt.AddContact(c)
				rt.FindClosestContacts(c.ID, 10)
				if i%3 == 0 {
					rt.RemoveContact(c.ID)
				}
			}
		})
	}
	wg.Wait()
	rt.checks.Wait()
}
