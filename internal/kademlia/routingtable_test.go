package kademlia

import (
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
)

// bruteForceClosest is the test oracle: the count closest contacts to
// target, computed independently of SortContactsByDistance by comparing
// distances as big integers.
func bruteForceClosest(all []Contact, target KademliaID, count int) []Contact {
	sorted := slices.Clone(all)
	slices.SortFunc(sorted, func(a, b Contact) int {
		return toBig(a.ID.CalcDistance(target)).Cmp(toBig(b.ID.CalcDistance(target)))
	})
	return sorted[:min(count, len(sorted))]
}

func TestFlatRoutingTableMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	me := testContact(0)
	rt := NewFlatRoutingTable(me)

	var all []Contact
	for i := 1; i <= 1000; i++ {
		c := testContact(i)
		all = append(all, c)
		rt.AddContact(c)
	}

	for range 50 {
		target := NewRandomKademliaID(r)
		got := rt.FindClosestContacts(target, 10)
		want := bruteForceClosest(all, target, 10)
		if !slices.Equal(got, want) {
			t.Fatalf("target %v:\n got  %v\n want %v", target.Short(), got, want)
		}
	}
}

// B is closer to the target than A although A's bucket is nearer the
// target's bucket. A search that walks buckets outward from the target's
// bucket and stops once it has enough contacts (as the course's starter
// code did) returns A.
func TestClosestContactsAcrossBuckets(t *testing.T) {
	var meID, aID, bID, target KademliaID
	aID[0] = 0x80    // 1000…
	bID[0] = 0x10    // 0001…
	target[0] = 0x40 // 0100…  d(A)=c0…, d(B)=50…, so B is closer

	rt := NewFlatRoutingTable(NewContact(meID, testAddr(0)))
	a, b := NewContact(aID, testAddr(1)), NewContact(bID, testAddr(2))
	rt.AddContact(a)
	rt.AddContact(b)

	got := rt.FindClosestContacts(target, 1)
	if len(got) != 1 || got[0] != b {
		t.Errorf("got %v, want [%v]", got, b)
	}
}

func TestFlatRoutingTableIgnoresSelf(t *testing.T) {
	me := testContact(0)
	rt := NewFlatRoutingTable(me)
	rt.AddContact(me)
	if got := rt.FindClosestContacts(me.ID, 10); len(got) != 0 {
		t.Errorf("table contains itself: %v", got)
	}
}

func TestFlatRoutingTableNoDuplicates(t *testing.T) {
	rt := NewFlatRoutingTable(testContact(0))
	c := testContact(1)
	rt.AddContact(c)
	rt.AddContact(c)
	if got := rt.FindClosestContacts(c.ID, 10); len(got) != 1 {
		t.Errorf("got %d contacts, want 1", len(got))
	}
}

func TestFlatRoutingTableRemoveContact(t *testing.T) {
	rt := NewFlatRoutingTable(testContact(0))
	a, b := testContact(1), testContact(2)
	rt.AddContact(a)
	rt.AddContact(b)
	rt.RemoveContact(a.ID)
	rt.RemoveContact(testContact(3).ID) // unknown: no effect

	got := rt.FindClosestContacts(a.ID, 10)
	if len(got) != 1 || got[0] != b {
		t.Errorf("got %v, want [%v]", got, b)
	}
}

func TestFlatRoutingTableCounts(t *testing.T) {
	rt := NewFlatRoutingTable(testContact(0))
	for i := 1; i <= 3; i++ {
		rt.AddContact(testContact(i))
	}
	target := testContact(1).ID
	if got := rt.FindClosestContacts(target, 10); len(got) != 3 {
		t.Errorf("count > size: got %d contacts, want 3", len(got))
	}
	if got := rt.FindClosestContacts(target, 2); len(got) != 2 {
		t.Errorf("count = 2: got %d contacts", len(got))
	}
	if got := rt.FindClosestContacts(target, 0); len(got) != 0 {
		t.Errorf("count = 0: got %d contacts", len(got))
	}
}

// The caller owns the returned slice: changing it must not change the table.
func TestFlatRoutingTableReturnsCopy(t *testing.T) {
	rt := NewFlatRoutingTable(testContact(0))
	c := testContact(1)
	rt.AddContact(c)

	got := rt.FindClosestContacts(c.ID, 1)
	got[0] = testContact(2)

	if again := rt.FindClosestContacts(c.ID, 1); again[0] != c {
		t.Errorf("table changed through returned slice: %v", again)
	}
}

// Run with -race: concurrent writers and readers must not race. The goal
// is overlapping access for the race detector, not load, so it stays small.
func TestFlatRoutingTableConcurrent(t *testing.T) {
	rt := NewFlatRoutingTable(testContact(0))
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
}
