package kademlia

import (
	"net/netip"
	"strings"
	"testing"
)

// testAddr returns a distinct address for each i (10.x.y.z:4000).
func testAddr(i int) netip.AddrPort {
	ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	return netip.AddrPortFrom(ip, 4000)
}

// testContact returns the contact a real node at testAddr(i) would have.
func testContact(i int) Contact {
	addr := testAddr(i)
	return NewContact(NewNodeID(addr), addr)
}

func TestContactString(t *testing.T) {
	id, _ := NewKademliaID("3fa2" + strings.Repeat("0", 56) + "09bc")
	c := NewContact(id, netip.MustParseAddrPort("10.0.0.1:8000"))
	if got := c.String(); got != "3fa2…09bc@10.0.0.1:8000" {
		t.Errorf("String() = %q", got)
	}
}

// A 4-bit example: key 1010 and five nodes at distances 15, 4, 1, 9, 2.
func TestSortContactsByDistance(t *testing.T) {
	target := idLow(0b1010)
	var contacts []Contact
	for _, b := range []byte{0b0101, 0b1110, 0b1011, 0b0011, 0b1000} {
		contacts = append(contacts, NewContact(idLow(b), testAddr(int(b))))
	}
	SortContactsByDistance(contacts, target)

	want := []byte{0b1011, 0b1000, 0b1110, 0b0011, 0b0101} // distances 1, 2, 4, 9, 15
	for i, c := range contacts {
		if c.ID != idLow(want[i]) {
			t.Errorf("position %d: got %v, want %04b", i, c.ID.Short(), want[i])
		}
	}
}
