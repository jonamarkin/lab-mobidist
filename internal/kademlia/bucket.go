package kademlia

import "slices"

// bucket is one k-bucket: contacts ordered from least recently seen
// (index 0, the head) to most recently seen (the tail). It is a plain
// slice: k is small, so linear scans are cheap. Not safe for concurrent
// use on its own; BucketRoutingTable guards it.
type bucket struct {
	contacts []Contact
}

// indexOf returns the position of the contact with the given ID, or -1.
func (b *bucket) indexOf(id KademliaID) int {
	return slices.IndexFunc(b.contacts, func(c Contact) bool { return c.ID == id })
}

// moveToTail marks the contact at position i as most recently seen.
func (b *bucket) moveToTail(i int) {
	c := b.contacts[i]
	b.contacts = append(slices.Delete(b.contacts, i, i+1), c)
}

// remove deletes the contact at position i.
func (b *bucket) remove(i int) {
	b.contacts = slices.Delete(b.contacts, i, i+1)
}
