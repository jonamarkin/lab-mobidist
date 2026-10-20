package registry

import (
	"context"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// Validator adapts the rules to kademlia.Validator, so that a node can
// hold latest pointers: before storing an update, the node asks it whether
// the new pointer may replace the current one. The fetch function the node
// supplies (a lookup in the DHT) reads the records the node does not have.
type Validator struct {
	Verifier Verifier
	MaxChain int // 0 means DefaultMaxChain
}

// Validate implements kademlia.Validator.
func (v Validator) Validate(ctx context.Context, key kademlia.KademliaID, newValue, current []byte, fetch kademlia.FetchFunc) error {
	rules := &Rules{Verifier: v.Verifier, Fetch: FetchFunc(fetch), MaxChain: v.MaxChain}
	_, err := rules.ValidateUpdate(ctx, key, newValue, current)
	return err
}

var _ kademlia.Validator = Validator{}
