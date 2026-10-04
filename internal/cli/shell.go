// Package cli is the interactive shell used to control a node, plus the
// helpers the node binary needs at startup (address resolution, joining).
package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// Shell reads commands line by line and runs them against one node.
type Shell struct {
	node    *kademlia.Kademlia
	out     io.Writer
	timeout time.Duration // per command
}

// NewShell returns a shell for node that writes its output to out.
func NewShell(node *kademlia.Kademlia, out io.Writer) *Shell {
	return &Shell{node: node, out: out, timeout: 30 * time.Second}
}

const help = `commands:
  ping IP:PORT | HOST:PORT | ID-PREFIX   ping a node, print the round-trip time
  put FILENAME                           store a file's contents; prints the key
  puttext TEXT...                        store the given text; prints the key
  get KEY [FILENAME]                     fetch a value; save it to FILENAME or print it
  lookup ID-PREFIX                       find the k nodes closest to an ID
                                         (a prefix is padded with zeros)
  show rt                                print the routing table
  show ds                                print the local data store
  id                                     print this node's ID and address
  help                                   print this help
  exit                                   terminate the node
`

// Run executes commands from in until "exit" or end of input.
func (s *Shell) Run(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	for {
		fmt.Fprint(s.out, "> ")
		if !scanner.Scan() {
			fmt.Fprintln(s.out)
			return scanner.Err()
		}
		if s.Execute(scanner.Text()) {
			return nil
		}
	}
}

// Execute runs one command line and reports whether the shell should exit.
// Errors are printed, not returned: a bad command must not stop the shell.
func (s *Shell) Execute(line string) (exit bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	var err error
	switch cmd, args := fields[0], fields[1:]; cmd {
	case "exit", "quit":
		return true
	case "help":
		fmt.Fprint(s.out, help)
	case "id":
		me := s.node.Me()
		fmt.Fprintf(s.out, "node %s at %s\nfull ID %s\n", me.ID.Short(), me.Address, me.ID)
	case "ping":
		err = s.ping(ctx, args)
	case "put":
		err = s.put(ctx, args)
	case "puttext":
		err = s.store(ctx, []byte(strings.Join(args, " ")))
	case "get":
		err = s.get(ctx, args)
	case "lookup":
		err = s.lookup(ctx, args)
	case "show":
		err = s.show(args)
	default:
		err = fmt.Errorf("unknown command %q (try help)", cmd)
	}
	if err != nil {
		fmt.Fprintln(s.out, "error:", err)
	}
	return false
}

func (s *Shell) ping(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ping IP:PORT | HOST:PORT | ID-PREFIX")
	}
	target := args[0]
	var c kademlia.Contact
	if strings.Contains(target, ":") {
		addr, err := ResolveAddr(target)
		if err != nil {
			return err
		}
		c = kademlia.NewContact(kademlia.NewNodeID(addr), addr)
	} else {
		var err error
		if c, err = s.contactByPrefix(target); err != nil {
			return err
		}
	}
	rtt, err := s.node.Ping(ctx, c.Address)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out, "reply from %s: rtt=%v\n", c, rtt.Round(time.Microsecond))
	return nil
}

// contactByPrefix finds the one routing-table contact whose ID starts
// with the given hex prefix.
func (s *Shell) contactByPrefix(prefix string) (kademlia.Contact, error) {
	prefix = strings.ToLower(prefix)
	if _, err := hex.DecodeString(prefix + strings.Repeat("0", len(prefix)%2)); err != nil {
		return kademlia.Contact{}, fmt.Errorf("%q is not an address or a hex ID prefix", prefix)
	}
	var matches []kademlia.Contact
	for _, c := range s.contacts() {
		if strings.HasPrefix(c.ID.String(), prefix) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return kademlia.Contact{}, fmt.Errorf("no contact with ID prefix %q", prefix)
	case 1:
		return matches[0], nil
	default:
		return kademlia.Contact{}, fmt.Errorf("ID prefix %q is ambiguous (%d contacts)", prefix, len(matches))
	}
}

func (s *Shell) lookup(ctx context.Context, args []string) error {
	if len(args) != 1 || len(args[0]) > 2*kademlia.IDLength {
		return errors.New("usage: lookup ID-PREFIX")
	}
	target, err := kademlia.NewKademliaID(args[0] + strings.Repeat("0", 2*kademlia.IDLength-len(args[0])))
	if err != nil {
		return err
	}
	res, err := s.node.LookupContact(ctx, target)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out, "%d closest to %s (%d probes, %d failed):\n", len(res.Contacts), target.Short(), res.Probes, res.Failed)
	for i, c := range res.Contacts {
		fmt.Fprintf(s.out, "  %2d. %s\n", i+1, c)
	}
	return nil
}

func (s *Shell) put(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: put FILENAME")
	}
	value, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	return s.store(ctx, value)
}

func (s *Shell) store(ctx context.Context, value []byte) error {
	res, err := s.node.Store(ctx, value)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out, "stored %d bytes on %d nodes (%d failed)\nkey %s\n", len(value), len(res.StoredAt), res.Failed, res.Key)
	return nil
}

func (s *Shell) get(ctx context.Context, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: get KEY [FILENAME]")
	}
	key, err := kademlia.NewKademliaID(strings.ToLower(args[0]))
	if err != nil {
		return err
	}
	res, err := s.node.LookupData(ctx, key)
	if err != nil {
		return err
	}
	if len(args) == 2 {
		if err := os.WriteFile(args[1], res.Value, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(s.out, "saved %d bytes to %s\n", len(res.Value), args[1])
	} else {
		fmt.Fprintf(s.out, "%s\n", res.Value)
	}
	fmt.Fprintf(s.out, "received from %s\n", res.From)
	return nil
}

func (s *Shell) show(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "rt":
		return s.showRT()
	case len(args) == 1 && args[0] == "ds":
		return s.showDS()
	}
	return errors.New("usage: show rt | show ds")
}

func (s *Shell) showDS() error {
	ds := s.node.DataStore()
	keys := ds.Keys()
	fmt.Fprintf(s.out, "data store of %s: %d values\n", s.node.Me(), len(keys))
	for _, key := range keys {
		value, _ := ds.Get(key)
		fmt.Fprintf(s.out, "  %s  %8d bytes  %s\n", key.Short(), len(value), preview(value))
	}
	return nil
}

// preview shows the start of a value if it is printable text.
func preview(value []byte) string {
	const max = 32
	text := string(value[:min(len(value), max)])
	for _, r := range text {
		if r < ' ' || r == 0x7f || r == '\uFFFD' {
			return "(binary)"
		}
	}
	if len(value) > max {
		text += "…"
	}
	return fmt.Sprintf("%q", text)
}

func (s *Shell) showRT() error {
	me := s.node.Me()
	rt, ok := s.node.RoutingTable().(*kademlia.BucketRoutingTable)
	if !ok {
		cs := s.contacts()
		fmt.Fprintf(s.out, "flat routing table of %s: %d contacts\n", me, len(cs))
		for _, c := range cs {
			fmt.Fprintf(s.out, "  %s\n", c)
		}
		return nil
	}
	buckets := rt.Buckets()
	total, used := 0, 0
	for _, b := range buckets {
		total += len(b)
		if len(b) > 0 {
			used++
		}
	}
	k := s.node.Config().K
	fmt.Fprintf(s.out, "routing table of %s: %d contacts in %d of %d buckets (k=%d)\n", me, total, used, kademlia.IDBits, k)
	fmt.Fprintln(s.out, "(empty buckets skipped; contacts least recently seen first)")
	for i, b := range buckets {
		if len(b) == 0 {
			continue
		}
		fmt.Fprintf(s.out, "bucket %3d (%d/%d):\n", i, len(b), k)
		for _, c := range b {
			fmt.Fprintf(s.out, "  %s\n", c)
		}
	}
	return nil
}

// contacts returns every contact in the routing table, closest to us first.
func (s *Shell) contacts() []kademlia.Contact {
	return s.node.RoutingTable().FindClosestContacts(s.node.Me().ID, math.MaxInt)
}
