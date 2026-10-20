package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/registry"
)

// The part 2 shell commands: publish, install, show DOMAIN:PACKAGE and
// show dns DOMAIN. They are thin wrappers over registry.Client, which
// does the work and the verification.

var errNoRegistry = errors.New("this node has no registry (started without a verifier)")

func (s *Shell) registry() (*registry.Client, error) {
	if s.Registry == nil {
		return nil, errNoRegistry
	}
	return s.Registry, nil
}

// publish [--force] [--prev=VERSION] DOMAIN:PACKAGE:VERSION FILENAME
func (s *Shell) publish(ctx context.Context, args []string) error {
	client, err := s.registry()
	if err != nil {
		return err
	}
	var opts registry.PublishOptions
	var positional []string
	for _, a := range args {
		switch {
		case a == "--force":
			opts.Force = true
		case strings.HasPrefix(a, "--prev="):
			v, err := registry.ParseVersion(strings.TrimPrefix(a, "--prev="))
			if err != nil {
				return err
			}
			opts.Prev = &v
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) != 2 {
		return errors.New("usage: publish [--force] [--prev=VERSION] DOMAIN:PACKAGE:VERSION FILENAME")
	}
	ref, err := registry.ParseRef(positional[0])
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(positional[1])
	if err != nil {
		return err
	}
	res, err := client.Publish(ctx, ref, blob, opts)
	if res.RecordKey != (kademlia.KademliaID{}) {
		// The upload was attempted: say what happened, even on failure.
		fmt.Fprintf(s.out, "blob    %s stored on %d nodes\nrecord  %s stored on %d nodes\n",
			res.BlobKey.Short(), len(res.Blob.StoredAt), res.RecordKey.Short(), len(res.Record.StoredAt))
		fmt.Fprintf(s.out, "pointer accepted by %d, refused by %d, unreachable %d\n",
			len(res.Pointer.Accepted), len(res.Pointer.Refused), res.Pointer.Failed)
		for _, r := range res.Pointer.Refused {
			fmt.Fprintf(s.out, "  %s refused: %s\n", r.Node.ID.Short(), r.Reason)
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out, "published %s:%s %v\n", ref.Domain, ref.Package, ref.Version)
	return nil
}

// install DOMAIN:PACKAGE:VERSION [FILENAME]
func (s *Shell) install(ctx context.Context, args []string) error {
	client, err := s.registry()
	if err != nil {
		return err
	}
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: install DOMAIN:PACKAGE:VERSION [FILENAME]")
	}
	ref, err := registry.ParseRef(args[0])
	if err != nil {
		return err
	}
	pkg, err := client.Install(ctx, ref)
	if err != nil {
		return err
	}
	if len(args) == 2 {
		if err := os.WriteFile(args[1], pkg.Blob, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(s.out, "saved %d bytes to %s\n", len(pkg.Blob), args[1])
	} else {
		fmt.Fprintf(s.out, "%s\n", pkg.Blob)
	}
	fmt.Fprintf(s.out, "installed %s:%s %v (latest is %v)\nblob %s received from %s\n",
		pkg.Ref.Domain, pkg.Ref.Package, pkg.Ref.Version, pkg.Head, pkg.Record.Blob.Short(), pkg.From)
	return nil
}

// show DOMAIN:PACKAGE
func (s *Shell) showChain(ctx context.Context, name string) error {
	client, err := s.registry()
	if err != nil {
		return err
	}
	domain, pkg, err := registry.ParseName(name)
	if err != nil {
		return err
	}
	chain, err := client.Chain(ctx, domain, pkg)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out, "%s:%s: %d versions, newest first\n", domain, pkg, len(chain))
	for i, e := range chain {
		mark := "   "
		if i == 0 {
			mark = "-> "
		}
		if e.Err != nil && e.Version == (registry.Version{}) {
			fmt.Fprintf(s.out, "%s(record %s: %v)\n", mark, e.RecordKey.Short(), e.Err)
			continue
		}
		status := "signature ok"
		if e.Err != nil {
			status = "INVALID: " + e.Err.Error()
		}
		fmt.Fprintf(s.out, "%s%-10v record %s  blob %s  %s\n", mark, e.Version, e.RecordKey.Short(), e.Blob.Short(), status)
	}
	return nil
}

// show dns DOMAIN
func (s *Shell) showDNS(ctx context.Context, domain string) error {
	client, err := s.registry()
	if err != nil {
		return err
	}
	pk, err := client.Owner(ctx, domain)
	if err != nil {
		return err
	}
	fmt.Fprintf(s.out, "%s is owned by the key in this TXT record:\n%s\n", domain, registry.EncodePublicKey(pk))
	return nil
}

// describe says what a stored value is, for show ds: a package record,
// a latest pointer, or a plain value (with a preview).
func describe(value []byte, mutable bool) string {
	switch registry.TagOf(value) {
	case registry.TagVersionRecord:
		if r, err := registry.DecodeVersionRecord(value); err == nil {
			return fmt.Sprintf("record  %s:%s %v -> blob %s", r.Domain, r.Package, r.Version, r.Blob.Short())
		}
	case registry.TagLatestPointer:
		if p, err := registry.DecodeLatestPointer(value); err == nil {
			return fmt.Sprintf("latest  %s:%s -> %v (record %s)", p.Domain, p.Package, p.Version, p.Record.Short())
		}
	}
	if mutable {
		return "mutable " + preview(value)
	}
	return "value   " + preview(value)
}
