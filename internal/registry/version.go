// Package registry is the package registry of part 2, built on the
// Kademlia data store: a signed, chained version record per package
// version, and one mutable "latest" pointer per package. A domain owns
// its packages; ownership is proven with a key published in DNS.
package registry

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"
)

// Version is a MAJOR.MINOR.PATCH version. Versions are totally ordered,
// which is what lets a node tell an update from a rollback by comparing
// two versions, without knowing the whole history.
type Version struct {
	Major, Minor, Patch uint64
}

// ParseVersion parses "MAJOR.MINOR.PATCH", e.g. "1.4.2". Each part is a
// plain decimal number: no sign, no spaces, no leading zeros, so every
// version has exactly one spelling.
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q: want MAJOR.MINOR.PATCH", s)
	}
	var n [3]uint64
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil || strconv.FormatUint(v, 10) != p {
			return Version{}, fmt.Errorf("version %q: bad number %q", s, p)
		}
		n[i] = v
	}
	return Version{n[0], n[1], n[2]}, nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare returns -1, 0 or +1 as v is lower than, equal to or higher
// than w: major first, then minor, then patch.
func (v Version) Compare(w Version) int {
	return cmp.Or(
		cmp.Compare(v.Major, w.Major),
		cmp.Compare(v.Minor, w.Minor),
		cmp.Compare(v.Patch, w.Patch),
	)
}

// Less reports whether v is lower than w.
func (v Version) Less(w Version) bool { return v.Compare(w) < 0 }

// MarshalText writes the version as "1.4.2", so it is a JSON string.
func (v Version) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// UnmarshalText parses the form written by MarshalText.
func (v *Version) UnmarshalText(text []byte) error {
	parsed, err := ParseVersion(string(text))
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}
