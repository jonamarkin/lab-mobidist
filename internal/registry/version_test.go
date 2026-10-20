package registry

import (
	"encoding/json"
	"testing"
)

func TestParseVersion(t *testing.T) {
	good := map[string]Version{
		"0.0.0":                    {0, 0, 0},
		"1.4.2":                    {1, 4, 2},
		"10.0.99":                  {10, 0, 99},
		"18446744073709551615.0.0": {18446744073709551615, 0, 0}, // max uint64
	}
	for s, want := range good {
		v, err := ParseVersion(s)
		if err != nil || v != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v", s, v, err, want)
		}
		if v.String() != s {
			t.Errorf("String() = %q, want %q", v.String(), s)
		}
	}
	bad := []string{"", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "+1.2.3", "-1.2.3",
		" 1.2.3", "1.2.3 ", "1.2.x", "a.b.c", "1..3", "1.2.", "18446744073709551616.0.0", "1,2,3"}
	for _, s := range bad {
		if v, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) = %v, want an error", s, v)
		}
	}
}

func TestVersionOrder(t *testing.T) {
	// Each version is strictly lower than the next.
	ordered := []string{"0.0.0", "0.0.1", "0.1.0", "0.1.1", "0.9.9", "1.0.0", "1.0.10", "1.2.0", "2.0.0", "10.0.0"}
	var prev Version
	for i, s := range ordered {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatal(err)
		}
		if v.Compare(v) != 0 || v.Less(v) {
			t.Errorf("%v is not equal to itself", v)
		}
		if i > 0 {
			if !prev.Less(v) || prev.Compare(v) != -1 || v.Compare(prev) != 1 || v.Less(prev) {
				t.Errorf("%v should be lower than %v", prev, v)
			}
		}
		prev = v
	}
}

func TestVersionJSON(t *testing.T) {
	type doc struct {
		V Version `json:"v"`
	}
	b, err := json.Marshal(doc{Version{1, 4, 2}})
	if err != nil || string(b) != `{"v":"1.4.2"}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
	var d doc
	if err := json.Unmarshal(b, &d); err != nil || d.V != (Version{1, 4, 2}) {
		t.Fatalf("Unmarshal = %+v, %v", d, err)
	}
	if err := json.Unmarshal([]byte(`{"v":"1.4"}`), &d); err == nil {
		t.Error("a malformed version string was accepted")
	}
	if err := json.Unmarshal([]byte(`{"v":142}`), &d); err == nil {
		t.Error("a number was accepted as a version")
	}
}
