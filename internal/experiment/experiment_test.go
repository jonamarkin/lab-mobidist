package experiment

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
)

// records parses JSON log lines and returns the ones with the given msg.
func records(t *testing.T, data []byte, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range bytes.Lines(data) {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("not JSON: %s", line)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

var fastSim = network.SimConfig{MaxLatency: time.Millisecond}

// Only the measured lookups are logged (none from building the network),
// each tagged with the run's parameters.
func TestRunProbesLogsOnlyMeasuredLookups(t *testing.T) {
	var buf bytes.Buffer
	cfg := ProbesConfig{Sizes: []int{10, 20}, Seeds: []uint64{1, 2}, Lookups: 5, Node: DefaultNode, Sim: fastSim}
	if err := RunProbes(context.Background(), &buf, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	done := records(t, buf.Bytes(), "lookup_done")
	if len(done) != 2*2*5 {
		t.Fatalf("%d lookup_done records, want 20", len(done))
	}
	for _, r := range done {
		if r["exp"] != "probes" || r["kind"] != "node" || r["n"] == nil || r["seed"] == nil {
			t.Errorf("record missing run parameters: %v", r)
		}
	}
	if got := len(records(t, buf.Bytes(), "run_start")); got != 4 {
		t.Errorf("%d run_start records, want 4", got)
	}
}

func TestRunLoss(t *testing.T) {
	var buf bytes.Buffer
	cfg := LossConfig{N: 20, Losses: []float64{0, 0.3}, Seeds: []uint64{1}, Values: 3, Lookups: 6,
		Concurrency: 3, Node: DefaultNode, Sim: fastSim}
	if err := RunLoss(context.Background(), &buf, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	done := records(t, buf.Bytes(), "lookup_done")
	if len(done) != 2*6 {
		t.Fatalf("%d lookup_done records, want 12", len(done))
	}
	for _, r := range done {
		if r["exp"] != "loss" || r["kind"] != "value" {
			t.Errorf("unexpected record %v", r)
		}
		if r["loss"] == 0.0 && r["value"] != true {
			t.Errorf("lookup failed without packet loss: %v", r)
		}
	}
}

func TestRunFailsOnBadNetwork(t *testing.T) {
	sim := network.SimConfig{LossRate: 1} // joins cannot succeed
	node := DefaultNode
	node.RPC.Timeout = 5 * time.Millisecond
	if err := RunProbes(context.Background(), io.Discard, io.Discard,
		ProbesConfig{Sizes: []int{3}, Seeds: []uint64{1}, Lookups: 1, Node: node, Sim: sim}); err == nil {
		t.Error("RunProbes succeeded on a broken network")
	}
	if err := RunLoss(context.Background(), io.Discard, io.Discard,
		LossConfig{N: 3, Losses: []float64{0}, Seeds: []uint64{1}, Values: 1, Lookups: 1, Node: node, Sim: sim}); err == nil {
		t.Error("RunLoss succeeded on a broken network")
	}
}

// With N <= k every node holds every value; the run must still finish.
func TestRunLossTinyNetwork(t *testing.T) {
	cfg := LossConfig{N: 5, Losses: []float64{0}, Seeds: []uint64{1}, Values: 1, Lookups: 2,
		Concurrency: 1, Node: DefaultNode, Sim: fastSim}
	var buf bytes.Buffer
	if err := RunLoss(context.Background(), &buf, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if got := len(records(t, buf.Bytes(), "lookup_done")); got != 2 {
		t.Errorf("%d lookup_done records, want 2", got)
	}
}
