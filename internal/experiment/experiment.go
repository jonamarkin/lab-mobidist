// Package experiment runs the report's experiments on the simulated
// network. It only produces data: every measured lookup is logged as JSON
// lines (lookup_start, probe, probe_ok/probe_failed, lookup_done) by the
// nodes themselves, tagged with the run's parameters, and an external
// script (scripts/analyze.py) computes the statistics.
package experiment

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
	"github.com/jonamarkin/lab-mobidist/internal/testnet"
)

// Defaults shared by the experiments.
var (
	// DefaultSim delays each packet by 5-20 ms, so parallel probes are
	// answered in a realistic, varying order.
	DefaultSim = network.SimConfig{MinLatency: 5 * time.Millisecond, MaxLatency: 20 * time.Millisecond}

	// DefaultNode uses the spec's k and alpha. The RPC timeout (100 ms) is
	// well above the worst round trip (2 x 20 ms); 2 retries as in the
	// default policy. Background refresh and replication are off, so only
	// the measured lookups run.
	DefaultNode = kademlia.Config{K: 10, Alpha: 3, RPC: rpc.Config{Timeout: 100 * time.Millisecond, Retries: 2}}
)

// gate is a slog.Handler that drops every record while it is off. The
// experiments turn logging off while a network is being built (joins and
// refreshes are not what we measure) and on for the measured lookups.
type gate struct {
	slog.Handler
	on *atomic.Bool
}

func (g gate) Enabled(ctx context.Context, l slog.Level) bool {
	return g.on.Load() && g.Handler.Enabled(ctx, l)
}
func (g gate) WithAttrs(a []slog.Attr) slog.Handler { return gate{g.Handler.WithAttrs(a), g.on} }
func (g gate) WithGroup(n string) slog.Handler      { return gate{g.Handler.WithGroup(n), g.on} }

// ProbesConfig is experiment 1: lookup cost as a function of network size.
type ProbesConfig struct {
	Sizes   []int    // network sizes N
	Seeds   []uint64 // one network per (N, seed)
	Lookups int      // node lookups per network, random targets from random nodes
	Node    kademlia.Config
	Sim     network.SimConfig
}

// RunProbes runs experiment 1, writing JSON log lines to w and progress
// to progress.
func RunProbes(ctx context.Context, w io.Writer, progress io.Writer, cfg ProbesConfig) error {
	on := new(atomic.Bool)
	base := slog.New(gate{slog.NewJSONHandler(w, nil), on})
	for _, n := range cfg.Sizes {
		for _, seed := range cfg.Seeds {
			log := base.With("exp", "probes", "n", n, "seed", seed)
			node := cfg.Node
			node.Logger = log
			nw, err := build(ctx, n, seed, node, cfg.Sim)
			if err != nil {
				return fmt.Errorf("n=%d seed=%d: %w", n, seed, err)
			}
			nw.Sim.SetLatency(cfg.Sim.MinLatency, cfg.Sim.MaxLatency)
			on.Store(true)
			log.Info("run_start", "lookups", cfg.Lookups, "k", node.K, "alpha", node.Alpha)
			for range cfg.Lookups {
				from := nw.Nodes[nw.Rand.IntN(n)]
				from.LookupContact(ctx, kademlia.NewRandomKademliaID(nw.Rand))
			}
			on.Store(false)
			nw.Close()
			fmt.Fprintf(progress, "probes: n=%d seed=%d done\n", n, seed)
		}
	}
	return nil
}

// build creates a network of n nodes. It is built without packet delay or
// loss (that only slows building down; joins are not what we measure);
// the caller then switches on the configured delay (and loss) to measure.
func build(ctx context.Context, n int, seed uint64, node kademlia.Config, sim network.SimConfig) (*testnet.Network, error) {
	quiet := sim
	quiet.MinLatency, quiet.MaxLatency = 0, 0
	return testnet.Build(ctx, testnet.Options{N: n, Seed: seed, Node: node, Sim: quiet, JoinParallelism: 32})
}

// LossConfig is experiment 2: lookup reliability as a function of packet
// loss.
type LossConfig struct {
	N           int
	Losses      []float64 // packet loss probabilities
	Seeds       []uint64  // one network per (loss, seed)
	Values      int       // random values stored before loss is switched on
	Lookups     int       // value lookups per network
	Concurrency int       // lookups in flight at once
	Node        kademlia.Config
	Sim         network.SimConfig
}

// RunLoss runs experiment 2. For every (loss, seed) it builds a fresh
// network without loss, stores random values, then switches the loss on
// and looks up random stored keys from random nodes.
func RunLoss(ctx context.Context, w io.Writer, progress io.Writer, cfg LossConfig) error {
	on := new(atomic.Bool)
	base := slog.New(gate{slog.NewJSONHandler(w, nil), on})
	for _, loss := range cfg.Losses {
		for _, seed := range cfg.Seeds {
			log := base.With("exp", "loss", "n", cfg.N, "seed", seed, "loss", loss)
			node := cfg.Node
			node.Logger = log
			nw, err := build(ctx, cfg.N, seed, node, cfg.Sim)
			if err != nil {
				return fmt.Errorf("loss=%v seed=%d: %w", loss, seed, err)
			}
			keys := make([]kademlia.KademliaID, cfg.Values)
			for i := range keys {
				value := fmt.Appendf(nil, "value %d of seed %d: %x", i, seed, nw.Rand.Uint64())
				res, err := nw.Nodes[nw.Rand.IntN(cfg.N)].Store(ctx, value)
				if err != nil {
					nw.Close()
					return fmt.Errorf("store: %w", err)
				}
				keys[i] = res.Key
			}

			// Choose all (node, key) pairs up front, from the seeded RNG,
			// so concurrency does not change which lookups are made. The
			// node must not hold the key itself: a local hit says nothing
			// about the network's reliability.
			type job struct {
				from *kademlia.Kademlia
				key  kademlia.KademliaID
			}
			jobs := make(chan job, cfg.Lookups)
			for range cfg.Lookups {
				key := keys[nw.Rand.IntN(len(keys))]
				from := nw.Nodes[nw.Rand.IntN(cfg.N)]
				// Bounded: if every node holds the key (N <= k), give up
				// and accept a local hit (logged with local=true).
				for range 1000 {
					if _, holds := from.DataStore().Get(key); !holds {
						break
					}
					from = nw.Nodes[nw.Rand.IntN(cfg.N)]
				}
				jobs <- job{from, key}
			}
			close(jobs)

			nw.Sim.SetLatency(cfg.Sim.MinLatency, cfg.Sim.MaxLatency)
			nw.Sim.SetLossRate(loss)
			on.Store(true)
			log.Info("run_start", "lookups", cfg.Lookups, "values", cfg.Values, "k", node.K, "alpha", node.Alpha,
				"timeout_ms", node.RPC.Timeout.Milliseconds(), "retries", node.RPC.Retries)
			var wg sync.WaitGroup
			for range max(1, cfg.Concurrency) {
				wg.Go(func() {
					for j := range jobs {
						j.from.LookupData(ctx, j.key)
					}
				})
			}
			wg.Wait()
			on.Store(false)
			nw.Close()
			fmt.Fprintf(progress, "loss: p=%.2f seed=%d done\n", loss, seed)
		}
	}
	return nil
}
