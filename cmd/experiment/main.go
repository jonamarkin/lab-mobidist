// Command experiment runs the report's experiments on the simulated
// network and writes the nodes' JSON event logs to a file, for
// scripts/analyze.py.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jonamarkin/lab-mobidist/internal/experiment"
)

func main() {
	which := flag.String("exp", "all", "experiment to run: probes, loss, or all")
	out := flag.String("out", "results/experiments.jsonl", "output file for the JSON event log")
	nSeeds := flag.Int("seeds", 5, "seeds (independent runs) per configuration")
	lookups := flag.Int("lookups", 100, "measured lookups per run")
	flag.Parse()

	seeds := make([]uint64, *nSeeds)
	for i := range seeds {
		seeds[i] = uint64(i + 1)
	}
	if err := os.MkdirAll("results", 0o755); err != nil {
		fail(err)
	}
	f, err := os.Create(*out)
	if err != nil {
		fail(err)
	}
	defer f.Close()

	ctx := context.Background()
	if *which == "probes" || *which == "all" {
		err := experiment.RunProbes(ctx, f, os.Stderr, experiment.ProbesConfig{
			Sizes: []int{25, 50, 100, 200, 400, 800, 1600}, Seeds: seeds, Lookups: *lookups,
			Node: experiment.DefaultNode, Sim: experiment.DefaultSim,
		})
		if err != nil {
			fail(err)
		}
	}
	if *which == "loss" || *which == "all" {
		err := experiment.RunLoss(ctx, f, os.Stderr, experiment.LossConfig{
			N: 500, Losses: []float64{0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7}, Seeds: seeds,
			Values: 50, Lookups: *lookups, Concurrency: 10,
			Node: experiment.DefaultNode, Sim: experiment.DefaultSim,
		})
		if err != nil {
			fail(err)
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
