// Command kademlia runs one Kademlia node over UDP and an interactive
// shell to control it. All protocol parameters are flags.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/cli"
	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

func main() {
	def := kademlia.DefaultConfig()
	addrFlag := flag.String("addr", ":4000", "address to listen on (IP:PORT); an empty IP means this host's IP")
	bootstrap := flag.String("bootstrap", "", "node to join through (IP:PORT or HOST:PORT); empty starts a new network")
	k := flag.Int("k", def.K, "replication factor / bucket size")
	alpha := flag.Int("alpha", def.Alpha, "lookup parallelism")
	timeout := flag.Duration("timeout", def.RPC.Timeout, "RPC timeout per attempt")
	retries := flag.Int("retries", def.RPC.Retries, "RPC retransmissions after the first attempt")
	refresh := flag.Duration("refresh", def.RefreshInterval, "bucket refresh interval (0 disables)")
	logPath := flag.String("log", "kademlia.log", `file for JSON event logs ("-" for stderr)`)
	flag.Parse()

	if err := run(*addrFlag, *bootstrap, *logPath, kademlia.Config{
		K: *k, Alpha: *alpha, RefreshInterval: *refresh,
		RPC: rpc.Config{Timeout: *timeout, Retries: *retries},
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(addrFlag, bootstrap, logPath string, cfg kademlia.Config) error {
	var logOut io.Writer = os.Stderr
	if logPath != "-" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		logOut = f
	}
	cfg.Logger = slog.New(slog.NewJSONHandler(logOut, nil))

	addr, err := cli.ListenAddr(addrFlag)
	if err != nil {
		return err
	}
	node, err := kademlia.NewKademlia(network.UDPNetwork{}, addr, cfg)
	if err != nil {
		return err
	}
	defer node.Close()
	fmt.Printf("node %s listening on %s\n", node.Me().ID.Short(), node.Me().Address)

	// SIGINT/SIGTERM (Ctrl-C, docker stop) end the node like "exit".
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if bootstrap != "" {
		if err := cli.JoinWithRetry(ctx, node, bootstrap, 30, time.Second, os.Stdout); err != nil {
			return fmt.Errorf("join: %w", err)
		}
		fmt.Printf("joined via %s\n", bootstrap)
	}

	done := make(chan error, 1)
	go func() { done <- cli.NewShell(node, os.Stdout).Run(os.Stdin) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil
	}
}
