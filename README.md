# lab-mobidist

A Kademlia distributed hash table in Go, built for the D7024E lab (part 1),
as the storage layer for a decentralized package registry (part 2).

- 256-bit IDs: node ID = SHA-256(IP:port), key = SHA-256(value); nodes reject
  values whose hash does not match the key, and clients verify fetched values.
- k-bucket routing table (b = 1) with ping-before-evict, iterative lookups with
  bounded parallelism (at most α probes in flight), join with bucket refresh,
  periodic bucket refresh, and periodic replication. No expiration.
- Control plane: UDP RPCs with our own request/response matching (random
  160-bit RPC IDs), timeouts and retransmission. Data plane: values are
  transferred over TCP (max 64 MiB per value).
- The same code runs on an in-process simulated network (latency, packet loss,
  1000+ nodes) and on real sockets (50 Docker containers).

Parameters (defaults): k = 10, α = 3, RPC timeout 500 ms with 2 retries,
bucket refresh and replication every hour.

## Requirements

Go 1.26, Docker with Compose (for the container network), Python 3 (for the
experiment analysis script; standard library only).

## Build and test

```bash
make build      # bin/kademlia
make test       # go test ./...
make race       # go test -race ./...
make cover      # coverage summary
go test -short ./...   # skips the 1000-node test
```

## Run a node

```bash
bin/kademlia -addr 127.0.0.1:4000                                # start a network
bin/kademlia -addr 127.0.0.1:4001 -bootstrap 127.0.0.1:4000     # join it
```

Flags: `-addr`, `-bootstrap`, `-k`, `-alpha`, `-timeout`, `-retries`,
`-refresh`, `-replicate`, `-log` (JSON event log, default `kademlia.log`).
An empty IP in `-addr` (e.g. `:4000`) means this host's own IP.

Shell commands:

| Command | Description |
|---|---|
| `ping IP:PORT \| HOST:PORT \| ID-PREFIX` | ping a node, print the round-trip time |
| `put FILENAME` | store a file's contents, print the key |
| `puttext TEXT...` | store the given text, print the key |
| `get KEY [FILENAME]` | fetch a value, save or print it, print where it came from |
| `lookup ID-PREFIX` | find the k nodes closest to an ID |
| `show rt` / `show ds` | print the routing table / the local data store |
| `id`, `help`, `exit` | |

## Docker (50 nodes)

```bash
make up             # bootstrap node + 49 nodes
make joined         # number of nodes that have joined (49 when ready)
make attach N=7     # shell of node 7 (detach: Ctrl-P Ctrl-Q)
make store-demo     # store from one new node, fetch from another
make down
REPLICATE=20s make up   # shorter replication interval, for demos
```

## Experiments

```bash
make experiments    # runs both experiments (~10 min), then analyzes the log
make analyze        # re-analyze results/experiments.jsonl
```

Results (tables and CSV files) are written to `results/`.

1. Lookup cost (probes and hops) as a function of network size N.
2. Lookup success rate as a function of packet loss.

## Layout

| Path | Contents |
|---|---|
| `cmd/kademlia` | node binary |
| `cmd/experiment` | experiment runner |
| `internal/kademlia` | the protocol: IDs, routing table, lookups, data store, data plane, replication |
| `internal/rpc` | request/response layer over unreliable packets |
| `internal/network` | network abstraction: simulated network and UDP/TCP |
| `internal/cli` | interactive shell and startup helpers |
| `internal/testnet` | builds large simulated networks (tests, experiments) |
| `internal/experiment` | the experiments |
| `scripts/analyze.py` | analysis of the experiment logs |
