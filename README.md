# lab-mobidist

A Kademlia distributed hash table in Go, built for the D7024E lab (part 1),
and a decentralized package registry on top of it (part 2).

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
- Registry (part 2): packages are named `DOMAIN:PACKAGE:VERSION`. Each version
  is a signed record chained to the previous one; one mutable "latest" pointer
  per package is the only key that is not the hash of its value. Nodes accept
  a pointer update only if it is signed by the domain's owner, newer than what
  they hold, and extends (never forks) the history they hold; a node that fell
  behind fetches the records it missed. Ownership is a public key in a DNS TXT
  record (`kademlia-pk=ed25519:<base64>`), real or faked from a file.

Parameters (defaults): k = 10, α = 3, RPC timeout 500 ms with 2 retries,
bucket refresh and replication every hour.

## Requirements

Go 1.26, Docker with Compose (for the container network), Python 3 (for the
experiment analysis script; standard library only). No Go dependencies
outside the standard library (`crypto/ed25519` for signatures).

## Build and test

```bash
make build      # bin/kademlia
make test       # go test ./...
make race       # go test -race ./...
make cover      # coverage summary
go test -short ./...   # skips the 1000-node tests
```

The suite has 185 tests (unit tests, simulated networks with a brute-force
oracle, two 1000-node tests, and real UDP/TCP on the loopback interface),
covers 91.7% of the statements, and passes with the race detector.

## Run a node

```bash
bin/kademlia -addr 127.0.0.1:4000                                # start a network
bin/kademlia -addr 127.0.0.1:4001 -bootstrap 127.0.0.1:4000     # join it
```

Flags: `-addr`, `-bootstrap`, `-k`, `-alpha`, `-timeout`, `-retries`,
`-refresh`, `-replicate`, `-log` (JSON event log, default `kademlia.log`).
An empty IP in `-addr` (e.g. `:4000`) means this host's own IP.

Registry flags: `-key FILE` (the node's signing key, needed to publish),
`-dns FILE` (a fake DNS file of `DOMAIN kademlia-pk=ed25519:...` lines;
without it the node does real DNS TXT lookups), and `-keygen FILE`
(generate a key, print its TXT record, and exit).

Shell commands:

| Command | Description |
|---|---|
| `ping IP:PORT \| HOST:PORT \| ID-PREFIX` | ping a node, print the round-trip time |
| `put FILENAME` | store a file's contents, print the key |
| `puttext TEXT...` | store the given text, print the key |
| `get KEY [FILENAME]` | fetch a value, save or print it, print where it came from |
| `lookup ID-PREFIX` | find the k nodes closest to an ID |
| `show rt` / `show ds` | print the routing table / the local data store |
| `publish [--force] [--prev=VERSION] DOMAIN:PACKAGE:VERSION FILENAME` | publish a file as a package version |
| `install DOMAIN:PACKAGE:VERSION [FILENAME]` | fetch a version (`latest` allowed), save or print it |
| `show DOMAIN:PACKAGE` | print the package's version chain |
| `show dns DOMAIN` | print the owner key of a domain |
| `id`, `help`, `exit` | |

Without `--force`, `publish` checks the update before uploading (the key owns
the domain, the version is newer than the latest, `--prev` is the latest).
With `--force` it uploads anyway, and the holders refuse it.

To try the registry locally, start the nodes with the demo DNS file and the
demo domain's key (both in `demo/`), then publish from one shell and install
from the other:

```bash
bin/kademlia -addr 127.0.0.1:4000 -dns demo/dns.txt -key demo/demo.test.pem
bin/kademlia -addr 127.0.0.1:4001 -bootstrap 127.0.0.1:4000 -dns demo/dns.txt
> publish demo.test:hello:1.0.0 some-file        # in the first shell
> install demo.test:hello:latest                 # in the second shell
> show demo.test:hello
```

A node started without `-dns` does real DNS TXT lookups, and one started
without `-key` can install but not publish.

## Docker (50 nodes)

```bash
make up             # bootstrap node + 49 nodes
make ps             # container status
make joined         # number of nodes that have joined (49 when ready)
make attach N=7     # shell of node 7 (detach: Ctrl-P Ctrl-Q)
make demo           # one extra node joins, pings, shows its table, exits
make store-demo     # store from one new node, fetch from another
make publish-demo   # publish two versions of demo.test:hello, install from another node
make reject-demo    # forced rollback, fork and impostor publishes, refused by the holders
make sprint-demo    # the sprint 3 sequence: v1, install, v2, install latest and v1, then the safety checks
make shell          # an interactive extra node with the demo key, to type the commands yourself
make user-shell     # the same without a key: can install, cannot publish
make down
REPLICATE=20s make up   # shorter replication interval, for demos
```

Every container runs with the fake DNS in `demo/dns.txt` and the signing key
of `demo.test`, so any node can publish as `demo.test`. `demo/other.test.pem`
is a second domain's key, used by `reject-demo` to show an impostor being
refused. `demo/files/` holds small package files (`v1.txt`, `v2.txt`,
`v3.txt`, `v5.txt`) available in every container as `/demo/files/`. These
keys are for the demo only.

## Experiments

```bash
make experiments    # runs both experiments (~10 min), then analyzes the log
make analyze        # re-analyze results/experiments.jsonl from a previous run
python3 scripts/analyze.py results-final/experiments.jsonl   # analyze the shipped run
```

Results (tables and CSV files) are written to `results/`.

1. Lookup cost (probes and hops) as a function of network size N.
2. Lookup success rate as a function of packet loss.

`results-final/` holds the run used in the report: the event log, the
analysis output (`run.txt`), the CSV files, and the commit it was made from.

## Layout

| Path | Contents |
|---|---|
| `cmd/kademlia` | node binary |
| `cmd/experiment` | experiment runner |
| `internal/kademlia` | the protocol: IDs, routing table, lookups, data store, data plane, replication, mutable keys |
| `internal/registry` | the package registry: versions, signed records, ownership verification, validation rules, client |
| `internal/rpc` | request/response layer over unreliable packets |
| `internal/network` | network abstraction: simulated network and UDP/TCP |
| `internal/cli` | interactive shell and startup helpers |
| `internal/testnet` | builds large simulated networks (tests, experiments) |
| `internal/experiment` | the experiments |
| `scripts/analyze.py` | analysis of the experiment logs |
| `demo/` | fake DNS file and signing keys for the Docker demo |
