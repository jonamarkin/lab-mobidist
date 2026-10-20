.PHONY: test race cover build experiments analyze up down ps joined attach demo store-demo publish-demo reject-demo

# --- Go ---------------------------------------------------------------

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

build:
	go build -o bin/kademlia ./cmd/kademlia

# Run both experiments (5 seeds each) on the simulated network, then
# analyze the event log: tables to stdout, CSV files in results/
experiments:
	go run ./cmd/experiment -out results/experiments.jsonl
	python3 scripts/analyze.py results/experiments.jsonl

# Re-analyze an existing log without re-running the experiments.
analyze:
	python3 scripts/analyze.py results/experiments.jsonl

# --- Docker: 50-node network -------------------------------------------

up:
	docker compose up -d --build

down:
	docker compose down

ps:
	docker compose ps

# How many nodes have joined (each prints "joined via ..." when done).
joined:
	@docker compose logs node | grep -c "joined via"

# Attach to node N's shell (default 1). Detach with Ctrl-P Ctrl-Q;
# typing "exit" terminates that node.
N ?= 1
attach:
	docker attach kademlia-node-$(N)

# Start one extra node that joins, runs a few commands, and exits.
demo:
	printf 'id\nping bootstrap:4000\nshow rt\nlookup 00\nexit\n' | \
		docker compose run --rm -T node

# Store a value from one new node, then fetch it by key from another.
store-demo:
	@key=$$(printf 'puttext hello from the store demo\nexit\n' | docker compose run --rm -T node | grep -oE 'key [0-9a-f]{64}' | cut -d' ' -f2); \
	echo "stored under key $$key"; \
	printf 'get %s\nexit\n' $$key | docker compose run --rm -T node

# --- Docker: package registry (part 2) ---------------------------------

# Flags of an extra node that joins the network with the demo registry.
NODE_FLAGS = -addr :4000 -bootstrap bootstrap:4000 -dns /demo/dns.txt
# A shell inside a fresh container, so the demos can write package files.
IN_NODE = docker compose run --rm -T --entrypoint sh node -c

# Publish two versions of demo.test:hello from one new node, then install
# the latest and the first from another, and show the chain.
publish-demo:
	$(IN_NODE) 'echo "hello, version 1" > /tmp/v1; echo "hello, version 2" > /tmp/v2; \
	  printf "publish demo.test:hello:1.0.0 /tmp/v1\npublish demo.test:hello:1.1.0 /tmp/v2\nshow demo.test:hello\nshow ds\nexit\n" \
	  | kademlia $(NODE_FLAGS) -key /demo/demo.test.pem'
	$(IN_NODE) 'printf "install demo.test:hello:latest\ninstall demo.test:hello:1.0.0 /tmp/old.txt\nshow dns demo.test\nexit\n" \
	  | kademlia $(NODE_FLAGS)'

# Invalid updates, forced past the client-side checks: the holders refuse
# a rollback, a fork, and a publish signed by another domain's key.
reject-demo:
	$(IN_NODE) 'echo "bad" > /tmp/bad; \
	  printf "publish --force demo.test:hello:0.9.0 /tmp/bad\npublish --force --prev=1.0.0 demo.test:hello:1.2.0 /tmp/bad\nexit\n" \
	  | kademlia $(NODE_FLAGS) -key /demo/demo.test.pem'
	$(IN_NODE) 'echo "bad" > /tmp/bad; \
	  printf "publish --force demo.test:hello:2.0.0 /tmp/bad\nshow demo.test:hello\nexit\n" \
	  | kademlia $(NODE_FLAGS) -key /demo/other.test.pem'
