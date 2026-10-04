.PHONY: test race cover build up down ps joined attach demo store-demo

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
