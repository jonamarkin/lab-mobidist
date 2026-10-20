# Stage 1: compile a static binary with the Go toolchain.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /kademlia ./cmd/kademlia

# Stage 2: a small runtime image with only the binary and the demo keys.
FROM alpine:3.22
COPY --from=build /kademlia /usr/local/bin/kademlia
# Demo registry: a fake DNS file and the keys of two demo domains. Every
# container gets them so any node can publish as demo.test (a demo
# shortcut: in a real deployment only the owner holds a key).
COPY demo/ /demo/
WORKDIR /data
EXPOSE 4000/udp 4000/tcp
ENTRYPOINT ["kademlia"]
