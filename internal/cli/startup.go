package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// ResolveAddr turns "IP:PORT" or "HOST:PORT" (e.g. "bootstrap:4000" in
// Docker) into an address, preferring IPv4.
func ResolveAddr(s string) (netip.AddrPort, error) {
	if addr, err := netip.ParseAddrPort(s); err == nil {
		return unmap(addr), nil
	}
	udp, err := net.ResolveUDPAddr("udp4", s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %q: %w", s, err)
	}
	return unmap(udp.AddrPort()), nil
}

// ListenAddr turns the -addr flag into the address to listen on. An empty
// host (":4000") means this machine's own IP, because a node's ID is the
// hash of the address other nodes see; 0.0.0.0 would give every container
// the same ID.
func ListenAddr(s string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port %q", portStr)
	}
	if host != "" {
		return ResolveAddr(s)
	}
	ip, err := HostIP()
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// HostIP returns this machine's IPv4 address: the one its hostname
// resolves to (in Docker, the container's IP), or else the address of the
// interface that would route to the outside. Neither sends any packets.
func HostIP() (netip.Addr, error) {
	if name, err := os.Hostname(); err == nil {
		if ips, err := net.LookupIP(name); err == nil {
			for _, ip := range ips {
				if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() && !a.IsLoopback() {
					return a.Unmap(), nil
				}
			}
		}
	}
	conn, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1; UDP "dial" sends nothing
	if err != nil {
		return netip.Addr{}, fmt.Errorf("cannot determine this host's IP: %w", err)
	}
	defer conn.Close()
	return unmap(conn.LocalAddr().(*net.UDPAddr).AddrPort()).Addr(), nil
}

// JoinWithRetry joins through bootstrap ("IP:PORT" or "HOST:PORT"),
// retrying while it is not yet reachable. In Docker all containers start
// at about the same time: the bootstrap node may not be listening yet,
// and Docker's DNS can time out under the burst of lookups, so the name is
// resolved again on every attempt.
func JoinWithRetry(ctx context.Context, node *kademlia.Kademlia, bootstrap string, attempts int, delay time.Duration, out io.Writer) error {
	var err error
	for i := 1; i <= attempts; i++ {
		var addr netip.AddrPort
		if addr, err = ResolveAddr(bootstrap); err == nil {
			if err = node.Join(ctx, addr); err == nil {
				return nil
			}
		}
		fmt.Fprintf(out, "join attempt %d/%d failed: %v\n", i, attempts, err)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}
