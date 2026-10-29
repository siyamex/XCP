// Package hostinfo tells facts about the server XCP runs on.
package hostinfo

import "net"

// ServerIPs lists the global unicast addresses of interfaces that are up and
// not loopback. (Some systems, like WSL, put a non-127 address on the
// loopback interface; it is not reachable from outside.) Behind NAT these
// are private addresses, not the public ones.
func ServerIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() && !n.IP.IsLinkLocalUnicast() {
				out = append(out, n.IP.String())
			}
		}
	}
	return out
}
