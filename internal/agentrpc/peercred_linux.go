//go:build linux

package agentrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
)

// PeerCredentials returns server transport credentials that accept only
// Unix socket connections from processes running as one of allowedUIDs.
// They do no encryption: the socket is local and protected by file
// permissions; the kernel-reported UID is the authentication.
func PeerCredentials(allowedUIDs []uint32) credentials.TransportCredentials {
	return peerTransport{allowed: slices.Clone(allowedUIDs)}
}

type peerTransport struct{ allowed []uint32 }

func (t peerTransport) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("agent: only Unix socket connections are accepted")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, nil, err
	}
	if credErr != nil {
		return nil, nil, fmt.Errorf("agent: read peer credentials: %w", credErr)
	}
	if !slices.Contains(t.allowed, cred.Uid) {
		return nil, nil, fmt.Errorf("agent: uid %d is not allowed", cred.Uid)
	}
	return conn, newPeerCreds(cred.Uid, cred.Gid, cred.Pid), nil
}

func (t peerTransport) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("agent: peer credentials are server-side only")
}

func (t peerTransport) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (t peerTransport) Clone() credentials.TransportCredentials {
	return peerTransport{allowed: slices.Clone(t.allowed)}
}

func (t peerTransport) OverrideServerName(string) error { return nil }
