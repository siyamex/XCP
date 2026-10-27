//go:build !linux

package agentrpc

import (
	"context"
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
)

var errUnsupported = errors.New("agent: peer credentials need Linux; use the fake agent for development")

// PeerCredentials is only available on Linux. Elsewhere every connection is refused.
func PeerCredentials([]uint32) credentials.TransportCredentials { return refuseAll{} }

type refuseAll struct{}

func (refuseAll) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errUnsupported
}

func (refuseAll) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errUnsupported
}

func (refuseAll) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}
func (refuseAll) Clone() credentials.TransportCredentials { return refuseAll{} }
func (refuseAll) OverrideServerName(string) error         { return nil }
