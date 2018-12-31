package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/appengine/socket"
)

func getCertExpiration(ctx context.Context, hostname string) (time.Time, error) {
	plaintextConn, err := socket.DialTimeout(ctx, "tcp", hostname+":443", 3*time.Second)
	if err != nil {
		return time.Time{}, err
	}

	conn := tls.Client(plaintextConn, &tls.Config{
		ServerName: hostname,
	})
	err = conn.Handshake()
	if err != nil {
		return time.Time{}, err
	}

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		err := fmt.Errorf("weird connection state: %#v", conn.ConnectionState())
		return time.Time{}, err
	}

	var minExpires time.Time

	for _, cert := range conn.ConnectionState().PeerCertificates {
		if minExpires.IsZero() || cert.NotAfter.Before(minExpires) {
			minExpires = cert.NotAfter
		}
	}

	return minExpires, nil
}
