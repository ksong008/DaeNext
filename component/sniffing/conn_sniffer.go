/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"net"
	"time"
)

type ConnSniffer struct {
	net.Conn
	*Sniffer
}

func NewConnSniffer(conn net.Conn, timeout time.Duration) *ConnSniffer {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, timeout),
	}
	return s
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	return s.Sniffer.Read(p)
}

func (s *ConnSniffer) Close() (err error) {
	var errs []error
	if err = s.Conn.Close(); err != nil {
		errs = append(errs, err)
	}
	if err = s.Sniffer.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
