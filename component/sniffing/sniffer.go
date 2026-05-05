/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
)

const (
	PacketSnifferMaxBufferedBytes = 64 * 1024
	PacketSnifferMaxChunks        = 64
)

type Sniffer struct {
	// Stream
	stream    bool
	r         io.Reader
	dataReady chan struct{}
	dataError error

	// Common
	sniffed   string
	buf       *bytes.Buffer
	readMu    sync.Mutex
	readWg    sync.WaitGroup
	ctx       context.Context
	cancel    func()
	closeOnce sync.Once
	closed    bool

	// Packet
	data         [][]byte
	needMore     bool
	quicNextRead int
	quicCryptos  []*quicutils.CryptoFrameOffset
}

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	buffer := pool.GetBuffer()
	buffer.Grow(AssumedTlsClientHelloMaxLength)
	buffer.Reset()
	s := &Sniffer{
		stream:    true,
		r:         r,
		buf:       buffer,
		dataReady: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	return s
}

func NewPacketSniffer(data []byte, timeout time.Duration) *Sniffer {
	buffer := pool.GetBuffer()
	buffer.Write(data)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s := &Sniffer{
		stream:    false,
		r:         nil,
		buf:       buffer,
		data:      [][]byte{buffer.Bytes()},
		dataReady: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	return s
}

type sniff func() (d string, err error)

func sniffGroup(sniffs ...sniff) (d string, err error) {
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return NormalizeDomain(d), nil
		}
		if err != ErrNotApplicable {
			return "", err
		}
	}
	return "", ErrNotApplicable
}

func (s *Sniffer) SniffTcp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	s.readMu.Lock()
	if s.closed {
		s.readMu.Unlock()
		return "", io.ErrClosedPipe
	}
	defer s.readMu.Unlock()
	var oerr error
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", oerr, err)
		}
	}()
	for {
		if s.stream {
			s.readWg.Add(1)
			go func() {
				defer s.readWg.Done()
				// Read once.
				_, err := s.buf.ReadFromOnce(s.r)
				if err != nil {
					s.dataError = err
				}
				close(s.dataReady)
			}()

			// Waiting 100ms for data.
			select {
			case <-s.dataReady:
				if s.dataError != nil {
					return "", s.dataError
				}
			case <-s.ctx.Done():
				return "", fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
			}
		} else {
			close(s.dataReady)
		}

		if s.buf.Len() == 0 {
			return "", ErrNotApplicable
		}

		d, err = sniffGroup(
			// Most sniffable traffic is TLS, thus we sniff it first.
			s.SniffTls,
			s.SniffHttp,
		)
		if errors.Is(err, ErrNeedMore) {
			oerr = err
			s.dataReady = make(chan struct{})
			continue
		}
		return d, err
	}
}

func (s *Sniffer) SniffUdp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	s.readMu.Lock()
	if s.closed {
		s.readMu.Unlock()
		return "", io.ErrClosedPipe
	}
	defer s.readMu.Unlock()

	// Always ready.
	select {
	case <-s.dataReady:
	default:
		close(s.dataReady)
	}

	if s.dataError != nil {
		return "", s.dataError
	}
	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	return sniffGroup(
		s.SniffQuic,
	)
}

func (s *Sniffer) AppendData(data []byte) {
	s.needMore = false
	if !s.stream && (s.buf.Len()+len(data) > PacketSnifferMaxBufferedBytes || len(s.data) >= PacketSnifferMaxChunks) {
		s.dataError = ErrDataTooLarge
		return
	}
	ori := s.buf.Len()
	s.buf.Write(data)
	s.data = append(s.data, s.buf.Bytes()[ori:])
}

func (s *Sniffer) Data() [][]byte {
	data := make([][]byte, len(s.data))
	for i, chunk := range s.data {
		data[i] = append([]byte(nil), chunk...)
	}
	return data
}

func (s *Sniffer) NeedMore() bool {
	return s.needMore
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.dataError != nil {
		n, _ = s.buf.Read(p)
		return n, s.dataError
	}

	if s.buf.Len() > 0 {
		// Read buf first.
		return s.buf.Read(p)
	}
	if !s.stream {
		return 0, io.EOF
	}
	return s.r.Read(p)
}

func (s *Sniffer) Close() (err error) {
	s.closeOnce.Do(func() {
		select {
		case <-s.ctx.Done():
		default:
			s.cancel()
		}
		s.readMu.Lock()
		s.closed = true
		s.readMu.Unlock()
		s.readWg.Wait()
		s.readMu.Lock()
		defer s.readMu.Unlock()
		if s.buf != nil {
			s.buf.Reset()
			pool.PutBuffer(s.buf)
			s.buf = nil
		}
		s.data = nil
	})
	return nil
}
