/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

type rustTproxyListenerHandoffReport struct {
	Status      string                  `json:"status"`
	Scope       string                  `json:"scope"`
	MapID       uint32                  `json:"map_id"`
	MapName     string                  `json:"map_name"`
	Port        uint16                  `json:"port"`
	KeysUpdated []uint32                `json:"keys_updated"`
	TCPOptions  rustTproxySocketOptions `json:"tcp_options"`
	UDPOptions  rustTproxySocketOptions `json:"udp_options"`
}

type rustTproxySocketOptions struct {
	IPTransparent           bool `json:"ip_transparent"`
	SOReuseaddr             bool `json:"so_reuseaddr"`
	IPRecvOrigDstAddr       bool `json:"ip_recvorigdstaddr"`
	IPv6RecvOrigDstAddr     bool `json:"ipv6_recvorigdstaddr"`
	OriginalDstCaptureReady bool `json:"original_dst_capture_ready"`
}

func (c *ControlPlane) listenAndServeViaRustAya(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	listener, err = c.openTproxyListenerViaRustAya(port)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()
	if err = c.Serve(readyChan, listener); err != nil {
		return nil, fmt.Errorf("failed to serve: %w", err)
	}
	return listener, nil
}

func (c *ControlPlane) openTproxyListenerViaRustAya(port uint16) (*Listener, error) {
	mapID, err := bpfMapID(c.core.bpf.ListenSocketMap)
	if err != nil {
		return nil, err
	}
	socketPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("create listener fd handoff socketpair: %w", err)
	}
	parentFD, childFD := socketPair[0], socketPair[1]
	parent := os.NewFile(uintptr(parentFD), "rust-tproxy-listener-parent")
	child := os.NewFile(uintptr(childFD), "rust-tproxy-listener-child")
	defer parent.Close()
	defer child.Close()

	ctx, cancel := context.WithTimeout(context.Background(), rustBpfLoaderHelperTimeout)
	defer cancel()
	cmd, err := rustBpfLoaderCommandContext(
		ctx,
		"tproxy-listener", "open-handoff",
		"--map-id", strconv.FormatUint(uint64(mapID), 10),
		"--port", strconv.Itoa(int(port)),
		"--handoff-fd", "3",
	)
	if err != nil {
		return nil, fmt.Errorf("resolve Rust/Aya tproxy listener helper: %w", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{child}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start Rust/Aya tproxy listener helper: %w", err)
	}
	_ = child.Close()

	payload, fds, recvErr := recvRustTproxyListenerHandoff(int(parent.Fd()))
	waitErr := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("Rust/Aya tproxy listener helper timed out after %s", rustBpfLoaderHelperTimeout)
	}
	if recvErr != nil {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("receive Rust/Aya tproxy listener handoff: %w%s", recvErr, rustHelperOutputSuffix(stdout.String(), stderr.String(), waitErr))
	}
	if waitErr != nil {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("Rust/Aya tproxy listener helper failed: %w%s", waitErr, rustHelperOutputSuffix(stdout.String(), stderr.String(), nil))
	}
	if len(fds) != 2 {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("Rust/Aya tproxy listener handoff returned %d fds, want 2", len(fds))
	}
	var report rustTproxyListenerHandoffReport
	if err := json.Unmarshal(payload, &report); err != nil {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("decode Rust/Aya tproxy listener handoff report: %w: %s", err, strings.TrimSpace(string(payload)))
	}
	if report.Status != "pass" || report.MapID != mapID {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("unexpected Rust/Aya tproxy listener handoff report: %s", strings.TrimSpace(string(payload)))
	}
	if !report.TCPOptions.OriginalDstCaptureReady || !report.UDPOptions.OriginalDstCaptureReady {
		closeReceivedFDs(fds)
		return nil, fmt.Errorf("Rust/Aya tproxy listener missing original-dst capture socket options: %s", strings.TrimSpace(string(payload)))
	}

	tcpListener, packetConn, err := wrapRustTproxyListenerFDs(fds)
	if err != nil {
		return nil, err
	}
	c.log.Infof("Opened tproxy listener via Rust/Aya on port %d and wrote listen_socket_map id %d", port, mapID)
	return &Listener{
		tcpListener:          tcpListener,
		packetConn:           packetConn,
		port:                 port,
		listenSocketMapReady: true,
		listenSocketMapID:    mapID,
	}, nil
}

func (c *ControlPlane) updateListenSocketMapForListener(listener *Listener, tcpListener *net.TCPListener, udpConn *net.UDPConn) error {
	mapID, err := bpfMapID(c.core.bpf.ListenSocketMap)
	if err != nil {
		return err
	}
	if listener.listenSocketMapReady && listener.listenSocketMapID == mapID {
		return nil
	}
	if err := c.updateListenSocketMapViaRustAya(mapID, tcpListener, udpConn); err == nil {
		listener.listenSocketMapReady = true
		listener.listenSocketMapID = mapID
		return nil
	} else {
		c.log.WithError(err).Debugln("Rust/Aya listen_socket_map update failed; falling back to Go map update")
	}
	if err := updateListenSocketMap(c.core.bpf.ListenSocketMap, consts.ZeroKey, tcpListener); err != nil {
		return fmt.Errorf("update TCP listen socket map: %w", err)
	}
	if err := updateListenSocketMap(c.core.bpf.ListenSocketMap, consts.OneKey, udpConn); err != nil {
		return fmt.Errorf("update UDP listen socket map: %w", err)
	}
	listener.listenSocketMapReady = true
	listener.listenSocketMapID = mapID
	return nil
}

func (c *ControlPlane) updateListenSocketMapViaRustAya(mapID uint32, tcpListener *net.TCPListener, udpConn *net.UDPConn) error {
	tcpFile, err := tcpListener.File()
	if err != nil {
		return fmt.Errorf("duplicate TCP listener fd for Rust/Aya sockmap update: %w", err)
	}
	defer tcpFile.Close()
	udpFile, err := udpConn.File()
	if err != nil {
		return fmt.Errorf("duplicate UDP socket fd for Rust/Aya sockmap update: %w", err)
	}
	defer udpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), rustBpfLoaderHelperTimeout)
	defer cancel()
	cmd, err := rustBpfLoaderCommandContext(
		ctx,
		"tproxy-listener", "update-map",
		"--map-id", strconv.FormatUint(uint64(mapID), 10),
		"--tcp-fd", "3",
		"--udp-fd", "4",
	)
	if err != nil {
		return fmt.Errorf("resolve Rust/Aya listen_socket_map helper: %w", err)
	}
	cmd.ExtraFiles = []*os.File{tcpFile, udpFile}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Rust/Aya listen_socket_map update timed out after %s", rustBpfLoaderHelperTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("Rust/Aya listen_socket_map update failed: %s", message)
	}
	var decoded struct {
		Status string `json:"status"`
		MapID  uint32 `json:"map_id"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		return fmt.Errorf("decode Rust/Aya listen_socket_map update output: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if decoded.Status != "pass" || decoded.MapID != mapID {
		return fmt.Errorf("unexpected Rust/Aya listen_socket_map update output: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func recvRustTproxyListenerHandoff(fd int) ([]byte, []int, error) {
	payload := make([]byte, 8192)
	oob := make([]byte, unix.CmsgSpace(2*4))
	n, oobn, _, _, err := unix.Recvmsg(fd, payload, oob, 0)
	if err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, nil, fmt.Errorf("empty fd handoff payload")
	}
	var fds []int
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, nil, err
	}
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			return nil, nil, err
		}
		fds = append(fds, rights...)
	}
	return payload[:n], fds, nil
}

func wrapRustTproxyListenerFDs(fds []int) (net.Listener, net.PacketConn, error) {
	tcpFile := os.NewFile(uintptr(fds[0]), "rust-tproxy-tcp-listener")
	udpFile := os.NewFile(uintptr(fds[1]), "rust-tproxy-udp-socket")
	tcpListener, tcpErr := net.FileListener(tcpFile)
	_ = tcpFile.Close()
	packetConn, udpErr := net.FilePacketConn(udpFile)
	_ = udpFile.Close()
	if tcpErr != nil || udpErr != nil {
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
		if packetConn != nil {
			_ = packetConn.Close()
		}
		if tcpErr != nil {
			return nil, nil, fmt.Errorf("wrap Rust/Aya TCP listener fd: %w", tcpErr)
		}
		return nil, nil, fmt.Errorf("wrap Rust/Aya UDP socket fd: %w", udpErr)
	}
	return tcpListener, packetConn, nil
}

func closeReceivedFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func rustHelperOutputSuffix(stdout string, stderr string, waitErr error) string {
	var parts []string
	if trimmed := strings.TrimSpace(stdout); trimmed != "" {
		parts = append(parts, "stdout: "+trimmed)
	}
	if trimmed := strings.TrimSpace(stderr); trimmed != "" {
		parts = append(parts, "stderr: "+trimmed)
	}
	if waitErr != nil {
		parts = append(parts, "wait: "+waitErr.Error())
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}
