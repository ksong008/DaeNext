/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/sirupsen/logrus"
)

const (
	rustBpfLoaderHelperEnv     = "DAE_RUST_BPF_LOADER_HELPER"
	rustBpfLoaderHelperDefault = "dae-aya-bpf-loader"
	rustBpfLoaderHelperTimeout = 90 * time.Second
)

func rustBpfLoaderHelperPath() string {
	if helper := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv)); helper != "" {
		return helper
	}
	return rustBpfLoaderHelperDefault
}

var errEmbeddedRustBpfLoaderUnavailable = errors.New("embedded rust bpf loader unavailable")

func rustBpfLoaderExecutable() (string, error) {
	if strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv)) != "" {
		return rustBpfLoaderHelperPath(), nil
	}
	helper, err := embeddedRustBpfLoaderPath()
	if err == nil && helper != "" {
		return helper, nil
	}
	if err != nil && !errors.Is(err, errEmbeddedRustBpfLoaderUnavailable) {
		return "", err
	}
	return rustBpfLoaderHelperDefault, nil
}

func rustBpfLoaderCommandContext(ctx context.Context, args ...string) (*exec.Cmd, error) {
	helper, err := rustBpfLoaderExecutable()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, helper, args...), nil
}

func RustBpfLoaderContract() (text string, err error) {
	return runRustBpfLoaderHelperOutput("bpf-loader", "contract")
}

func fullLoadBpfObjectsViaRustAyaLoader(
	log *logrus.Logger,
	netns *DaeNetns,
	bpf *bpfObjects,
	opts *loadBpfOptions,
) error {
	if netns == nil {
		return fmt.Errorf("dae netns is not initialized")
	}
	if opts == nil {
		return fmt.Errorf("load bpf options are nil")
	}
	netnsID, err := netns.NetnsID()
	if err != nil {
		return fmt.Errorf("failed to get netns id: %w", err)
	}
	hasBpfGetCurrentTask := rustBpfLoaderHasGetCurrentTask(log)
	pinRoot := rustAyaLoaderPinRoot(opts.PinPath)
	out, err := runRustBpfLoaderHelperOutput(
		"bpf-loader", "load-pin",
		"--pin-root", pinRoot,
		"--tproxy-port", strconv.Itoa(int(opts.HostTproxyPort)),
		"--control-plane-pid", strconv.Itoa(os.Getpid()),
		"--dae0-ifindex", strconv.Itoa(netns.Dae0().Attrs().Index),
		"--dae-netns-id", strconv.FormatUint(uint64(uint32(netnsID)), 10),
		"--dae0peer-mac", netns.Dae0Peer().Attrs().HardwareAddr.String(),
		"--has-bpf-get-current-task", strconv.FormatBool(hasBpfGetCurrentTask),
	)
	if err != nil {
		return err
	}
	log.Debugf("Rust/Aya BPF loader output: %s", strings.TrimSpace(out))
	if err := adoptRustAyaPinnedBpfObjects(bpf, pinRoot); err != nil {
		return fmt.Errorf("adopt Rust/Aya loaded BPF objects: %w", err)
	}
	return nil
}

func rustBpfLoaderHasGetCurrentTask(log *logrus.Logger) bool {
	hasBpfGetCurrentTask := true
	if err := features.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetCurrentTask); err != nil {
		hasBpfGetCurrentTask = false
		log.Warnf("Kernel does not support bpf_get_current_task for cgroup/sock: %v; process names may fall back to bpf_get_current_comm", err)
	}
	if err := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask); err != nil {
		hasBpfGetCurrentTask = false
		log.Warnf("Kernel does not support bpf_get_current_task for cgroup/sock_addr: %v; process names may fall back to bpf_get_current_comm", err)
	}
	if hasBpfGetCurrentTask {
		log.Debugf("bpf_get_current_task is supported for cgroup process-name tracking")
	}
	return hasBpfGetCurrentTask
}

func adoptRustAyaPinnedBpfObjects(bpf *bpfObjects, pinRoot string) error {
	maps, err := loadRustAyaPinnedBpfMaps(filepath.Join(pinRoot, "maps"))
	if err != nil {
		return err
	}
	programs, err := loadRustAyaPinnedBpfPrograms(filepath.Join(pinRoot, "programs"))
	if err != nil {
		return errors.Join(err, closePinnedBpfMaps(&maps))
	}
	bpf.bpfMaps = maps
	bpf.bpfPrograms = programs
	return nil
}

func loadRustAyaPinnedBpfMaps(pinRoot string) (bpfMaps, error) {
	var maps bpfMaps
	load := func(name string) (*ebpf.Map, error) {
		return ebpf.LoadPinnedMap(filepath.Join(pinRoot, name), nil)
	}
	var err error
	if maps.CookiePidMap, err = load("cookie_pid_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.DomainRoutingMap, err = load("domain_routing_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.FastSock, err = load("fast_sock"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.ListenSocketMap, err = load("listen_socket_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.LpmArrayMap, err = load("lpm_array_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.OutboundConnectivityMap, err = load("outbound_connectivity_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.RedirectTrack, err = load("redirect_track"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.RoutingMap, err = load("routing_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.RoutingTuplesMap, err = load("routing_tuples_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.TgidPnameMap, err = load("tgid_pname_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.UdpConnStateMap, err = load("udp_conn_state_map"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	if maps.UnusedLpmType, err = load("unused_lpm_type"); err != nil {
		return maps, closePinnedBpfMapsWithErr(&maps, err)
	}
	return maps, nil
}

func loadRustAyaPinnedBpfPrograms(pinRoot string) (bpfPrograms, error) {
	var programs bpfPrograms
	load := func(name string) (*ebpf.Program, error) {
		return ebpf.LoadPinnedProgram(filepath.Join(pinRoot, name), nil)
	}
	var err error
	if programs.TproxyDae0Ingress, err = load("tproxy_dae0_ingress"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyDae0peerIngress, err = load("tproxy_dae0peer_ingress"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyLanEgressL2, err = load("tproxy_lan_egress_l2"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyLanEgressL3, err = load("tproxy_lan_egress_l3"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyLanIngressL2, err = load("tproxy_lan_ingress_l2"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyLanIngressL3, err = load("tproxy_lan_ingress_l3"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanCgConnect4, err = load("tproxy_wan_cg_connect4"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanCgConnect6, err = load("tproxy_wan_cg_connect6"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanCgSendmsg4, err = load("tproxy_wan_cg_sendmsg4"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanCgSendmsg6, err = load("tproxy_wan_cg_sendmsg6"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanCgSockCreate, err = load("tproxy_wan_cg_sock_create"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanCgSockRelease, err = load("tproxy_wan_cg_sock_release"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanEgressL2, err = load("tproxy_wan_egress_l2"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanEgressL3, err = load("tproxy_wan_egress_l3"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanIngressL2, err = load("tproxy_wan_ingress_l2"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	if programs.TproxyWanIngressL3, err = load("tproxy_wan_ingress_l3"); err != nil {
		return programs, closePinnedBpfProgramsWithErr(&programs, err)
	}
	return programs, nil
}

func closePinnedBpfMapsWithErr(maps *bpfMaps, err error) error {
	return errors.Join(err, closePinnedBpfMaps(maps))
}

func closePinnedBpfProgramsWithErr(programs *bpfPrograms, err error) error {
	return errors.Join(err, closePinnedBpfPrograms(programs))
}

func closePinnedBpfMaps(maps *bpfMaps) error {
	return errors.Join(
		closeBpfMap(maps.CookiePidMap),
		closeBpfMap(maps.DomainRoutingMap),
		closeBpfMap(maps.FastSock),
		closeBpfMap(maps.ListenSocketMap),
		closeBpfMap(maps.LpmArrayMap),
		closeBpfMap(maps.OutboundConnectivityMap),
		closeBpfMap(maps.RedirectTrack),
		closeBpfMap(maps.RoutingMap),
		closeBpfMap(maps.RoutingTuplesMap),
		closeBpfMap(maps.TgidPnameMap),
		closeBpfMap(maps.UdpConnStateMap),
		closeBpfMap(maps.UnusedLpmType),
	)
}

func closePinnedBpfPrograms(programs *bpfPrograms) error {
	return errors.Join(
		closeBpfProgram(programs.TproxyDae0Ingress),
		closeBpfProgram(programs.TproxyDae0peerIngress),
		closeBpfProgram(programs.TproxyLanEgressL2),
		closeBpfProgram(programs.TproxyLanEgressL3),
		closeBpfProgram(programs.TproxyLanIngressL2),
		closeBpfProgram(programs.TproxyLanIngressL3),
		closeBpfProgram(programs.TproxyWanCgConnect4),
		closeBpfProgram(programs.TproxyWanCgConnect6),
		closeBpfProgram(programs.TproxyWanCgSendmsg4),
		closeBpfProgram(programs.TproxyWanCgSendmsg6),
		closeBpfProgram(programs.TproxyWanCgSockCreate),
		closeBpfProgram(programs.TproxyWanCgSockRelease),
		closeBpfProgram(programs.TproxyWanEgressL2),
		closeBpfProgram(programs.TproxyWanEgressL3),
		closeBpfProgram(programs.TproxyWanIngressL2),
		closeBpfProgram(programs.TproxyWanIngressL3),
	)
}

func closeBpfMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	return m.Close()
}

func closeBpfProgram(p *ebpf.Program) error {
	if p == nil {
		return nil
	}
	return p.Close()
}

func runRustBpfLoaderHelperOutput(args ...string) (string, error) {
	return runRustBpfLoaderHelperInput(nil, args...)
}

func runRustBpfLoaderHelperInput(input []byte, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rustBpfLoaderHelperTimeout)
	defer cancel()
	cmd, err := rustBpfLoaderCommandContext(ctx, args...)
	if err != nil {
		return "", err
	}
	if input != nil {
		cmd.Stdin = strings.NewReader(string(input))
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("rust bpf loader helper timed out after %s", rustBpfLoaderHelperTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("rust bpf loader helper %q failed: %s", cmd.Path, message)
	}
	return string(out), nil
}
