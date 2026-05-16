/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	NsName       = "daens"
	HostVethName = "dae0"
	NsVethName   = "dae0peer"
)

type netnsLinkMode string

const (
	netnsLinkEnv        = "DAE_NETNS_LINK"
	netnsLinkModeAuto   = netnsLinkMode("auto")
	netnsLinkModeVeth   = netnsLinkMode("veth")
	netnsLinkModeNetkit = netnsLinkMode("netkit")
)

var (
	daeNetns       *DaeNetns
	once           sync.Once
	netkitProbeSeq atomic.Uint32
)

type DaeNetns struct {
	log *logrus.Logger

	setupDone atomic.Bool
	mu        sync.Mutex

	dae0, dae0peer netlink.Link
	hostNs, daeNs  netns.NsHandle
	linkMode       netnsLinkMode
}

func NewDaeNetns(log *logrus.Logger) *DaeNetns {
	return &DaeNetns{
		log:    log,
		hostNs: netns.None(),
		daeNs:  netns.None(),
	}
}

func InitDaeNetns(log *logrus.Logger) {
	once.Do(func() {
		daeNetns = NewDaeNetns(log)
	})
	daeNetns.log = log
}

func GetDaeNetns() *DaeNetns {
	return daeNetns
}

func (ns *DaeNetns) NetnsID() (int, error) {
	return netlink.GetNetNsIdByFd(int(ns.daeNs))
}

func (ns *DaeNetns) Dae0() netlink.Link {
	return ns.dae0
}

func (ns *DaeNetns) Dae0Peer() netlink.Link {
	return ns.dae0peer
}

func (ns *DaeNetns) LinkMode() string {
	if ns == nil {
		return ""
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return string(ns.linkMode)
}

func (ns *DaeNetns) Setup() (err error) {
	if ns.setupDone.Load() {
		return
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.setupDone.Load() {
		return
	}
	if err = ns.setup(); err != nil {
		return
	}
	ns.setupDone.Store(true)
	return nil
}

func (ns *DaeNetns) Close() (err error) {
	return ns.closeWith(DeleteNamedNetns, DeleteLink)
}

func (ns *DaeNetns) closeWith(deleteNamedNetns func(string) error, deleteLink func(string) error) (err error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	var errs []error
	if e := deleteNamedNetns(NsName); e != nil {
		errs = append(errs, fmt.Errorf("delete named netns %s: %w", NsName, e))
	}
	if e := deleteLink(HostVethName); e != nil {
		errs = append(errs, fmt.Errorf("delete link %s: %w", HostVethName, e))
	}
	if e := closeNsHandle("dae", &ns.daeNs); e != nil {
		errs = append(errs, e)
	}
	if e := closeNsHandle("host", &ns.hostNs); e != nil {
		errs = append(errs, e)
	}

	ns.dae0 = nil
	ns.dae0peer = nil
	ns.linkMode = ""
	ns.setupDone.Store(false)
	return errors.Join(errs...)
}

func closeNsHandle(name string, handle *netns.NsHandle) error {
	if handle == nil {
		return nil
	}
	if *handle == netns.None() {
		return nil
	}
	if *handle == 0 {
		// A zero-value DaeNetns historically left NsHandle fields at 0; do not close stdin.
		*handle = netns.None()
		return nil
	}
	if err := handle.Close(); err != nil {
		if errors.Is(err, unix.EBADF) {
			*handle = netns.None()
			return nil
		}
		return fmt.Errorf("close %s netns handle: %w", name, err)
	}
	return nil
}

func (ns *DaeNetns) With(f func() error) (err error) {
	if err = ns.Setup(); err != nil {
		return fmt.Errorf("failed to setup dae netns: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = f(); err != nil {
		return fmt.Errorf("failed to run func in dae netns: %v", err)
	}
	return
}

func (ns *DaeNetns) setup() (err error) {
	ns.log.Trace("setting up dae netns")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if ns.hostNs, err = netns.Get(); err != nil {
		return fmt.Errorf("failed to get host netns: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = ns.setupLinkPairAndNetns(); err != nil {
		return
	}
	if err = ns.setupSysctl(); err != nil {
		return
	}
	if err = ns.setupIPv4Datapath(); err != nil {
		return
	}
	if err = ns.setupIPv6Datapath(); err != nil {
		return
	}
	if err = ns.setupRoutingPolicy(); err != nil {
		return
	}
	return
}

func (ns *DaeNetns) setupRoutingPolicy() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	/// Insert ip rule / ip route.
	var table = 2023

	/** ip table
	ip route add local default dev lo table 2023
	ip -6 route add local default dev lo table 2023
	*/
	routes := []netlink.Route{{
		Scope:     unix.RT_SCOPE_HOST,
		LinkIndex: consts.LoopbackIfIndex,
		Dst: &net.IPNet{
			IP:   []byte{0, 0, 0, 0},
			Mask: net.CIDRMask(0, 32),
		},
		Table: table,
		Type:  unix.RTN_LOCAL,
	}, {
		Scope:     unix.RT_SCOPE_HOST,
		LinkIndex: consts.LoopbackIfIndex,
		Dst: &net.IPNet{
			IP:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(0, 128),
		},
		Table: table,
		Type:  unix.RTN_LOCAL,
	}}
	for _, route := range routes {
		if err = netlink.RouteAdd(&route); err != nil {
			if len(route.Dst.IP) == net.IPv6len {
				// ipv6
				ns.log.Warnln("IpRouteAdd: Bad IPv6 support. Perhaps your machine disabled IPv6.")
				continue
			}
			return fmt.Errorf("IpRouteAdd: %w", err)
		}
	}

	/** ip rule
	ip rule add fwmark 0x8000000/0x8000000 table 2023
	ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
	*/
	tproxyMark := uint32(consts.TproxyMark)
	rules := []netlink.Rule{{
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Goto:              -1,
		Flow:              -1,
		Family:            unix.AF_INET,
		Table:             table,
		Mark:              tproxyMark,
		Mask:              &tproxyMark,
	}, {
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Goto:              -1,
		Flow:              -1,
		Family:            unix.AF_INET6,
		Table:             table,
		Mark:              tproxyMark,
		Mask:              &tproxyMark,
	}}

	for _, rule := range rules {
		if err = netlink.RuleAdd(&rule); err != nil {
			if rule.Family == unix.AF_INET6 {
				// ipv6
				ns.log.Warnln("IpRuleAdd: Bad IPv6 support. Perhaps your machine disabled IPv6 (need CONFIG_IPV6_MULTIPLE_TABLES).")
				continue
			}
			return fmt.Errorf("IpRuleAdd: %w", err)
		}
	}
	return nil
}

func parseNetnsLinkMode(raw string) (netnsLinkMode, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		return netnsLinkModeAuto, nil
	}
	switch netnsLinkMode(mode) {
	case netnsLinkModeAuto, netnsLinkModeVeth, netnsLinkModeNetkit:
		return netnsLinkMode(mode), nil
	default:
		return "", fmt.Errorf("invalid %s=%q, want auto, netkit, or veth", netnsLinkEnv, raw)
	}
}

func (ns *DaeNetns) setupLinkPairAndNetns() error {
	mode, err := parseNetnsLinkMode(os.Getenv(netnsLinkEnv))
	if err != nil {
		return err
	}
	return ns.setupLinkPairAndNetnsWith(mode, ns.probeNetkitSupport, ns.setupNetkitAndNetns, ns.setupVethAndNetns, ns.cleanupFailedLinkSetup)
}

func (ns *DaeNetns) setupLinkPairAndNetnsWith(
	mode netnsLinkMode,
	probeNetkit func() error,
	setupNetkit func() error,
	setupVeth func() error,
	cleanup func(),
) error {
	switch mode {
	case netnsLinkModeVeth:
		if err := setupVeth(); err != nil {
			return err
		}
		ns.linkMode = netnsLinkModeVeth
		ns.logNetnsLinkInfo("dae netns link mode: veth")
		return nil
	case netnsLinkModeNetkit:
		if err := probeNetkit(); err != nil {
			return fmt.Errorf("netkit requested but preflight failed: %w", err)
		}
		if err := setupNetkit(); err != nil {
			if cleanup != nil {
				cleanup()
			}
			return fmt.Errorf("netkit requested but setup failed: %w", err)
		}
		ns.linkMode = netnsLinkModeNetkit
		ns.logNetnsLinkInfo("dae netns link mode: netkit")
		return nil
	case netnsLinkModeAuto:
		var fallbackReason error
		if err := probeNetkit(); err != nil {
			fallbackReason = fmt.Errorf("preflight failed: %w", err)
		} else if err := setupNetkit(); err != nil {
			fallbackReason = fmt.Errorf("setup failed: %w", err)
		} else {
			ns.linkMode = netnsLinkModeNetkit
			ns.logNetnsLinkInfo("dae netns link mode: netkit")
			return nil
		}
		if cleanup != nil {
			cleanup()
		}
		ns.logNetnsLinkWarnf("dae netns link mode: veth fallback: %v", fallbackReason)
		if err := setupVeth(); err != nil {
			return fmt.Errorf("failed to setup veth fallback after netkit failure (%v): %w", fallbackReason, err)
		}
		ns.linkMode = netnsLinkModeVeth
		return nil
	default:
		return fmt.Errorf("invalid netns link mode: %q", mode)
	}
}

func (ns *DaeNetns) setupVethAndNetns() error {
	if err := ns.setupVeth(); err != nil {
		return err
	}
	return ns.setupNetns()
}

func (ns *DaeNetns) setupNetkitAndNetns() error {
	if err := ns.setupNetkit(); err != nil {
		return err
	}
	return ns.setupNetns()
}

func (ns *DaeNetns) cleanupFailedLinkSetup() {
	if ns.hostNs != netns.None() && ns.hostNs != 0 {
		_ = netns.Set(ns.hostNs)
	}
	_ = DeleteNamedNetns(NsName)
	_ = DeleteLink(HostVethName)
	_ = DeleteLink(NsVethName)
	_ = closeNsHandle("dae", &ns.daeNs)
	ns.dae0 = nil
	ns.dae0peer = nil
	ns.linkMode = ""
}

func (ns *DaeNetns) logNetnsLinkInfo(msg string) {
	if ns != nil && ns.log != nil {
		ns.log.Info(msg)
	}
}

func (ns *DaeNetns) logNetnsLinkWarnf(format string, args ...any) {
	if ns != nil && ns.log != nil {
		ns.log.Warnf(format, args...)
	}
}

func nextNetkitProbeNames() (hostName, peerName string) {
	seq := netkitProbeSeq.Add(1) % 100000
	pid := os.Getpid() % 10000
	suffix := fmt.Sprintf("%04d%05d", pid, seq)
	return "dnkh" + suffix, "dnkp" + suffix
}

func (ns *DaeNetns) probeNetkitSupport() (err error) {
	hostName, peerName := nextNetkitProbeNames()
	defer DeleteLink(hostName)
	defer DeleteLink(peerName)

	netkit := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:   hostName,
			TxQLen: 1000,
		},
		Mode:       netlink.NETKIT_MODE_L2,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
		Scrub:      netlink.NETKIT_SCRUB_NONE,
		PeerScrub:  netlink.NETKIT_SCRUB_NONE,
	}
	netkit.SetPeerAttrs(&netlink.LinkAttrs{Name: peerName})
	if err = netlink.LinkAdd(netkit); err != nil {
		return fmt.Errorf("create netkit pair: %w", err)
	}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get netkit primary: %w", err)
	}
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		return fmt.Errorf("get netkit peer: %w", err)
	}
	if err = netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("set netkit primary up: %w", err)
	}
	if err = netlink.LinkSetUp(peerLink); err != nil {
		return fmt.Errorf("set netkit peer up: %w", err)
	}
	if err = addClsactQdisc(hostName); err != nil {
		return fmt.Errorf("add clsact to netkit primary: %w", err)
	}
	if err = addClsactQdisc(peerName); err != nil {
		return fmt.Errorf("add clsact to netkit peer: %w", err)
	}
	return nil
}

func (ns *DaeNetns) setupVeth() (err error) {
	// ip l a dae0 type veth peer name dae0peer
	DeleteLink(HostVethName)
	DeleteLink(NsVethName)
	if err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   HostVethName,
			TxQLen: 1000,
		},
		PeerName: NsVethName,
	}); err != nil {
		return fmt.Errorf("failed to add veth pair: %v", err)
	}
	if ns.dae0, err = netlink.LinkByName(HostVethName); err != nil {
		return fmt.Errorf("failed to get link dae0: %v", err)
	}
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %v", err)
	}
	// ip l s dae0 up
	if err = netlink.LinkSetUp(ns.dae0); err != nil {
		return fmt.Errorf("failed to set link dae0 up: %v", err)
	}
	return
}

func (ns *DaeNetns) setupNetkit() (err error) {
	DeleteLink(HostVethName)
	DeleteLink(NsVethName)
	netkit := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:   HostVethName,
			TxQLen: 1000,
		},
		Mode:       netlink.NETKIT_MODE_L2,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
		Scrub:      netlink.NETKIT_SCRUB_NONE,
		PeerScrub:  netlink.NETKIT_SCRUB_NONE,
	}
	netkit.SetPeerAttrs(&netlink.LinkAttrs{Name: NsVethName})
	if err = netlink.LinkAdd(netkit); err != nil {
		return fmt.Errorf("failed to add netkit pair: %v", err)
	}
	if ns.dae0, err = netlink.LinkByName(HostVethName); err != nil {
		return fmt.Errorf("failed to get link dae0: %v", err)
	}
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %v", err)
	}
	if err = netlink.LinkSetUp(ns.dae0); err != nil {
		return fmt.Errorf("failed to set netkit link dae0 up: %v", err)
	}
	return nil
}

func (ns *DaeNetns) setupNetns() (err error) {
	// ip netns a daens
	DeleteNamedNetns(NsName)
	ns.daeNs, err = netns.NewNamed(NsName)
	if err != nil {
		return fmt.Errorf("failed to create netns: %v", err)
	}
	// NewNamed() will switch to the new netns, switch back to host netns
	if err = netns.Set(ns.hostNs); err != nil {
		return fmt.Errorf("failed to switch to host netns: %v", err)
	}
	// ip l s dae0peer netns daens
	if err = netlink.LinkSetNsFd(ns.dae0peer, int(ns.daeNs)); err != nil {
		return fmt.Errorf("failed to move dae0peer to daens: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)
	// (ip net e daens) ip l s dae0peer up
	if err = netlink.LinkSetUp(ns.dae0peer); err != nil {
		return fmt.Errorf("failed to set link dae0peer up: %v", err)
	}
	// re-fetch dae0peer to make sure we have the latest mac address
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %v", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get link lo: %v", err)
	}
	// (ip net e daens) ip l s lo up
	if err = netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to set link lo up: %v", err)
	}
	return
}

func (ns *DaeNetns) setupSysctl() (err error) {
	// sysctl net.ipv6.conf.dae0.disable_ipv6=0
	if err = sysctl.Keyf("net.ipv6.conf.%s.disable_ipv6", HostVethName).Set("0", true); err != nil {
		return fmt.Errorf("failed to set disable_ipv6 for dae0: %v", err)
	}
	// sysctl net.ipv6.conf.dae0.forwarding=1
	if err = sysctl.Keyf("net.ipv6.conf.%s.forwarding", HostVethName).Set("1", true); err != nil {
		return fmt.Errorf("failed to set forwarding for dae0: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// *_early_demux is not mandatory, but it's recommended to enable it for better performance
	sysctl.Keyf("net.ipv4.tcp_early_demux").Set("1", false)
	sysctl.Keyf("net.ipv4.ip_early_demux").Set("1", false)

	// (ip net e daens) sysctl net.ipv4.conf.dae0peer.accept_local=1
	// This is to prevent kernel from dropping skb due to "martian source" check: https://elixir.bootlin.com/linux/v6.6/source/net/ipv4/fib_frontend.c#L381
	if err = sysctl.Keyf("net.ipv4.conf.%s.accept_local", NsVethName).Set("1", false); err != nil {
		return fmt.Errorf("failed to set accept_local for dae0peer: %v", err)
	}
	return
}

func (ns *DaeNetns) setupIPv4Datapath() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// (ip net e daens) ip a a 169.254.0.11 dev dae0peer
	// Although transparent UDP socket doesn't use this IP, it's still needed to make proper L3 header
	ip, ipNet, err := net.ParseCIDR("169.254.0.11/32")
	ipNet.IP = ip
	if err != nil {
		return fmt.Errorf("failed to parse ip 169.254.0.11: %v", err)
	}
	if err = netlink.AddrAdd(ns.dae0peer, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("failed to add v4 addr to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a 169.254.0.1 dev dae0peer
	// 169.254.0.1 is the link-local address used for ARP caching
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("169.254.0.1"), Mask: net.CIDRMask(32, 32)},
		Gw:        nil,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("failed to add v4 route1 to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a default via 169.254.0.1 dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		Gw:        net.ParseIP("169.254.0.1"),
	}); err != nil {
		return fmt.Errorf("failed to add v4 route2 to dae0peer: %v", err)
	}
	// (ip net e daens) ip n r 169.254.0.1 dev dae0peer lladdr $mac_dae0 nud permanent
	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("169.254.0.1"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("failed to add neigh to dae0peer: %v", err)
	}
	return
}

func (ns *DaeNetns) setupIPv6Datapath() (err error) {
	// ip -6 a a fe80::ecee:eeff:feee:eeee/128 dev dae0 scope link
	// fe80::ecee:eeff:feee:eeee/128 is the link-local address used for L2 NDP addressing
	if err = netlink.AddrAdd(ns.dae0, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("fe80::ecee:eeff:feee:eeee"),
			Mask: net.CIDRMask(128, 128),
		},
	}); err != nil {
		return fmt.Errorf("failed to add v6 addr to dae0: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// (ip net e daens) ip -6 r a default via fe80::ecee:eeff:feee:eeee dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:        net.ParseIP("fe80::ecee:eeff:feee:eeee"),
	}); err != nil {
		return fmt.Errorf("failed to add v6 route to dae0peer: %v", err)
	}
	// (ip net e daens) ip n r fe80::ecee:eeff:feee:eeee dev dae0peer lladdr $mac_dae0 nud permanent
	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("fe80::ecee:eeff:feee:eeee"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("failed to add neigh to dae0peer: %v", err)
	}
	return
}

func DeleteNamedNetns(name string) error {
	namedPath := path.Join("/run/netns", name)
	var errs []error
	if err := unix.Unmount(namedPath, unix.MNT_DETACH|unix.MNT_FORCE); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
		errs = append(errs, fmt.Errorf("unmount %s: %w", namedPath, err))
	}
	if err := os.Remove(namedPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove %s: %w", namedPath, err))
	}
	return errors.Join(errs...)
}

func DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	}
	if err = netlink.LinkDel(link); err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	}
	return nil
}
