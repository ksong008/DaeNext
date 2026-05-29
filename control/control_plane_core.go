/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1
var coreFlip = 0

var activeTcxLinks sync.Map

type trackedTcxLink struct {
	link ciliumLink.Link
	once sync.Once
	err  error
}

func (l *trackedTcxLink) Close() error {
	l.once.Do(func() {
		if l.link != nil {
			l.err = l.link.Close()
		}
	})
	return l.err
}

type controlPlaneCore struct {
	mu sync.Mutex

	log             *logrus.Logger
	deferFuncs      []func() error
	bpf             *bpfObjects
	domainRouting   *domainRoutingTracker
	outboundId2Name map[uint8]string

	connectivityHelperMu sync.Mutex
	connectivityHelper   *rustConnectivityHelper
	domainHelperMu       sync.Mutex
	domainHelper         *rustDomainRoutingHelper

	kernelVersion *internal.Version

	flip       int
	isReload   bool
	bpfEjected bool

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager
	netns  *DaeNetns

	attachBackendMu sync.RWMutex
	attachBackends  map[string]tcAttachBackend
}

type tcAttachBackend string

const (
	tcAttachBackendAuto tcAttachBackend = "auto"
	tcAttachBackendTc   tcAttachBackend = "tc"
	tcAttachBackendTcx  tcAttachBackend = "tcx"
)

func currentTcAttachBackend() tcAttachBackend {
	if nativeEbpfExplicitlyDisabled(os.Getenv("DAE_RUST_NATIVE_EBPF")) {
		return tcAttachBackendTc
	}
	for _, envName := range []string{"DAE_RUST_NATIVE_EBPF_BACKEND", "DAE_NATIVE_EBPF_BACKEND"} {
		if backend := parseTcAttachBackend(os.Getenv(envName)); backend != "" {
			return backend
		}
	}
	return tcAttachBackendAuto
}

func nativeEbpfExplicitlyDisabled(value string) bool {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "0", "false", "off", "no":
		return true
	default:
		return false
	}
}

func parseTcAttachBackend(value string) tcAttachBackend {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", "auto":
		return tcAttachBackendAuto
	case "tcx":
		return tcAttachBackendTcx
	case "tc", "tc-netlink", "tc_netlink", "tc-command-fallback", "tc_command_fallback":
		return tcAttachBackendTc
	default:
		return ""
	}
}

func tcxAnchorForPriority(priority uint16) ciliumLink.Anchor {
	if priority <= 1 {
		return ciliumLink.Head()
	}
	return ciliumLink.Tail()
}

func tcxAttachTypeForParent(parent uint32) (ebpf.AttachType, bool) {
	switch parent {
	case netlink.HANDLE_MIN_INGRESS:
		return ebpf.AttachTCXIngress, true
	case netlink.HANDLE_MIN_EGRESS:
		return ebpf.AttachTCXEgress, true
	default:
		return ebpf.AttachNone, false
	}
}

func tcxLinkKey(ifname string, filter *netlink.BpfFilter, attachType ebpf.AttachType) string {
	return fmt.Sprintf("%s:%d:%d:%s", ifname, filter.LinkIndex, attachType, filter.Name)
}

func summarizeTcAttachBackends(backends []tcAttachBackend) string {
	hasTCX := false
	hasTC := false
	for _, backend := range backends {
		switch backend {
		case tcAttachBackendTcx:
			hasTCX = true
		case tcAttachBackendTc:
			hasTC = true
		}
	}
	switch {
	case hasTCX && hasTC:
		return "tcx+tc"
	case hasTCX:
		return "tcx"
	default:
		return "tc"
	}
}

func newControlPlaneCore(log *logrus.Logger,
	bpf *bpfObjects,
	outboundId2Name map[uint8]string,
	kernelVersion *internal.Version,
	netns *DaeNetns,
	isReload bool,
) *controlPlaneCore {
	if isReload {
		coreFlip = coreFlip&1 ^ 1
	}
	var deferFuncs []func() error
	if !isReload {
		deferFuncs = append(deferFuncs, bpf.Close)
	}
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager(log)
	deferFuncs = append(deferFuncs, ifmgr.Close)
	return &controlPlaneCore{
		log:             log,
		deferFuncs:      deferFuncs,
		bpf:             bpf,
		domainRouting:   newDomainRoutingTracker(),
		outboundId2Name: outboundId2Name,
		kernelVersion:   kernelVersion,
		flip:            coreFlip,
		isReload:        isReload,
		bpfEjected:      false,
		ifmgr:           ifmgr,
		closed:          closed,
		close:           toClose,
		netns:           netns,
		attachBackends:  make(map[string]tcAttachBackend),
	}
}

func (c *controlPlaneCore) Flip() {
	coreFlip = coreFlip&1 ^ 1
}
func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	if e := c.closeRustConnectivityHelper(); e != nil {
		err = e
	}
	if e := c.closeRustDomainRoutingHelper(); e != nil {
		if err != nil {
			err = fmt.Errorf("%w; %v", err, e)
		} else {
			err = e
		}
	}
	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			// Combine errors.
			if err != nil {
				err = fmt.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	c.close()
	return err
}

func (c *controlPlaneCore) getRustConnectivityHelper() *rustConnectivityHelper {
	c.connectivityHelperMu.Lock()
	defer c.connectivityHelperMu.Unlock()
	if c.connectivityHelper == nil {
		c.connectivityHelper = newRustConnectivityHelper()
	}
	return c.connectivityHelper
}

func (c *controlPlaneCore) closeRustConnectivityHelper() error {
	c.connectivityHelperMu.Lock()
	helper := c.connectivityHelper
	c.connectivityHelper = nil
	c.connectivityHelperMu.Unlock()
	if helper == nil {
		return nil
	}
	return helper.Close()
}

func (c *controlPlaneCore) getRustDomainRoutingHelper() *rustDomainRoutingHelper {
	c.domainHelperMu.Lock()
	defer c.domainHelperMu.Unlock()
	if c.domainHelper == nil {
		c.domainHelper = newRustDomainRoutingHelper()
	}
	return c.domainHelper
}

func (c *controlPlaneCore) closeRustDomainRoutingHelper() error {
	c.domainHelperMu.Lock()
	helper := c.domainHelper
	c.domainHelper = nil
	c.domainHelperMu.Unlock()
	if helper == nil {
		return nil
	}
	return helper.Close()
}

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, err
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, err
	}
	if features["tx-checksum-ip-generic"] {
		ifParams.TxL4CksmIp4Offload = true
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["tx-checksum-ipv4"] {
		ifParams.TxL4CksmIp4Offload = true
	}
	if features["tx-checksum-ipv6"] {
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["rx-checksum"] {
		ifParams.RxCksmOffload = true
	}
	switch {
	case regexp.MustCompile(`^docker\d+$`).MatchString(link.Attrs().Name):
		ifParams.UseNonstandardOffloadAlgorithm = true
	default:
	}
	return ifParams, nil
}

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		c.log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

func addClsactQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) addQdisc(ifname string) error {
	return addClsactQdisc(ifname)
}

func (c *controlPlaneCore) delQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("cannot add clsact qdisc: %w", err)
		}
	}
	return nil
}

func delBpfFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}

	var errs []error
	if err := netlink.FilterDel(filter); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}

	link, err := netlink.LinkByIndex(filter.LinkIndex)
	if err != nil {
		if len(errs) == 0 && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	filters, err := netlink.FilterList(link, filter.Parent)
	if err != nil {
		if len(errs) == 0 && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	for _, existing := range filters {
		bpfFilter, ok := existing.(*netlink.BpfFilter)
		if !ok || !sameBpfFilterIdentity(filter, bpfFilter) {
			continue
		}
		if err := netlink.FilterDel(bpfFilter); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func sameBpfFilterIdentity(want *netlink.BpfFilter, got *netlink.BpfFilter) bool {
	if want == nil || got == nil {
		return false
	}
	if want.FilterAttrs.Handle != 0 {
		return got.FilterAttrs.Handle == want.FilterAttrs.Handle
	}
	return want.Name != "" && got.Name == want.Name
}

func (c *controlPlaneCore) attachBackend() string {
	c.attachBackendMu.RLock()
	defer c.attachBackendMu.RUnlock()

	backends := make([]tcAttachBackend, 0, len(c.attachBackends))
	for _, backend := range c.attachBackends {
		backends = append(backends, backend)
	}
	return summarizeTcAttachBackends(backends)
}

func (c *controlPlaneCore) recordAttachBackend(filter *netlink.BpfFilter, backend tcAttachBackend) {
	c.attachBackendMu.Lock()
	defer c.attachBackendMu.Unlock()
	if c.attachBackends == nil {
		c.attachBackends = make(map[string]tcAttachBackend)
	}
	c.attachBackends[filter.Name] = backend
}

func (c *controlPlaneCore) attachIfaceFilter(ifname string, filter *netlink.BpfFilter, program *ebpf.Program) error {
	return c.attachIfaceFilterWithTcOps(
		ifname,
		"",
		filter,
		program,
		func() error {
			return netlink.FilterAdd(filter)
		},
		func() error {
			if err := delBpfFilter(filter); err != nil {
				return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filter.Name, err)
			}
			return nil
		},
	)
}

func (c *controlPlaneCore) attachIfaceFilterInNetns(daens *DaeNetns, ifname string, filter *netlink.BpfFilter, program *ebpf.Program) error {
	return daens.With(func() error {
		return c.attachIfaceFilterWithTcOps(
			ifname,
			NsName,
			filter,
			program,
			func() error {
				return netlink.FilterAdd(filter)
			},
			func() error {
				return daens.With(func() error {
					if err := delBpfFilter(filter); err != nil {
						return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filter.Name, err)
					}
					return nil
				})
			},
		)
	})
}

func (c *controlPlaneCore) attachIfaceFilterWithTcOps(ifname string, netnsName string, filter *netlink.BpfFilter, program *ebpf.Program, tcAdd func() error, tcDel func() error) error {
	backend := currentTcAttachBackend()
	if err := c.attachIfaceFilterViaRustAya(ifname, netnsName, filter, backend, tcDel); err == nil {
		return nil
	} else {
		c.log.WithError(err).Debugf("Rust/Aya TC attach failed for %s on %s; falling back to Go attach path", filter.Name, ifname)
	}
	if backend == tcAttachBackendTc {
		return c.attachIfaceFilterViaTc(ifname, filter, "tc", tcAdd, tcDel)
	}

	attachType, ok := tcxAttachTypeForParent(filter.Parent)
	if !ok {
		return fmt.Errorf("unsupported tcx parent %#x for filter %s", filter.Parent, filter.Name)
	}
	linkKey := tcxLinkKey(ifname, filter, attachType)
	if old, ok := activeTcxLinks.LoadAndDelete(linkKey); ok {
		if err := old.(*trackedTcxLink).Close(); err != nil {
			c.log.Warnf("close stale TCX link before reattach for %s on %s: %v", filter.Name, ifname, err)
		}
	}
	tcxLink, err := ciliumLink.AttachTCX(ciliumLink.TCXOptions{
		Interface: filter.LinkIndex,
		Program:   program,
		Attach:    attachType,
		Anchor:    tcxAnchorForPriority(filter.Priority),
	})
	if err == nil {
		c.log.Infof("Bind %s via TCX on %s", filter.Name, ifname)
		c.recordAttachBackend(filter, tcAttachBackendTcx)
		tracked := &trackedTcxLink{link: tcxLink}
		activeTcxLinks.Store(linkKey, tracked)
		if err := tcDel(); err != nil {
			c.log.Warnf("cleanup stale tc filter after TCX attach for %s on %s: %v", filter.Name, ifname, err)
		}
		c.deferFuncs = append(c.deferFuncs, func() error {
			if current, ok := activeTcxLinks.Load(linkKey); ok && current == tracked {
				activeTcxLinks.Delete(linkKey)
			}
			if err := tracked.Close(); err != nil {
				return fmt.Errorf("TCXLinkClose(%v:%v): %w", ifname, filter.Name, err)
			}
			return nil
		})
		return nil
	}
	if backend == tcAttachBackendTcx {
		return fmt.Errorf("cannot attach ebpf object to filter %s via tcx: %w", filter.Name, err)
	}

	c.log.Warnf("TCX attach failed for %s on %s, falling back to tc: %v", filter.Name, ifname, err)
	return c.attachIfaceFilterViaTc(ifname, filter, "tc fallback", tcAdd, tcDel)
}

func (c *controlPlaneCore) attachIfaceFilterViaTc(ifname string, filter *netlink.BpfFilter, backend string, tcAdd func() error, tcDel func() error) error {
	if err := tcAdd(); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter %s via %s: %w", filter.Name, backend, err)
	}
	c.log.Infof("Bind %s via TC on %s", filter.Name, ifname)
	c.recordAttachBackend(filter, tcAttachBackendTc)
	c.deferFuncs = append(c.deferFuncs, func() error {
		return tcDel()
	})
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		if err := c._bindLan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindLan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			c.log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = CheckIpforward(ifname); err != nil {
		return err
	}
	if err = CheckSendRedirects(ifname); err != nil {
		return err
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	// Insert filters.
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be behind of WAN's
			Priority: 2,
		},
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	var ingressProgram *ebpf.Program
	if linkHdrLen > 0 {
		ingressProgram = c.bpf.bpfPrograms.TproxyLanIngressL2
		filterIngress.Fd = ingressProgram.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		ingressProgram = c.bpf.bpfPrograms.TproxyLanIngressL3
		filterIngress.Fd = ingressProgram.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	// Remove and add.
	_ = delBpfFilter(filterIngress)
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = delBpfFilter(filterIngressFlipped)
	}
	if err := c.attachIfaceFilter(ifname, filterIngress, ingressProgram); err != nil {
		return err
	}

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	var egressProgram *ebpf.Program
	if linkHdrLen > 0 {
		egressProgram = c.bpf.bpfPrograms.TproxyLanEgressL2
		filterEgress.Fd = egressProgram.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		egressProgram = c.bpf.bpfPrograms.TproxyLanEgressL3
		filterEgress.Fd = egressProgram.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	// Remove and add.
	_ = delBpfFilter(filterEgress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = delBpfFilter(filterEgressFlipped)
	}
	if err := c.attachIfaceFilter(ifname, filterEgress, egressProgram); err != nil {
		return err
	}

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	/// Set-up SrcPidMapper.
	/// Attach programs to support pname routing.
	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	if err := c.setupSkPidMonitorViaRustAya(cgroupPath); err == nil {
		return nil
	} else {
		c.log.WithError(err).Debugln("Rust/Aya cgroup pname monitor attach failed; falling back to Go AttachCgroup")
	}
	return c.setupSkPidMonitorViaGo(cgroupPath)
}

func (c *controlPlaneCore) setupSkPidMonitorViaGo(cgroupPath string) error {
	// Bind cg programs
	type cgProg struct {
		Name   string
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	cgProgs := []cgProg{
		{Prog: c.bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Prog: c.bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Prog: c.bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Prog: c.bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Prog: c.bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Prog: c.bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, prog := range cgProgs {
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			return fmt.Errorf("AttachCgroup: %v: %w", prog.Prog.String(), err)
		}
		c.deferFuncs = append(c.deferFuncs, func() error {
			if err := attached.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		})
	}
	return nil
}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if err := c._bindWan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindWan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			c.log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return fmt.Errorf("cannot bind to loopback interface")
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}

	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	/// Set-up WAN ingress/egress TC programs.
	// Insert TC filters
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	var egressProgram *ebpf.Program
	if linkHdrLen > 0 {
		egressProgram = c.bpf.bpfPrograms.TproxyWanEgressL2
		filterEgress.Fd = egressProgram.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		egressProgram = c.bpf.bpfPrograms.TproxyWanEgressL3
		filterEgress.Fd = egressProgram.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	_ = delBpfFilter(filterEgress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = delBpfFilter(filterEgressFlipped)
	}
	if err := c.attachIfaceFilter(ifname, filterEgress, egressProgram); err != nil {
		return err
	}

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	var ingressProgram *ebpf.Program
	if linkHdrLen > 0 {
		ingressProgram = c.bpf.bpfPrograms.TproxyWanIngressL2
		filterIngress.Fd = ingressProgram.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		ingressProgram = c.bpf.bpfPrograms.TproxyWanIngressL3
		filterIngress.Fd = ingressProgram.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	_ = delBpfFilter(filterIngress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = delBpfFilter(filterIngressFlipped)
	}
	if err := c.attachIfaceFilter(ifname, filterIngress, ingressProgram); err != nil {
		return err
	}

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := c.netns
	if daens == nil {
		return fmt.Errorf("dae netns is not initialized")
	}

	// tproxy_dae0peer_ingress@eth0 at dae netns.
	daens.With(func() error {
		return c.addQdisc(daens.Dae0Peer().Attrs().Name)
	})
	filterDae0peerIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0Peer().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	daens.With(func() error {
		return delBpfFilter(filterDae0peerIngress)
	})
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterDae0peerIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		daens.With(func() error {
			return delBpfFilter(filterIngressFlipped)
		})
	}
	if err = c.attachIfaceFilterInNetns(
		daens,
		daens.Dae0Peer().Attrs().Name,
		filterDae0peerIngress,
		c.bpf.bpfPrograms.TproxyDae0peerIngress,
	); err != nil {
		return err
	}

	// tproxy_dae0_ingress@dae0 at host netns
	c.addQdisc(daens.Dae0().Attrs().Name)
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0Ingress.FD(),
		Name:         consts.AppName + "_dae0_ingress",
		DirectAction: true,
	}
	_ = delBpfFilter(filterDae0Ingress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterDae0Ingress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = delBpfFilter(filterEgressFlipped)
	}
	if err := c.attachIfaceFilter(
		daens.Dae0().Attrs().Name,
		filterDae0Ingress,
		c.bpf.bpfPrograms.TproxyDae0Ingress,
	); err != nil {
		return err
	}
	return
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *controlPlaneCore) BatchUpdateDomainRouting(cache *DnsCache) error {
	if c.domainRouting != nil && cache != nil && cache.RouteOwnerKey != "" {
		snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
		if err != nil {
			return err
		}
		return c.domainRouting.syncOwner(c.bpf.DomainRoutingMap, cache.RouteOwnerKey, snapshot, c.updateDomainRoutingMapViaRustHelper)
	}

	ips := cache.cachedIPs()
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	var keys [][4]uint32
	var vals []bpfDomainRouting
	var updates []rustDomainRoutingMapUpdate
	for _, ip := range ips {
		ip6 := ip.As16()
		key := common.Ipv6ByteSliceToUint32Array(ip6[:])
		keys = append(keys, key)
		r := bpfDomainRouting{}
		if len(cache.DomainBitmap) != len(r.Bitmap) {
			return fmt.Errorf("domain bitmap length not sync with kern program")
		}
		copy(r.Bitmap[:], cache.DomainBitmap)
		vals = append(vals, r)
		updates = append(updates, rustDomainRoutingMapUpdate{
			Key:    key,
			Bitmap: r.Bitmap,
		})
	}
	if err := c.updateDomainRoutingMapViaRustHelper(c.bpf.DomainRoutingMap, updates, nil); err == nil {
		return nil
	}
	if _, err := BpfMapBatchUpdate(c.bpf.DomainRoutingMap, keys, vals, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return err
	}
	return nil
}

// BatchRemoveDomainRouting remove bpf map domain_routing.
func (c *controlPlaneCore) BatchRemoveDomainRouting(cache *DnsCache) error {
	if c.domainRouting != nil && cache != nil && cache.RouteOwnerKey != "" {
		return c.domainRouting.syncOwner(c.bpf.DomainRoutingMap, cache.RouteOwnerKey, domainRoutingOwnerSnapshot{}, c.updateDomainRoutingMapViaRustHelper)
	}

	ips := cache.cachedIPs()
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	var keys [][4]uint32
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
	}
	if err := c.updateDomainRoutingMapViaRustHelper(c.bpf.DomainRoutingMap, nil, keys); err == nil {
		return nil
	}
	if _, err := BpfMapBatchDelete(c.bpf.DomainRoutingMap, keys); err != nil {
		return err
	}
	return nil
}

// EjectBpf will resect bpf from destroying life-cycle of control plane core.
func (c *controlPlaneCore) EjectBpf() *bpfObjects {
	if !c.bpfEjected && !c.isReload {
		c.deferFuncs = c.deferFuncs[1:]
	}
	c.bpfEjected = true
	return c.bpf
}

// InjectBpf will inject bpf back.
func (c *controlPlaneCore) InjectBpf(bpf *bpfObjects) {
	if c.bpfEjected {
		c.bpfEjected = false
		c.deferFuncs = append([]func() error{bpf.Close}, c.deferFuncs...)
	}
	return
}
