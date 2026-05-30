/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

var ErrControlPlaneNotInit = errors.New("control plane doesn't init yet")

var defaultCheckNetworkLinks = []string{
	"http://edge.microsoft.com/captiveportal/generate_204",
	"http://www.gstatic.com/generate_204",
	"http://www.qualcomm.cn/generate_204",
}

var snapshotRuntimeStats = control.SnapshotRuntimeStats
var postStartupGC = runtime.GC
var currentHeapAllocBytes = func() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.HeapAlloc
}

const (
	subscriptionResolveConcurrency = 6
	postStartupGCMinInterval       = 5 * time.Second
	postStartupGCHeapGrowthBytes   = 64 << 20
)

type Options struct {
	SubscriptionConfigDir string
	CheckNetworkLinks     []string
	OnReady               func()

	// Suppresses the misleading empty-config warnings emitted by the first
	// control-plane construction. This is only for daed's bootstrap
	// EmptyConfig; reloads and real empty configs must still warn.
	SuppressInitialEmptyConfigWarnings bool
}

type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

type RuntimeOverview struct {
	UpdatedAt             time.Time
	UploadRate            uint64
	DownloadRate          uint64
	UploadTotal           uint64
	DownloadTotal         uint64
	ActiveConnections     int
	UDPSessions           int
	UDPTaskQueues         int
	UDPTaskDropTotal      uint64
	PacketSnifferSessions int
	RSSBytes              uint64
	HeapAllocBytes        uint64
	Goroutines            int
	control.DnsObservabilityStats
	Samples []RuntimeTrafficSample
}

type reloadMessage struct {
	Config           *config.Config
	Callback         chan<- error
	AbortConnections bool
	ServeResult      *serveResult
}

type serveResult struct {
	listener *control.Listener
	err      error
}

type Engine struct {
	mu sync.RWMutex

	controlPlane *control.ControlPlane
	onceWaiting  sync.Once

	reloadCh chan *reloadMessage
	exitCh   chan struct{}

	subscriptionConfigDir              string
	checkNetworkLinks                  []string
	onReady                            func()
	suppressInitialEmptyConfigWarnings bool
	httpTransport                      *http.Transport
	netns                              *control.DaeNetns
	udpEndpointPool                    *control.UdpEndpointPool
	udpTaskPool                        *control.UdpTaskPool
	anyfromPool                        *control.AnyfromPool
	fallbackDNS                        netip.AddrPort
	bootstrapDirect                    netproxy.Dialer
	bootstrapDirectFullcone            netproxy.Dialer
	logMu                              sync.RWMutex
	log                                *logrus.Logger
	lastPostStartupGC                  time.Time
	lastPostStartupHeapAlloc           uint64
}

func New(opts Options) *Engine {
	checkLinks := append([]string(nil), opts.CheckNetworkLinks...)
	if len(checkLinks) == 0 {
		checkLinks = append([]string(nil), defaultCheckNetworkLinks...)
	}
	netns := control.NewDaeNetns(nil)
	e := &Engine{
		reloadCh:                           make(chan *reloadMessage),
		subscriptionConfigDir:              opts.SubscriptionConfigDir,
		checkNetworkLinks:                  checkLinks,
		onReady:                            opts.OnReady,
		suppressInitialEmptyConfigWarnings: opts.SuppressInitialEmptyConfigWarnings,
		netns:                              netns,
		udpEndpointPool:                    control.NewUdpEndpointPool(),
		udpTaskPool:                        control.NewUdpTaskPool(),
		anyfromPool:                        control.NewAnyfromPoolWithNetns(netns),
	}
	e.httpTransport = &http.Transport{
		DialContext:           e.routeAwareDialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		DisableKeepAlives:     true,
		DisableCompression:    false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
	return e
}

func (e *Engine) SetLogLevel(level logrus.Level) {
	e.logMu.RLock()
	log := e.log
	e.logMu.RUnlock()
	if log != nil {
		log.SetLevel(level)
	}
}

func (e *Engine) setRuntimeLogger(log *logrus.Logger) {
	e.logMu.Lock()
	e.log = log
	e.logMu.Unlock()
}

func (e *Engine) Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string, disableTimestamp bool, dry bool) (err error) {
	startupStartedAt := time.Now()
	e.mu.Lock()
	e.exitCh = make(chan struct{})
	e.mu.Unlock()
	e.setRuntimeLogger(log)
	runDone := make(chan struct{})
	defer e.closeExitCh()
	defer close(runDone)
	defer e.setRuntimeLogger(nil)
	defer func() {
		e.setControlPlane(nil)
		if ns := e.netns; ns != nil {
			if closeErr := ns.Close(); closeErr != nil {
				log.WithError(closeErr).Warnln("Failed to close dae netns")
			}
		}
		if e.udpEndpointPool != nil {
			_ = e.udpEndpointPool.Flush()
		}
		if e.udpTaskPool != nil {
			e.udpTaskPool.Flush()
		}
		if e.anyfromPool != nil {
			_ = e.anyfromPool.Flush()
		}
	}()

	if dry {
		log.Infoln("Dry run in api-only mode")
	dryLoop:
		for msg := range e.reloadCh {
			switch msg {
			case nil:
				break dryLoop
			default:
				msg.Callback <- nil
			}
		}
		return nil
	}

	controlPlaneStartedAt := time.Now()
	current, err := e.newControlPlane(log, nil, nil, conf, externGeoDataDirs, e.suppressInitialEmptyConfigWarnings)
	logStartupPhase(log, "control-plane.create.total", controlPlaneStartedAt, err)
	if err != nil {
		return err
	}
	e.setControlPlane(current)
	e.maybePostStartupGC(log, true)

	listenReadyStartedAt := time.Now()
	sendServeResult := func(result serveResult) {
		select {
		case e.reloadCh <- &reloadMessage{ServeResult: &result}:
		case <-runDone:
		}
	}
	startListenAndServe := func(plane *control.ControlPlane, port uint16, log *logrus.Logger) {
		readyChan := make(chan bool, 1)
		go func() {
			ready := <-readyChan
			if !ready {
				logStartupPhase(log, "listen.ready", listenReadyStartedAt, errors.New("listener did not become ready"))
				return
			}
			logStartupPhase(log, "listen.ready", listenReadyStartedAt, nil)
			logStartupPhase(log, "startup.total", startupStartedAt, nil)
			log.Infoln("Ready")
			if e.onReady != nil {
				e.onReady()
			}
		}()
		go func() {
			var listener *control.Listener
			serveErr := e.netns.With(func() error {
				var err error
				listener, err = plane.ListenAndServe(readyChan, port)
				return err
			})
			if serveErr != nil {
				log.Errorln("ListenAndServe:", serveErr)
				select {
				case readyChan <- false:
				default:
				}
			}
			sendServeResult(serveResult{listener: listener, err: serveErr})
		}()
	}
	startServe := func(plane *control.ControlPlane, listener *control.Listener, log *logrus.Logger) (bool, <-chan error) {
		readyChan := make(chan bool, 1)
		serveErrCh := make(chan error, 1)
		go func() {
			serveErr := plane.Serve(readyChan, listener)
			if serveErr != nil {
				log.Errorln("Serve:", serveErr)
			}
			serveErrCh <- serveErr
			sendServeResult(serveResult{listener: listener, err: serveErr})
		}()
		return <-readyChan, serveErrCh
	}
	startListenAndServe(current, conf.Global.TproxyPort, log)

	reloading := false
	var reloadErr error
	var callback chan<- error
	var runErr error

loop:
	for msg := range e.reloadCh {
		switch {
		case msg == nil:
			if reloading {
				reloadErr = errors.Join(reloadErr, errors.New("runtime stopped during reload"))
				if callback != nil {
					callback <- reloadErr
				}
			}
			break loop
		case msg.ServeResult != nil:
			result := msg.ServeResult
			if reloading {
				if result.err != nil {
					reloadErr = errors.Join(reloadErr, fmt.Errorf("previous control plane serve: %w", result.err))
				}
				if result.listener == nil {
					if reloadErr == nil {
						reloadErr = errors.New("listener unavailable after reload")
					}
					if callback != nil {
						callback <- reloadErr
					}
					runErr = reloadErr
					break loop
				}
				reloading = false
				log.Warnln("[Reload] Serve")
				ready, serveErrCh := startServe(current, result.listener, log)
				if !ready {
					serveErr := <-serveErrCh
					if serveErr == nil {
						serveErr = errors.New("control plane serve failed before ready")
					}
					reloadErr = errors.Join(reloadErr, fmt.Errorf("reload serve: %w", serveErr))
					if callback != nil {
						callback <- reloadErr
					}
					runErr = reloadErr
					break loop
				}
				log.Warnln("[Reload] Finished")
				if callback != nil {
					callback <- reloadErr
				}
				continue
			}
			if result.err != nil {
				runErr = fmt.Errorf("control plane serve: %w", result.err)
			}
			break loop
		default:
			log.Warnln("[Reload] Received reload signal; prepare to reload")
			newConf := msg.Config
			oldLogOutput := log.Out
			oldLogHooks := cloneLogHooks(log.Hooks)
			log = logrus.New()
			log.Hooks = oldLogHooks
			logger.SetLogger(log, newConf.Global.LogLevel, disableTimestamp, nil)
			logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
			log.SetOutput(oldLogOutput)
			logrus.SetOutput(oldLogOutput)
			e.setRuntimeLogger(log)

			obj := current.EjectBpf()
			var dnsCache map[string]*control.DnsCache
			if reflect.DeepEqual(conf.Dns, newConf.Dns) {
				dnsCache = current.SnapshotDnsCache()
			}
			shouldStopOldDNSListener := strings.TrimSpace(conf.Dns.Bind) != "" &&
				strings.TrimSpace(newConf.Dns.Bind) != "" &&
				strings.TrimSpace(conf.Dns.Bind) == strings.TrimSpace(newConf.Dns.Bind)
			oldDNSListenerStopped := false
			if shouldStopOldDNSListener {
				if err := current.StopDNSListener(); err != nil {
					log.Warnf("[Reload] Failed to stop old DNS listener: %v", err)
				} else {
					oldDNSListenerStopped = true
				}
			}

			log.Warnln("[Reload] Load new control plane")
			next, nextErr := e.newControlPlane(log, obj, dnsCache, newConf, externGeoDataDirs, false)
			if nextErr != nil {
				reloadErr = nextErr
				log.WithField("err", nextErr).Errorln("[Reload] Failed to reload; try to roll back configuration")
				next, nextErr = e.newControlPlane(log, obj, dnsCache, conf, externGeoDataDirs, false)
				if nextErr != nil {
					if oldDNSListenerStopped {
						if restartErr := current.StartDNSListener(); restartErr != nil {
							log.WithError(restartErr).Errorln("[Reload] Failed to restart old DNS listener after rollback failure")
						} else {
							log.Warnln("[Reload] Restored old DNS listener after rollback failure")
						}
					}
					obj.Close()
					current.Close()
					log.WithField("err", nextErr).Fatalln("[Reload] Failed to roll back configuration")
				}
				newConf = conf
				log.Errorln("[Reload] Last reload failed; rolled back configuration")
			} else {
				reloadErr = nil
				log.Warnln("[Reload] Stopped old control plane")
			}

			next.InjectBpf(obj)
			old := current
			current = next
			e.setControlPlane(next)
			conf = newConf
			reloading = true
			callback = msg.Callback

			if msg.AbortConnections {
				old.AbortConnections()
			}
			if closeErr := old.Close(); closeErr != nil {
				log.WithError(closeErr).Warnln("[Reload] Failed to close old control plane")
				reloadErr = errors.Join(reloadErr, fmt.Errorf("close old control plane: %w", closeErr))
			}
			control.FlushReloadScopedResources(e.udpEndpointPool, e.anyfromPool, e.udpTaskPool)
			old = nil
			e.maybePostStartupGC(log, false)
		}
	}

	if current != nil {
		if err := current.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close control plane: %w", err))
		}
	}
	return runErr
}

func (e *Engine) Reload(conf *config.Config) error {
	return e.ReloadWithAbort(conf, false)
}

func (e *Engine) ReloadWithContext(ctx context.Context, conf *config.Config) error {
	return e.ReloadWithAbortContext(ctx, conf, false)
}

func (e *Engine) ReloadWithAbort(conf *config.Config, abortConnections bool) error {
	return e.ReloadWithAbortContext(context.Background(), conf, abortConnections)
}

func (e *Engine) ReloadWithAbortContext(ctx context.Context, conf *config.Config, abortConnections bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ch := make(chan error, 1)
	msg := &reloadMessage{
		Config:           conf,
		Callback:         ch,
		AbortConnections: abortConnections,
	}
	select {
	case e.reloadCh <- msg:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) Stop(timeout time.Duration) error {
	if timeout <= 0 {
		e.reloadCh <- nil
		if exitCh := e.currentExitCh(); exitCh != nil {
			<-exitCh
		}
		return nil
	}
	select {
	case e.reloadCh <- nil:
	case <-time.After(timeout):
		return errors.New("timeout sending dae shutdown signal")
	}
	exitCh := e.currentExitCh()
	if exitCh == nil {
		return nil
	}
	select {
	case <-exitCh:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout waiting for dae shutdown")
	}
}

func (e *Engine) ControlPlane() (*control.ControlPlane, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.controlPlane == nil {
		return nil, ErrControlPlaneNotInit
	}
	return e.controlPlane, nil
}

func (e *Engine) NetnsLinkMode() string {
	e.mu.RLock()
	netns := e.netns
	e.mu.RUnlock()
	if netns == nil {
		return ""
	}
	return netns.LinkMode()
}

func (e *Engine) AttachBackend() string {
	ctl, err := e.ControlPlane()
	if err != nil {
		return "tc"
	}
	return ctl.AttachBackend()
}

func (e *Engine) GetRuntimeOverview(windowSec int, maxPoints int) (*RuntimeOverview, error) {
	activeTCPConnections := 0
	ctl, err := e.ControlPlane()
	if err != nil {
		if !errors.Is(err, ErrControlPlaneNotInit) {
			return nil, err
		}
	} else {
		activeTCPConnections = ctl.ActiveTCPConnections()
	}

	udpSessions := 0
	if e.udpEndpointPool != nil {
		udpSessions = e.udpEndpointPool.Count()
	}
	snapshot := snapshotRuntimeStats(activeTCPConnections, udpSessions, windowSec, maxPoints)
	udpTaskQueues := snapshot.UDPTaskQueues
	udpTaskDropTotal := snapshot.UDPTaskDropTotal
	if e.udpTaskPool != nil {
		udpTaskQueues = e.udpTaskPool.Count()
		udpTaskDropTotal = e.udpTaskPool.DropCount()
	}
	samples := make([]RuntimeTrafficSample, 0, len(snapshot.Samples))
	for _, sample := range snapshot.Samples {
		samples = append(samples, RuntimeTrafficSample{
			Timestamp:    sample.Timestamp,
			UploadRate:   sample.UploadRate,
			DownloadRate: sample.DownloadRate,
		})
	}

	return &RuntimeOverview{
		UpdatedAt:             snapshot.UpdatedAt,
		UploadRate:            snapshot.UploadRate,
		DownloadRate:          snapshot.DownloadRate,
		UploadTotal:           snapshot.UploadTotal,
		DownloadTotal:         snapshot.DownloadTotal,
		ActiveConnections:     snapshot.ActiveConnections,
		UDPSessions:           snapshot.UDPSessions,
		UDPTaskQueues:         udpTaskQueues,
		UDPTaskDropTotal:      udpTaskDropTotal,
		PacketSnifferSessions: snapshot.PacketSnifferSessions,
		RSSBytes:              snapshot.RSSBytes,
		HeapAllocBytes:        snapshot.HeapAllocBytes,
		Goroutines:            snapshot.Goroutines,
		DnsObservabilityStats: snapshot.DnsObservabilityStats,
		Samples:               samples,
	}, nil
}

func (e *Engine) HTTPTransport() http.RoundTripper {
	return e.httpTransport
}

func (e *Engine) TryHTTPTransport() (http.RoundTripper, bool) {
	if _, err := e.ControlPlane(); err != nil {
		return nil, false
	}
	return e.HTTPTransport(), true
}

func (e *Engine) CacheStats() CacheStats {
	ctl, err := e.ControlPlane()
	if err != nil {
		return CacheStats{}
	}
	return ctl.CacheStats()
}

func (e *Engine) TriggerLatencyChecks() {
	ctl, err := e.ControlPlane()
	if err != nil {
		return
	}
	ctl.TriggerLatencyChecks()
}

func (e *Engine) SnapshotNodeLatencies() []NodeLatencySnapshot {
	ctl, err := e.ControlPlane()
	if err != nil {
		return nil
	}
	return ctl.SnapshotNodeLatencies()
}

func (e *Engine) IsControlPlaneNotInit(err error) bool {
	return errors.Is(err, ErrControlPlaneNotInit)
}

func (e *Engine) routeAwareDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	domain, dest, err := routeAwareDialTarget(host, rawPort)
	if err != nil {
		return nil, err
	}
	ctl, err := e.ControlPlane()
	if err != nil {
		return nil, err
	}
	conn, err := ctl.RouteDialTcp(&control.RouteDialParam{
		Ctx:         ctx,
		Outbound:    consts.OutboundControlPlaneRouting,
		Domain:      domain,
		Mac:         [6]uint8{},
		ProcessName: [16]uint8{},
		Src:         netip.MustParseAddrPort("0.0.0.0:0"),
		Dest:        dest,
		Mark:        0,
	})
	if err != nil {
		return nil, err
	}
	return &netproxy.FakeNetConn{Conn: conn, LAddr: nil, RAddr: nil}, nil
}

func routeAwareDialTarget(host string, rawPort string) (domain string, dest netip.AddrPort, err error) {
	if strings.TrimSpace(host) == "" {
		return "", netip.AddrPort{}, fmt.Errorf("empty host")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return "", netip.AddrPort{}, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return "", netip.AddrPortFrom(addr, uint16(port)), nil
	}
	return host, netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)), nil
}

func (e *Engine) waitForNetwork(log *logrus.Logger, global *config.Global) {
	epo := 5 * time.Second
	startedAt := time.Now()
	bootstrapDirect := e.bootstrapDirect
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := bootstrapDirect.DialContext(ctx, common.MagicNetwork("tcp", global.SoMarkFromDae, global.Mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
		Timeout: epo,
	}
	log.Infoln("Waiting for network...")
	attempts := 0
	for {
		attempts++
		success, timedOut := e.checkNetworkLinksOnce(&client, log)
		if success {
			break
		}
		if timedOut {
			continue
		}
		time.Sleep(epo)
	}
	log.WithField("attempts", attempts).Infoln("[Startup] network gate cleared")
	logStartupPhase(log, "wait-for-network", startedAt, nil)
	log.Infoln("Network online.")
}

func (e *Engine) applyGlobalRuntimeTuning(global *config.Global) {
	if global == nil {
		return
	}
	if e.udpEndpointPool != nil {
		e.udpEndpointPool.SetMaxEntries(global.UdpEndpointPoolSize)
	}
}

func prepareRuntimeConfigView(conf *config.Config) (global config.Global, routing config.Routing, dns config.Dns, err error) {
	global = conf.Global
	global.LanInterface = append([]string(nil), conf.Global.LanInterface...)
	global.WanInterface = append([]string(nil), conf.Global.WanInterface...)
	if err = preprocessWanInterfaceAuto(&global); err != nil {
		return config.Global{}, config.Routing{}, config.Dns{}, err
	}
	return global, conf.Routing, conf.Dns, nil
}

func (e *Engine) checkNetworkLinksOnce(client *http.Client, log *logrus.Logger) (success bool, timedOut bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type networkCheckResult struct {
		success  bool
		timedOut bool
	}

	results := make(chan networkCheckResult, len(e.checkNetworkLinks))
	var wg sync.WaitGroup
	for _, link := range e.checkNetworkLinks {
		link := link
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
			if err != nil {
				log.Debugln("CheckNetwork:", err)
				results <- networkCheckResult{}
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Debugln("CheckNetwork:", err)
				var neterr net.Error
				if errors.As(err, &neterr) && neterr.Timeout() {
					results <- networkCheckResult{timedOut: true}
					return
				}
				results <- networkCheckResult{}
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				cancel()
				results <- networkCheckResult{success: true}
				return
			}
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
			results <- networkCheckResult{}
		}()
	}

	for range e.checkNetworkLinks {
		result := <-results
		if result.success {
			success = true
		}
		if result.timedOut {
			timedOut = true
		}
	}
	wg.Wait()
	return success, timedOut
}

func (e *Engine) newControlPlane(log *logrus.Logger, bpf interface{}, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, suppressEmptyConfigWarnings bool) (c *control.ControlPlane, err error) {
	if log.IsLevelEnabled(logrus.DebugLevel) {
		bConf, _ := conf.Marshal(2)
		log.Debugln(string(bConf))
	}

	globalConf, routingConf, dnsConf, err := prepareRuntimeConfigView(conf)
	if err != nil {
		return nil, err
	}
	e.applyGlobalRuntimeTuning(&globalConf)

	fallbackDNS, err := netip.ParseAddrPort(globalConf.FallbackResolver)
	if err != nil {
		return nil, fmt.Errorf("invalid global.fallback_resolver %q: %w", globalConf.FallbackResolver, err)
	}
	e.fallbackDNS = fallbackDNS
	e.bootstrapDirect = direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{FullCone: false, FallbackDNS: globalConf.FallbackResolver})
	e.bootstrapDirectFullcone = direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{FullCone: true, FallbackDNS: globalConf.FallbackResolver})
	tagToNodeList := map[string][]string{}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	if !globalConf.DisableWaitingNetwork && len(globalConf.WanInterface) > 0 {
		e.onceWaiting.Do(func() {
			e.waitForNetwork(log, &globalConf)
		})
	}

	if len(conf.Subscription) > 0 {
		if e.subscriptionConfigDir == "" {
			return nil, fmt.Errorf("subscription config dir is required when subscription entries are present")
		}
		log.Infoln("Fetching subscriptions...")
	}
	subscriptionResolutionStartedAt := time.Now()
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := e.bootstrapDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
		Timeout: 30 * time.Second,
	}
	resolvingFailed := false
	if len(conf.Subscription) > 0 {
		type subscriptionResolveResult struct {
			tag   string
			nodes []string
			err   error
			raw   string
		}

		results := make([]subscriptionResolveResult, len(conf.Subscription))
		sem := make(chan struct{}, subscriptionResolveConcurrency)
		var wg sync.WaitGroup
		for index, sub := range conf.Subscription {
			index := index
			rawSub := string(sub)
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() {
					<-sem
				}()

				tag, nodes, resolveErr := subscription.ResolveSubscription(log, &client, e.subscriptionConfigDir, rawSub)
				results[index] = subscriptionResolveResult{
					tag:   tag,
					nodes: nodes,
					err:   resolveErr,
					raw:   rawSub,
				}
			}()
		}
		wg.Wait()

		for _, result := range results {
			if result.err != nil {
				log.Warnf(`failed to resolve subscription "%v": %v`, result.raw, result.err)
				resolvingFailed = true
				continue
			}
			if len(result.nodes) > 0 {
				tagToNodeList[result.tag] = append(tagToNodeList[result.tag], result.nodes...)
			}
		}
	}
	if len(conf.Subscription) > 0 {
		log.WithField("subscriptions", len(conf.Subscription)).
			WithField("resolutionFailed", resolvingFailed).
			Infoln("[Startup] subscription resolution completed")
		logStartupPhase(log, "subscription.resolve", subscriptionResolutionStartedAt, nil)
	}
	if e.subscriptionConfigDir != "" {
		if err := cleanupSubscriptionPersistFiles(e.subscriptionConfigDir, tagToNodeList); err != nil {
			return nil, err
		}
	}

	warnEmptyRuntimeConfig(log, tagToNodeList, resolvingFailed, &globalConf, suppressEmptyConfigWarnings)

	controlPlaneStartedAt := time.Now()
	c, err = control.NewControlPlane(
		log,
		bpf,
		dnsCache,
		control.RuntimeDeps{
			Netns:                  e.netns,
			UdpEndpointPool:        e.udpEndpointPool,
			UdpTaskPool:            e.udpTaskPool,
			AnyfromPool:            e.anyfromPool,
			ResolverDialer:         e.bootstrapDirect,
			ResolverFullconeDialer: e.bootstrapDirectFullcone,
			ResolverDNS:            e.fallbackDNS,
		},
		tagToNodeList,
		conf.Group,
		&routingConf,
		&globalConf,
		&dnsConf,
		externGeoDataDirs,
	)
	logStartupPhase(log, "control-plane.core", controlPlaneStartedAt, err)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func warnEmptyRuntimeConfig(log *logrus.Logger, tagToNodeList map[string][]string, resolvingFailed bool, globalConf *config.Global, suppress bool) {
	if suppress {
		return
	}
	if len(tagToNodeList) == 0 {
		if resolvingFailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}
	if globalConf == nil || len(globalConf.LanInterface) == 0 && len(globalConf.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}
}

func cleanupSubscriptionPersistFiles(configDir string, tagToNodeList map[string][]string) error {
	files, err := os.ReadDir(filepath.Join(configDir, "persist.d"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			if err := os.Remove(filepath.Join(configDir, "persist.d", file.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func cloneLogHooks(hooks logrus.LevelHooks) logrus.LevelHooks {
	if len(hooks) == 0 {
		return nil
	}
	cloned := make(logrus.LevelHooks, len(hooks))
	for level, levelHooks := range hooks {
		cloned[level] = append([]logrus.Hook(nil), levelHooks...)
	}
	return cloned
}

func (e *Engine) maybePostStartupGC(log *logrus.Logger, force bool) {
	now := time.Now()
	heapBefore := currentHeapAllocBytes()

	e.mu.Lock()
	lastGCAt := e.lastPostStartupGC
	lastHeapAfter := e.lastPostStartupHeapAlloc
	if !force {
		if !lastGCAt.IsZero() && now.Sub(lastGCAt) < postStartupGCMinInterval {
			e.mu.Unlock()
			return
		}
		if lastHeapAfter > 0 &&
			heapBefore < lastHeapAfter+postStartupGCHeapGrowthBytes &&
			heapBefore*2 < lastHeapAfter*3 {
			e.mu.Unlock()
			return
		}
	}
	e.lastPostStartupGC = now
	e.mu.Unlock()

	gcStartedAt := time.Now()
	postStartupGC()
	heapAfter := currentHeapAllocBytes()

	e.mu.Lock()
	e.lastPostStartupHeapAlloc = heapAfter
	e.mu.Unlock()

	log.WithField("heapBefore", heapBefore).
		WithField("heapAfter", heapAfter).
		WithField("force", force).
		Infoln("[Startup] post-startup gc decision")
	logStartupPhase(log, "post-startup.gc", gcStartedAt, nil)
}

func (e *Engine) setControlPlane(c *control.ControlPlane) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.controlPlane = c
}

func (e *Engine) currentExitCh() chan struct{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.exitCh
}

func (e *Engine) closeExitCh() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exitCh != nil {
		close(e.exitCh)
		e.exitCh = nil
	}
}

func logStartupPhase(log *logrus.Logger, phase string, startedAt time.Time, err error) {
	if log == nil {
		return
	}
	entry := log.WithField("phase", phase).WithField("elapsed", time.Since(startedAt).String())
	if err != nil {
		entry.WithError(err).Warnln("[Startup] phase failed")
		return
	}
	entry.Infoln("[Startup] phase completed")
}
