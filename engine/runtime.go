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
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

var ErrControlPlaneNotInit = errors.New("control plane doesn't init yet")

var defaultCheckNetworkLinks = []string{
	"http://edge.microsoft.com/captiveportal/generate_204",
	"http://www.gstatic.com/generate_204",
	"http://www.qualcomm.cn/generate_204",
}

var snapshotRuntimeStats = control.SnapshotRuntimeStats

const subscriptionResolveConcurrency = 6

type Options struct {
	SubscriptionConfigDir string
	CheckNetworkLinks     []string
	OnReady               func()
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
}

type Engine struct {
	mu sync.RWMutex

	controlPlane *control.ControlPlane
	onceWaiting  sync.Once

	reloadCh chan *reloadMessage
	exitCh   chan struct{}

	subscriptionConfigDir   string
	checkNetworkLinks       []string
	onReady                 func()
	httpTransport           *http.Transport
	netns                   *control.DaeNetns
	udpEndpointPool         *control.UdpEndpointPool
	udpTaskPool             *control.UdpTaskPool
	anyfromPool             *control.AnyfromPool
	fallbackDNS             netip.AddrPort
	bootstrapDirect         netproxy.Dialer
	bootstrapDirectFullcone netproxy.Dialer
}

func New(opts Options) *Engine {
	checkLinks := append([]string(nil), opts.CheckNetworkLinks...)
	if len(checkLinks) == 0 {
		checkLinks = append([]string(nil), defaultCheckNetworkLinks...)
	}
	netns := control.NewDaeNetns(nil)
	e := &Engine{
		reloadCh:              make(chan *reloadMessage),
		subscriptionConfigDir: opts.SubscriptionConfigDir,
		checkNetworkLinks:     checkLinks,
		onReady:               opts.OnReady,
		netns:                 netns,
		udpEndpointPool:       control.NewUdpEndpointPool(),
		udpTaskPool:           control.NewUdpTaskPool(),
		anyfromPool:           control.NewAnyfromPoolWithNetns(netns),
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

func (e *Engine) Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string, disableTimestamp bool, dry bool) (err error) {
	startupStartedAt := time.Now()
	e.mu.Lock()
	e.exitCh = make(chan struct{})
	e.mu.Unlock()
	runDone := make(chan struct{})
	defer e.closeExitCh()
	defer close(runDone)
	defer func() {
		e.setControlPlane(nil)
		if ns := e.netns; ns != nil {
			ns.Close()
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
	current, err := e.newControlPlane(log, nil, nil, conf, externGeoDataDirs)
	logStartupPhase(log, "control-plane.create.total", controlPlaneStartedAt, err)
	if err != nil {
		return err
	}
	e.setControlPlane(current)

	var listener *control.Listener
	listenReadyStartedAt := time.Now()
	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			<-readyChan
			logStartupPhase(log, "listen.ready", listenReadyStartedAt, nil)
			logStartupPhase(log, "startup.total", startupStartedAt, nil)
			log.Infoln("Ready")
			if e.onReady != nil {
				e.onReady()
			}
		}()
		e.netns.With(func() error {
			if listener, err = current.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
				log.Errorln("ListenAndServe:", err)
			}
			return err
		})
		select {
		case e.reloadCh <- nil:
		case <-runDone:
		}
	}()

	reloading := false
	var reloadErr error
	var callback chan<- error

loop:
	for msg := range e.reloadCh {
		switch msg {
		case nil:
			if reloading {
				if listener == nil {
					break loop
				}
				reloading = false
				log.Warnln("[Reload] Serve")
				readyChan := make(chan bool, 1)
				go func() {
					if err := current.Serve(readyChan, listener); err != nil {
						log.Errorln("ListenAndServe:", err)
					}
					select {
					case e.reloadCh <- nil:
					case <-runDone:
					}
				}()
				<-readyChan
				log.Warnln("[Reload] Finished")
				callback <- reloadErr
			} else {
				break loop
			}
		default:
			log.Warnln("[Reload] Received reload signal; prepare to reload")
			newConf := msg.Config
			oldLogOutput := log.Out
			log = logrus.New()
			logger.SetLogger(log, newConf.Global.LogLevel, disableTimestamp, nil)
			logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
			log.SetOutput(oldLogOutput)
			logrus.SetOutput(oldLogOutput)

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
			next, nextErr := e.newControlPlane(log, obj, dnsCache, newConf, externGeoDataDirs)
			if nextErr != nil {
				reloadErr = nextErr
				log.WithField("err", nextErr).Errorln("[Reload] Failed to reload; try to roll back configuration")
				next, nextErr = e.newControlPlane(log, obj, dnsCache, conf, externGeoDataDirs)
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
			old.Close()
			control.FlushReloadScopedResources(e.udpEndpointPool, e.anyfromPool, e.udpTaskPool)
		}
	}

	if current != nil {
		if err := current.Close(); err != nil {
			return fmt.Errorf("close control plane: %w", err)
		}
	}
	return nil
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

func (e *Engine) waitForNetwork(log *logrus.Logger, conf *config.Config) {
	epo := 5 * time.Second
	startedAt := time.Now()
	bootstrapDirect := e.bootstrapDirect
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := bootstrapDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
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

func (e *Engine) newControlPlane(log *logrus.Logger, bpf interface{}, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	if log.IsLevelEnabled(logrus.DebugLevel) {
		bConf, _ := conf.Marshal(2)
		log.Debugln(string(bConf))
	}

	conf = deepcopy.Copy(conf).(*config.Config)

	e.fallbackDNS = netip.MustParseAddrPort(conf.Global.FallbackResolver)
	e.bootstrapDirect = direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{FullCone: false, FallbackDNS: conf.Global.FallbackResolver})
	e.bootstrapDirectFullcone = direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{FullCone: true, FallbackDNS: conf.Global.FallbackResolver})
	tagToNodeList := map[string][]string{}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	if !conf.Global.DisableWaitingNetwork && len(conf.Global.WanInterface) > 0 {
		e.onceWaiting.Do(func() {
			e.waitForNetwork(log, conf)
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
		files, err := os.ReadDir(filepath.Join(e.subscriptionConfigDir, "persist.d"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, file := range files {
			tag := strings.TrimSuffix(file.Name(), ".sub")
			if _, ok := tagToNodeList[tag]; !ok {
				if err := os.Remove(filepath.Join(e.subscriptionConfigDir, "persist.d", file.Name())); err != nil {
					return nil, err
				}
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if resolvingFailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}
	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}
	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

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
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
		externGeoDataDirs,
	)
	logStartupPhase(log, "control-plane.core", controlPlaneStartedAt, err)
	if err != nil {
		return nil, err
	}
	gcStartedAt := time.Now()
	runtime.GC()
	logStartupPhase(log, "post-startup.gc", gcStartedAt, nil)
	return c, nil
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
