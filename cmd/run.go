/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	daeengine "github.com/daeuniverse/dae/engine"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	PidFilePath            = "/var/run/dae.pid"
	SignalProgressFilePath = "/var/run/dae.progress"
)

var (
	CheckNetworkLinks = []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to stdout and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				logrus.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				logrus.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			if !disableAuthSudo {
				internal.AutoSu()
			}

			configLoadStartedAt := time.Now()
			conf, includes, err := daeengine.ReadConfigFile(cfgFile)
			if err != nil {
				logrus.WithField("err", err).Fatalln("Failed to read config")
			}

			var logOpts *lumberjack.Logger
			if logFile != "" {
				logOpts = &lumberjack.Logger{
					Filename:   logFile,
					MaxSize:    logFileMaxSize,
					MaxAge:     0,
					MaxBackups: logFileMaxBackups,
					LocalTime:  true,
					Compress:   true,
				}
			}
			log := logrus.New()
			logger.SetLogger(log, conf.Global.LogLevel, disableTimestamp, logOpts)
			logger.SetLogger(logrus.StandardLogger(), conf.Global.LogLevel, disableTimestamp, logOpts)

			logStartupPhase(log, "config.load", configLoadStartedAt, nil)
			log.Infof("Include config files: [%v]", strings.Join(includes, ", "))

			runtimeEngine := daeengine.New(daeengine.Options{
				SubscriptionConfigDir: filepath.Dir(cfgFile),
				CheckNetworkLinks:     CheckNetworkLinks,
				OnReady: func() {
					sdnotify.Ready()
					if !disablePidFile {
						_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
					}
					_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644)
				},
			})

			pprofServer := startPprofServer(conf.Global.PprofPort)
			defer shutdownPprofServer(pprofServer)

			runErrCh := make(chan error, 1)
			go func() {
				runErrCh <- runtimeEngine.Run(log, conf, []string{filepath.Dir(cfgFile)}, disableTimestamp, false)
			}()

			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
			for {
				select {
				case err := <-runErrCh:
					if err != nil {
						log.Fatalln(err)
					}
					return
				case sig := <-sigs:
					switch sig {
					case syscall.SIGUSR2, syscall.SIGUSR1:
						suspend := sig == syscall.SIGUSR2
						if suspend {
							log.Warnln("[Reload] Received suspend signal; prepare to suspend")
						} else {
							log.Warnln("[Reload] Received reload signal; prepare to reload")
						}
						sdnotify.Reloading()
						_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadProcessing}, 0644)

						abortConnections := os.Remove(AbortFile) == nil
						log.Warnln("[Reload] Load new config")
						newConf := conf
						if suspend {
							newConf = daeengine.EmptyConfig()
							newConf.Global = deepcopy.Copy(conf.Global).(config.Global)
							newConf.Global.WanInterface = nil
							newConf.Global.LanInterface = nil
							newConf.Global.LogLevel = "warning"
						} else {
							var nextIncludes []string
							nextConf, nextIncludes, err := daeengine.ReadConfigFile(cfgFile)
							if err != nil {
								log.WithField("err", err).Errorln("[Reload] Failed to reload")
								sdnotify.Ready()
								_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
								continue
							}
							log.Infof("Include config files: [%v]", strings.Join(nextIncludes, ", "))
							newConf = nextConf
						}

						if err := runtimeEngine.ReloadWithAbort(newConf, abortConnections); err != nil {
							sdnotify.Ready()
							_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
							log.WithField("err", err).Errorln("[Reload] Failed to reload")
							continue
						}

						conf = newConf
						sdnotify.Ready()
						_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
						pprofServer = restartPprofServer(pprofServer, conf.Global.PprofPort)
					case syscall.SIGHUP:
						continue
					default:
						log.Infof("Received signal: %v", sig.String())
						if err := runtimeEngine.Stop(10 * time.Second); err != nil {
							log.Errorf("Force exit after shutdown timeout: %v", err)
						}
						_ = os.Remove(PidFilePath)
						return
					}
				}
			}
		},
	}
)

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

func startPprofServer(port uint16) *http.Server {
	if port == 0 {
		return nil
	}
	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", port),
		Handler: nil,
	}
	go server.ListenAndServe()
	return server
}

func shutdownPprofServer(server *http.Server) {
	if server == nil {
		return
	}
	_ = server.Shutdown(context.Background())
}

func restartPprofServer(server *http.Server, port uint16) *http.Server {
	shutdownPprofServer(server)
	return startPprofServer(port)
}

func init() {
	rootCmd.AddCommand(runCmd)
}
