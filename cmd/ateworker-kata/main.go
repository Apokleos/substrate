//go:build linux

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command ateworker-kata implements the Worker service by driving Kata shim Sandbox and Task APIs.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/spf13/pflag"
	atev1 "go.ate.dev/substrate/api/infra/k8s/ate/v1"
	"go.ate.dev/substrate/cmd/ateworker-kata/internal/erofscache"
	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	"go.ate.dev/substrate/internal/actorlock"
	"go.ate.dev/substrate/internal/actorlog"
	"go.ate.dev/substrate/internal/apierror"
	"go.ate.dev/substrate/internal/ateinterceptors"
	actornet "go.ate.dev/substrate/internal/ateworker/actornet"
	cgroup "go.ate.dev/substrate/internal/ateworker/cgroup"
	pid1 "go.ate.dev/substrate/internal/ateworker/pid1"
	register "go.ate.dev/substrate/internal/ateworker/register"
	atunnel "go.ate.dev/substrate/internal/atunnel"
	"go.ate.dev/substrate/internal/nodepath"
	"go.ate.dev/substrate/internal/preview"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
	"go.ate.dev/substrate/internal/resources"
	"go.ate.dev/substrate/internal/serverboot"
	"go.ate.dev/substrate/internal/version"
	workerstats "go.ate.dev/substrate/internal/workerstats"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	podUID              = pflag.String("pod-uid", "", "The UID of the current pod")
	podIPs              = pflag.String("pod-ips", "", "Comma-separated Pod IPs")
	shimRoot            = pflag.String("shim-root", "/run/ateworker-kata/shims", "Root directory for per-actor shim bundles")
	rootfsMode          = pflag.String("rootfs-mode", "ext4", "Workload rootfs mode: ext4 or erofs-overlay")
	erofsCacheDir       = pflag.String("erofs-cache-dir", filepath.Join(nodepath.BasePath, "ateworker-kata-erofs"), "Node-local cache for immutable EROFS workload rootfs images")
	maxActors           = pflag.Int("max-actors", 1000, "How many actors this worker will host at once")
	showVersion         = pflag.Bool("version", false, "Print version and exit")
	logLevelFlag        = pflag.String("log-level", "info", "Minimum log level: debug, info, warn, or error")
	previewFlags        = pflag.StringSlice("preview", nil, "Preview gates to enable.")
	usageSampleInterval = pflag.Duration("usage-sample-interval", time.Minute, "How often to refresh active actor usage samples")

	readinessListenAddress = pflag.String("readiness-listen-address", "0.0.0.0:8080", "Address for HTTP readiness checks")
	tunnelConfig           = atunnel.RegisterFlags(pflag.CommandLine)
)

const serviceName = "ateworker-kata"

func main() {
	pid1.RunIfPID1()
	pflag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(context.Background()); err != nil {
		slog.Error("ateworker-kata exited", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	logWriter := actorlog.NewSyncedWriter(os.Stdout)
	serverboot.InitLoggerWithWriter(logWriter)
	if err := serverboot.SetLogLevel(*logLevelFlag); err != nil {
		return err
	}
	if err := preview.Init(*previewFlags...); err != nil {
		return fmt.Errorf("invalid --preview: %w", err)
	}
	if err := resources.ValidateWorkerPodUID(*podUID); err != nil {
		return fmt.Errorf("invalid --pod-uid: %w", err)
	}
	if *maxActors < 0 {
		return fmt.Errorf("--max-actors must not be negative, got %d", *maxActors)
	}
	if *usageSampleInterval <= 0 {
		return fmt.Errorf("--usage-sample-interval must be positive")
	}
	if !filepath.IsAbs(*shimRoot) {
		return fmt.Errorf("--shim-root must be absolute")
	}
	if err := os.MkdirAll(*shimRoot, 0o700); err != nil {
		return err
	}
	var rootfsCache *erofscache.Cache
	switch *rootfsMode {
	case "ext4":
	case "erofs-overlay":
		if !filepath.IsAbs(*erofsCacheDir) {
			return fmt.Errorf("--erofs-cache-dir must be absolute")
		}
		var err error
		rootfsCache, err = erofscache.New(*erofsCacheDir, "/usr/bin/mkfs.erofs")
		if err != nil {
			return fmt.Errorf("initialize EROFS cache: %w", err)
		}
	default:
		return fmt.Errorf("--rootfs-mode must be ext4 or erofs-overlay, got %q", *rootfsMode)
	}
	// Kata runtime-rs creates cgroups for the shim, VMM, and workload tasks.
	// Delegate the worker pod's private cgroup before starting any shim so the
	// runtime sees a writable pod-scoped hierarchy, as the other Worker runtimes
	// backends do.
	if err := cgroup.Delegate(ctx); err != nil {
		return fmt.Errorf("while setting up cgroup delegation: %w", err)
	}

	ateworkerDir := nodepath.WorkerPath(*podUID)
	if err := os.MkdirAll(ateworkerDir, 0o700); err != nil {
		return err
	}
	socket := nodepath.WorkerSocketPath(*podUID)
	if err := os.RemoveAll(socket); err != nil {
		return fmt.Errorf("remove stale worker socket: %w", err)
	}
	lis, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer lis.Close()
	defer func() {
		if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
			slog.WarnContext(ctx, "Failed to remove worker socket", slog.Any("err", err))
		}
	}()

	tunnel, err := atunnel.Start(ctx, *tunnelConfig, actornet.ActorHTTPUpstream)
	if err != nil {
		return err
	}
	service := newService(*shimRoot, *maxActors, tunnel, actorlog.NewActorLogger(logWriter, metadata.OnGCE()))
	service.erofsCache = rootfsCache
	pool := workerstats.Pool{Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("WORKER_POOL_NAME")}
	if pool.Namespace == "" || pool.Name == "" {
		slog.WarnContext(ctx, "Worker pool unknown; usage records will name no pool", slog.Any("pool", pool))
	}
	usageStdout := workerstats.NewStdoutHandler(logWriter)
	defer usageStdout.Close()
	service.usage = workerstats.NewUsageEmitter(nil, usageStdout, pool)
	stopSampler := workerstats.StartSampler(ctx, *usageSampleInterval, service.sweepStats)
	defer stopSampler()
	server := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.UnaryInterceptor(ateinterceptors.InternalServerUnaryInterceptor),
	)
	ateworkerpb.RegisterWorkerServer(server, service)
	reflection.Register(server)
	readiness := &serverboot.Readiness{}
	readiness.AddCheck("registered", service.epoch.Registered)
	go serverboot.StartHealthServer(ctx, *readinessListenAddress, readiness)

	reportConfig := register.ReportConfig{
		SocketPath:           nodepath.WorkerSupportSocket,
		CredentialBundlePath: tunnelConfig.CredentialBundle,
		TrustBundlePath:      tunnelConfig.TrustBundle,
		AteletSPIFFEID:       tunnelConfig.BrokerIdentity,
		Actors:               *maxActors,
		PodIPs:               register.ParsePodIPs(*podIPs),
		SandboxClass:         string(atev1.SandboxClassKata),
		RuntimesFile:         nodepath.WorkerSandboxRuntimesPath(*podUID),
	}
	go func() {
		err := register.Report(ctx, reportConfig, &service.epoch)
		if err != nil && ctx.Err() == nil {
			serverboot.Fatal(ctx, "Failed to report worker capacity", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		sig := <-sigCh
		slog.InfoContext(ctx, "Received signal; draining Kata worker", slog.String("signal", sig.String()))
		readiness.MarkNotReady()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		service.gracefulShutdown(shutdownCtx)
		server.GracefulStop()
	}()

	slog.InfoContext(ctx, serviceName+" serving", slog.String("socket", socket))
	return server.Serve(lis)
}

type actorPhase uint8

const (
	phaseStarting actorPhase = iota
	phaseRunning
	phaseCheckpointed
)

type hostedActor struct {
	mu            sync.Mutex
	attribution   resources.ActorAttribution
	dirs          *ateworkerpb.ActorDirs
	network       *actornet.SandboxSession
	client        *katashim.Client
	sandboxID     string
	tasks         []katashim.Task
	runtimeAssets []katashim.RuntimeAssetIdentity
	logs          []interface{ Close() error }
	usage         *workerstats.Activation
	phase         actorPhase
	cleaning      bool
	deactivated   bool
	runtimeGone   bool
	logsClosed    bool
	mountsGone    bool
	networkGone   bool
}

type AteWorkerService struct {
	ateworkerpb.UnimplementedWorkerServer

	locks    *actorlock.Locks
	inFlight *actorlock.InFlight
	shutdown atomic.Bool

	shimRoot    string
	maxActors   int
	tunnel      *atunnel.Tunnel
	actorLogger *actorlog.ActorLogger
	usage       *workerstats.UsageEmitter
	erofsCache  *erofscache.Cache
	epoch       register.Epoch

	actorsMu   sync.RWMutex
	actors     map[string]*hostedActor
	draining   int
	statsSlots chan struct{}
}

var _ ateworkerpb.WorkerServer = (*AteWorkerService)(nil)

func newService(root string, capacity int, tunnel *atunnel.Tunnel, logger *actorlog.ActorLogger) *AteWorkerService {
	return &AteWorkerService{
		locks: actorlock.New(), inFlight: actorlock.NewInFlight(), shimRoot: root,
		maxActors: capacity, tunnel: tunnel, actorLogger: logger,
		actors: make(map[string]*hostedActor), statsSlots: make(chan struct{}, 32),
	}
}

func (s *AteWorkerService) beginRPC(actorUID, name string, cancel context.CancelFunc) (func(), error) {
	release := s.inFlight.Add(actorUID, name, cancel)
	if s.shutdown.Load() {
		release()
		return nil, apierror.Unavailable("worker draining: not accepting new workloads")
	}
	return release, nil
}

func (s *AteWorkerService) gracefulShutdown(ctx context.Context) {
	s.shutdown.Store(true)
	s.inFlight.CancelStartups()
	actors := s.actorSnapshot()
	for _, actor := range actors {
		if !s.locks.Lock(ctx, actor.attribution.UID) {
			continue
		}
		_ = s.cleanupActor(ctx, actor)
		s.locks.Unlock(actor.attribution.UID)
	}
}

func (s *AteWorkerService) actorSnapshot() []*hostedActor {
	s.actorsMu.RLock()
	defer s.actorsMu.RUnlock()
	out := make([]*hostedActor, 0, len(s.actors))
	for _, actor := range s.actors {
		out = append(out, actor)
	}
	return out
}
