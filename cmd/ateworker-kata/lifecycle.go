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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	"go.ate.dev/substrate/internal/apierror"
	actornet "go.ate.dev/substrate/internal/ateworker/actornet"
	"go.ate.dev/substrate/internal/imagecache"
	"go.ate.dev/substrate/internal/netns"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
	"go.ate.dev/substrate/internal/resources"
	"go.ate.dev/substrate/internal/wakeupprobe"
	workerstats "go.ate.dev/substrate/internal/workerstats"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	rpcRunWorkload        = "RunWorkload"
	rpcRestoreWorkload    = "RestoreWorkload"
	rpcCheckpointWorkload = "CheckpointWorkload"
	maxActorContainers    = 25
	cleanupTimeout        = 30 * time.Second
)

func (s *AteWorkerService) RunWorkload(ctx context.Context, req *ateworkerpb.RunWorkloadRequest) (_ *ateworkerpb.RunWorkloadResponse, retErr error) {
	limits := req.GetResources().GetLimits()
	if err := validateWorkloadRequest(req.GetActorUid(), req.GetActorDirs(), req.GetSpec(), req.GetRuntimeAssetPaths(), limits.GetCpuMillicores(), limits.GetMemoryBytes()); err != nil {
		return nil, err
	}
	epoch, err := s.epoch.Require()
	if err != nil {
		return nil, err
	}
	if !s.locks.Lock(ctx, req.GetActorUid()) {
		return nil, ctx.Err()
	}
	defer s.locks.Unlock(req.GetActorUid())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	release, err := s.beginRPC(req.GetActorUid(), rpcRunWorkload, cancel)
	if err != nil {
		return nil, err
	}
	defer release()

	attribution := workerstats.ActorAttributionFromRequest(req)
	if previous := s.lookupActor(req.GetActorUid()); previous != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		err := s.cleanupActor(cleanupCtx, previous)
		cleanupCancel()
		if err != nil {
			return nil, fmt.Errorf("clean previous activation: %w", err)
		}
	}
	actor, err := s.admitActor(attribution, req.GetActorDirs(), false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr == nil {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cleanupCancel()
		retErr = errors.Join(retErr, s.cleanupActor(cleanupCtx, actor))
	}()
	if err := s.activate(ctx, actor, req.GetSpec(), req.GetRuntimeAssetPaths(), req.GetRuntimeAssetSha256(), req.GetEgressGateway(), limits.GetCpuMillicores(), limits.GetMemoryBytes(), false, false); err != nil {
		return nil, err
	}
	go s.recordInitial(context.WithoutCancel(ctx), actor)
	s.actorLogger.EmitLifecycleLog(ctx, "Actor started", attribution)
	return &ateworkerpb.RunWorkloadResponse{WorkerEpoch: epoch}, nil
}

// watchSandbox removes an actor whose shim/VMM exits outside an expected
// checkpoint, terminate, or worker shutdown. The actor lifecycle lock makes
// the decision after any concurrent lifecycle RPC has finished.
func (s *AteWorkerService) watchSandbox(actor *hostedActor, client *katashim.Client) {
	resp, waitErr := client.WaitSandbox(context.Background())
	if !s.locks.Lock(context.Background(), actor.attribution.UID) {
		return
	}
	defer s.locks.Unlock(actor.attribution.UID)

	current := s.lookupActor(actor.attribution.UID)
	actor.mu.Lock()
	unexpected := current == actor && actor.client == client && actor.phase == phaseRunning && !actor.cleaning
	actor.mu.Unlock()
	if !unexpected {
		return
	}
	attrs := []any{"actor_uid", actor.attribution.UID}
	if resp != nil {
		attrs = append(attrs, "exit_status", resp.GetExitStatus())
	}
	if waitErr != nil {
		attrs = append(attrs, "err", waitErr)
	}
	slog.Error("Kata sandbox exited unexpectedly", attrs...)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := s.cleanupActor(cleanupCtx, actor); err != nil {
		slog.Error("Failed to clean unexpectedly exited Kata sandbox", "actor_uid", actor.attribution.UID, "err", err)
		return
	}
	s.recordFinal(context.Background(), actor)
}

func (s *AteWorkerService) RestoreWorkload(ctx context.Context, req *ateworkerpb.RestoreWorkloadRequest) (_ *ateworkerpb.RestoreWorkloadResponse, retErr error) {
	limits := req.GetResources().GetLimits()
	if err := validateWorkloadRequest(req.GetActorUid(), req.GetActorDirs(), req.GetSpec(), req.GetRuntimeAssetPaths(), limits.GetCpuMillicores(), limits.GetMemoryBytes()); err != nil {
		return nil, err
	}
	if err := validateMemoryFidelity(req.GetFidelity()); err != nil {
		return nil, err
	}
	epoch, err := s.epoch.Require()
	if err != nil {
		return nil, err
	}
	prepare := katashim.PrepareCheckpointForRestore
	if req.GetPreserveRestoreDir() {
		prepare = katashim.ValidateCheckpointForRestore
	}
	prepareStarted := time.Now()
	prepareErr := prepare(req.GetActorDirs().GetRestoreDir())
	slog.Info("Kata restore checkpoint preparation completed",
		"actor_uid", req.GetActorUid(),
		"preserve_restore_dir", req.GetPreserveRestoreDir(),
		"elapsed_us", time.Since(prepareStarted).Microseconds(),
		"success", prepareErr == nil)
	if prepareErr != nil {
		return nil, apierror.DataLoss("invalid Kata checkpoint: %v", prepareErr)
	}
	if !s.locks.Lock(ctx, req.GetActorUid()) {
		return nil, ctx.Err()
	}
	defer s.locks.Unlock(req.GetActorUid())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	release, err := s.beginRPC(req.GetActorUid(), rpcRestoreWorkload, cancel)
	if err != nil {
		return nil, err
	}
	defer release()

	attribution := workerstats.ActorAttributionFromRequest(req)
	if previous := s.lookupActor(req.GetActorUid()); previous != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		err := s.cleanupActor(cleanupCtx, previous)
		cleanupCancel()
		if err != nil {
			return nil, fmt.Errorf("clean previous activation: %w", err)
		}
	}
	actor, err := s.admitActor(attribution, req.GetActorDirs(), true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr == nil {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cleanupCancel()
		retErr = errors.Join(retErr, s.cleanupActor(cleanupCtx, actor))
	}()
	if err := s.activate(ctx, actor, req.GetSpec(), req.GetRuntimeAssetPaths(), req.GetRuntimeAssetSha256(), req.GetEgressGateway(), limits.GetCpuMillicores(), limits.GetMemoryBytes(), true, req.GetPreserveRestoreDir()); err != nil {
		return nil, err
	}
	go s.recordInitial(context.WithoutCancel(ctx), actor)
	s.actorLogger.EmitLifecycleLog(ctx, "Actor restored", attribution)
	return &ateworkerpb.RestoreWorkloadResponse{WorkerEpoch: epoch}, nil
}

func (s *AteWorkerService) activate(ctx context.Context, actor *hostedActor, spec *ateworkerpb.WorkloadSpec, paths, digests map[string]string, gateway *ateworkerpb.EgressGateway, cpuMilli, memoryBytes int64, restoring, trustedLocalRestore bool) error {
	actor.mu.Lock()
	defer actor.mu.Unlock()
	activationStarted := time.Now()
	logStage := func(stage string, started time.Time) {
		slog.Info("Kata activation phase completed",
			"actor_uid", actor.attribution.UID,
			"restoring", restoring,
			"stage", stage,
			"elapsed_us", time.Since(started).Microseconds())
	}
	stageStarted := time.Now()
	assets, err := resolveRuntimeAssets(actor.dirs.GetSandboxAssetsDir(), paths)
	if err != nil {
		return fmt.Errorf("validate Kata runtime assets: %w", err)
	}
	if err := materializeRuntimeConfig(actor.dirs.GetSandboxAssetsDir(), &assets); err != nil {
		return err
	}
	identities, err := runtimeAssetIdentities(assets, digests)
	if err != nil {
		return err
	}
	actor.runtimeAssets = identities
	logStage("runtime-assets", stageStarted)
	stageStarted = time.Now()
	egress, err := s.tunnel.PrepareEgress(ctx, actor.attribution, gateway)
	if err != nil {
		return err
	}
	session, err := actornet.ServeSandbox(ctx, actornet.SandboxNetworkConfig{
		ActorUID: actor.attribution.UID, EgressPort: s.tunnel.EgressPort,
	}, s.tunnel.Egress, s.tunnel.DNSRelay)
	if err != nil {
		return err
	}
	actor.network = session
	if err := s.tunnel.ActivateEgress(actor.attribution, egress); err != nil {
		return err
	}
	actor.sandboxID = newSandboxID(actor.attribution.UID)
	netnsPath, err := setupKataNetwork(ctx, session, actor.sandboxID)
	if err != nil {
		return err
	}
	logStage("sandbox-network", stageStarted)
	stageStarted = time.Now()
	tasks, err := prepareTasks(ctx, actor.attribution.UID, actor.sandboxID, actor.dirs, spec.GetContainers(), restoring, s.erofsCache)
	if err != nil {
		return err
	}
	actor.tasks = tasks
	logs, err := s.prepareTaskLogs(actor.attribution, tasks)
	if err != nil {
		return err
	}
	actor.logs = logs
	logStage("task-artifacts", stageStarted)
	stageStarted = time.Now()
	var client *katashim.Client
	err = netns.Do(ctx, session.Network.RuntimeNetNS, func(ctx context.Context) error {
		var startErr error
		client, startErr = katashim.Start(ctx, katashim.Config{
			Binary: assets.shim, KataConfig: assets.config, Root: s.shimRoot, SandboxID: actor.sandboxID,
		})
		return startErr
	})
	if err != nil {
		return err
	}
	actor.client = client
	logStage("shim-start", stageStarted)
	stageStarted = time.Now()
	if restoring {
		ids, err := client.Restore(ctx, actor.dirs.GetRestoreDir(), netnsPath, actor.attribution.UID, tasks, identities, cpuMilli, memoryBytes, trustedLocalRestore)
		if err != nil {
			return err
		}
		if err := client.StartRestoredTasks(ctx, ids); err != nil {
			return err
		}
	} else {
		if err := client.CreateSandbox(ctx, katashim.CreateSandboxRequest{
			Hostname:    actor.attribution.UID,
			NetNSPath:   netnsPath,
			Annotations: map[string]string{"io.kubernetes.cri.sandbox-id": actor.sandboxID},
			CPUMilli:    cpuMilli,
			MemoryBytes: memoryBytes,
		}); err != nil {
			return err
		}
		if err := client.StartSandbox(ctx); err != nil {
			return err
		}
		if err := client.CreateAndStartTasks(ctx, tasks); err != nil {
			return err
		}
	}
	logStage("sandbox-tasks-start", stageStarted)
	stageStarted = time.Now()
	if err := wakeupprobe.WaitAll(ctx, spec.GetContainers(), actornet.ActorVethIP, wakeupprobe.DialFunc(session.Dialer())); err != nil {
		return fmt.Errorf("wait for Kata actor readiness: %w", err)
	}
	logStage("wakeup-readiness", stageStarted)
	stageStarted = time.Now()
	if err := s.tunnel.ActivateIngress(actor.attribution, session.Dialer()); err != nil {
		return err
	}
	logStage("traffic-activation", stageStarted)
	logStage("activation-total", activationStarted)
	actor.phase = phaseRunning
	go s.watchSandbox(actor, client)
	return nil
}

func (s *AteWorkerService) CheckpointWorkload(ctx context.Context, req *ateworkerpb.CheckpointWorkloadRequest) (*ateworkerpb.CheckpointWorkloadResponse, error) {
	if err := validateActorDirs(req.GetActorDirs()); err != nil {
		return nil, err
	}
	if err := validateMemoryFidelity(req.GetFidelity()); err != nil {
		return nil, err
	}
	if !s.locks.Lock(ctx, req.GetActorUid()) {
		return nil, ctx.Err()
	}
	defer s.locks.Unlock(req.GetActorUid())
	actor := s.lookupActor(req.GetActorUid())
	if actor == nil {
		return nil, apierror.NotFound("actor %q is not hosted here", req.GetActorUid())
	}
	actor.mu.Lock()
	phase := actor.phase
	actor.mu.Unlock()
	if phase == phaseCheckpointed {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		if err := s.cleanupActor(cleanupCtx, actor); err != nil {
			return nil, fmt.Errorf("continue post-checkpoint cleanup: %w", err)
		}
		files, err := katashim.SealCheckpointForRestore(req.GetActorDirs().GetCheckpointDir())
		if err != nil {
			return nil, apierror.DataLoss("invalid Kata checkpoint: %v", err)
		}
		return &ateworkerpb.CheckpointWorkloadResponse{SnapshotFiles: files}, nil
	}
	actor.mu.Lock()
	if actor.phase != phaseRunning || actor.client == nil {
		actor.mu.Unlock()
		return nil, apierror.FailedPrecondition("actor %q is not running", req.GetActorUid())
	}
	client := actor.client
	tasks := append([]katashim.Task(nil), actor.tasks...)
	runtimeAssets := append([]katashim.RuntimeAssetIdentity(nil), actor.runtimeAssets...)
	actor.mu.Unlock()
	finalStatsStarted := time.Now()
	s.readFinal(ctx, actor)
	slog.Info("Kata checkpoint worker phase completed", "actor_uid", req.GetActorUid(), "stage", "final-stats", "elapsed_us", time.Since(finalStatsStarted).Microseconds())
	tunnelDeactivateStarted := time.Now()
	if err := s.tunnel.Deactivate(ctx, actor.attribution); err != nil {
		return nil, err
	}
	slog.Info("Kata checkpoint worker phase completed", "actor_uid", req.GetActorUid(), "stage", "tunnel-deactivate", "elapsed_us", time.Since(tunnelDeactivateStarted).Microseconds())
	shimCheckpointStarted := time.Now()
	if err := client.Checkpoint(ctx, req.GetActorDirs().GetCheckpointDir(), tasks, runtimeAssets); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		return nil, errors.Join(err, s.cleanupActor(cleanupCtx, actor))
	}
	slog.Info("Kata checkpoint worker phase completed", "actor_uid", req.GetActorUid(), "stage", "shim-checkpoint-rpc", "elapsed_us", time.Since(shimCheckpointStarted).Microseconds())
	actor.mu.Lock()
	actor.phase = phaseCheckpointed
	actor.mu.Unlock()
	sealStarted := time.Now()
	files, manifestErr := katashim.SealCheckpointForRestore(req.GetActorDirs().GetCheckpointDir())
	slog.Info("Kata checkpoint worker phase completed", "actor_uid", req.GetActorUid(), "stage", "checkpoint-seal", "elapsed_us", time.Since(sealStarted).Microseconds())
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	cleanupStarted := time.Now()
	cleanupErr := s.cleanupActor(cleanupCtx, actor)
	slog.Info("Kata checkpoint worker phase completed", "actor_uid", req.GetActorUid(), "stage", "runtime-cleanup", "elapsed_us", time.Since(cleanupStarted).Microseconds())
	cancel()
	if manifestErr != nil {
		return nil, errors.Join(apierror.DataLoss("invalid Kata checkpoint: %v", manifestErr), cleanupErr)
	}
	if cleanupErr != nil {
		return nil, fmt.Errorf("checkpoint succeeded but cleanup failed: %w", cleanupErr)
	}
	s.recordFinal(ctx, actor)
	return &ateworkerpb.CheckpointWorkloadResponse{SnapshotFiles: files}, nil
}

func (s *AteWorkerService) TerminateWorkload(ctx context.Context, req *ateworkerpb.TerminateWorkloadRequest) (*ateworkerpb.TerminateWorkloadResponse, error) {
	if err := validateActorDirs(req.GetActorDirs()); err != nil {
		return nil, err
	}
	if !s.locks.Lock(ctx, req.GetActorUid()) {
		return nil, ctx.Err()
	}
	defer s.locks.Unlock(req.GetActorUid())
	actor := s.lookupActor(req.GetActorUid())
	if actor == nil {
		return &ateworkerpb.TerminateWorkloadResponse{}, nil
	}
	s.readFinal(ctx, actor)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if err := s.cleanupActor(cleanupCtx, actor); err != nil {
		return nil, err
	}
	s.recordFinal(ctx, actor)
	s.actorLogger.EmitLifecycleLog(ctx, "Actor terminated", actor.attribution)
	return &ateworkerpb.TerminateWorkloadResponse{}, nil
}

func (s *AteWorkerService) admitActor(attribution resources.ActorAttribution, dirs *ateworkerpb.ActorDirs, restoring bool) (*hostedActor, error) {
	s.actorsMu.Lock()
	defer s.actorsMu.Unlock()
	if _, exists := s.actors[attribution.UID]; exists {
		return nil, apierror.AlreadyExists("actor %q is already hosted", attribution.UID)
	}
	if len(s.actors) >= s.maxActors {
		return nil, apierror.ResourceExhausted("worker is full: %d actors", s.maxActors)
	}
	actor := &hostedActor{
		attribution: attribution, dirs: dirs, phase: phaseStarting,
		usage: workerstats.NewActivation(time.Now(), restoring),
	}
	s.actors[attribution.UID] = actor
	return actor, nil
}

func (s *AteWorkerService) lookupActor(uid string) *hostedActor {
	s.actorsMu.RLock()
	defer s.actorsMu.RUnlock()
	return s.actors[uid]
}

func (s *AteWorkerService) cleanupActor(ctx context.Context, actor *hostedActor) error {
	if actor == nil {
		return nil
	}
	s.actorsMu.Lock()
	if current := s.actors[actor.attribution.UID]; current != actor {
		s.actorsMu.Unlock()
		return nil
	}
	actor.mu.Lock()
	if !actor.cleaning {
		actor.cleaning = true
		s.draining++
	}
	s.actorsMu.Unlock()
	defer actor.mu.Unlock()

	var errs []error
	if !actor.deactivated {
		startedAt := time.Now()
		if err := s.tunnel.Deactivate(ctx, actor.attribution); err != nil {
			errs = append(errs, err)
		} else {
			actor.deactivated = true
		}
		slog.Info("Kata actor cleanup phase completed", "actor_uid", actor.attribution.UID, "stage", "tunnel-deactivate", "elapsed_us", time.Since(startedAt).Microseconds())
	}
	if !actor.runtimeGone {
		startedAt := time.Now()
		if actor.client != nil {
			if err := actor.client.Delete(ctx, actor.tasks); err != nil {
				errs = append(errs, err)
			} else {
				actor.client = nil
				actor.runtimeGone = true
			}
		} else {
			actor.runtimeGone = true
		}
		slog.Info("Kata actor cleanup phase completed", "actor_uid", actor.attribution.UID, "stage", "shim-runtime-delete", "elapsed_us", time.Since(startedAt).Microseconds())
	}
	if !actor.runtimeGone {
		// Keep logs, mounts, and networking intact while Kata may still be
		// finishing teardown. A later lifecycle retry continues from here.
		return errors.Join(errs...)
	}
	if !actor.logsClosed {
		closeAll(actor.logs)
		actor.logs = nil
		actor.logsClosed = true
	}
	if !actor.mountsGone {
		startedAt := time.Now()
		if err := imagecache.UnmountAllUnder(actor.dirs.GetOciBundleDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		} else {
			actor.mountsGone = true
		}
		slog.Info("Kata actor cleanup phase completed", "actor_uid", actor.attribution.UID, "stage", "mount-cleanup", "elapsed_us", time.Since(startedAt).Microseconds())
	}
	if !actor.networkGone {
		startedAt := time.Now()
		if err := cleanupKataNetwork(ctx, actor.network, actor.sandboxID); err != nil {
			errs = append(errs, err)
		} else {
			actor.network = nil
			actor.networkGone = true
		}
		slog.Info("Kata actor cleanup phase completed", "actor_uid", actor.attribution.UID, "stage", "network-cleanup", "elapsed_us", time.Since(startedAt).Microseconds())
	}
	if len(errs) == 0 {
		s.actorsMu.Lock()
		if s.actors[actor.attribution.UID] == actor {
			delete(s.actors, actor.attribution.UID)
			s.draining--
		}
		s.actorsMu.Unlock()
	}
	return errors.Join(errs...)
}

func validateWorkloadRequest(actorUID string, dirs *ateworkerpb.ActorDirs, spec *ateworkerpb.WorkloadSpec, paths map[string]string, cpuMilli, memoryBytes int64) error {
	if actorUID == "" {
		return apierror.InvalidArgument("actor_uid is required")
	}
	if err := validateActorDirs(dirs); err != nil {
		return err
	}
	if errs := resources.ValidateSandboxAssetsDir(actorUID, dirs.GetSandboxAssetsDir(), field.NewPath("actor_dirs", "sandbox_assets_dir")); len(errs) != 0 {
		return resources.ToAPIError(errs)
	}
	if cpuMilli <= 0 || memoryBytes <= 0 {
		return apierror.InvalidArgument("positive cpu_milli and memory_bytes are required")
	}
	if spec == nil || len(spec.GetContainers()) == 0 {
		return apierror.InvalidArgument("actor spec has no containers")
	}
	if len(spec.GetContainers()) > maxActorContainers {
		return apierror.Unimplemented("ateworker-kata supports at most %d containers, got %d", maxActorContainers, len(spec.GetContainers()))
	}
	names := make([]string, 0, len(spec.GetContainers()))
	for _, container := range spec.GetContainers() {
		names = append(names, container.GetName())
		if len(container.GetDurableDirVolumeMounts()) != 0 || len(container.GetExternalVolumeMounts()) != 0 || len(container.GetSystemInfoVolumeMounts()) != 0 || len(container.GetImageVolumeMounts()) != 0 {
			return apierror.Unimplemented("ateworker-kata does not yet support workload volume mounts")
		}
		if container.GetContainerSpec() == nil {
			return apierror.InvalidArgument("container %q has no container_spec", container.GetName())
		}
	}
	if err := resources.ValidateContainerNames(names); err != nil {
		return apierror.InvalidArgument("%v", err)
	}
	if _, err := resolveRuntimeAssets(dirs.GetSandboxAssetsDir(), paths); err != nil {
		return err
	}
	return nil
}

func validateActorDirs(dirs *ateworkerpb.ActorDirs) error {
	if errs := resources.ValidateActorDirs(dirs, field.NewPath("actor_dirs")); len(errs) != 0 {
		return apierror.InvalidArgument("%v", errs.ToAggregate())
	}
	return nil
}

func validateMemoryFidelity(fidelity ateworkerpb.SnapshotFidelity) error {
	if errs := resources.ValidateSnapshotFidelity(fidelity, []ateworkerpb.SnapshotFidelity{ateworkerpb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY}, field.NewPath("fidelity")); len(errs) != 0 {
		return apierror.InvalidArgument("%v", errs.ToAggregate())
	}
	return nil
}

func newSandboxID(actorUID string) string {
	sum := sha256.Sum256([]byte(actorUID + "\x00" + uuid.NewString()))
	return "ate-" + hex.EncodeToString(sum[:16])
}
