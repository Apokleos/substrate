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
	"errors"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	"go.ate.dev/substrate/internal/apierror"
	"go.ate.dev/substrate/internal/ateattr"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
	"go.ate.dev/substrate/internal/resources"
	"go.ate.dev/substrate/pkg/sandboxclass"
)

func (s *AteWorkerService) GetWorkloadStats(ctx context.Context, req *ateworkerpb.GetWorkloadStatsRequest) (*ateworkerpb.GetWorkloadStatsResponse, error) {
	if req.GetActorUid() == "" {
		return nil, apierror.InvalidArgument("actor_uid is required")
	}
	actor := s.lookupActor(req.GetActorUid())
	if actor == nil {
		return nil, apierror.NotFound("worker is not executing actor %q", req.GetActorUid())
	}
	sample, err := measureActor(ctx, actor)
	if err != nil {
		return nil, apierror.FailedPrecondition("actor %q cannot be sampled: %v", req.GetActorUid(), err)
	}
	if s.lookupActor(req.GetActorUid()) != actor {
		return nil, apierror.NotFound("worker stopped executing actor %q while the sample was being taken", req.GetActorUid())
	}
	actor.usage.Store(sample)
	return &ateworkerpb.GetWorkloadStatsResponse{Sample: sample}, nil
}

func (s *AteWorkerService) GetActiveWorkloadStats(context.Context, *ateworkerpb.GetActiveWorkloadStatsRequest) (*ateworkerpb.GetActiveWorkloadStatsResponse, error) {
	actors := s.actorSnapshot()
	samples := make([]*ateworkerpb.WorkloadStatsSample, 0, len(actors))
	for _, actor := range actors {
		sample := actor.usage.Latest()
		if sample == nil {
			sample = actor.usage.WithEpoch(kataSample(&actor.attribution, nil))
		}
		samples = append(samples, sample)
	}
	return &ateworkerpb.GetActiveWorkloadStatsResponse{Samples: samples}, nil
}

func measureActor(ctx context.Context, actor *hostedActor) (*ateworkerpb.WorkloadStatsSample, error) {
	actor.mu.Lock()
	if actor.phase != phaseRunning || actor.client == nil || actor.cleaning {
		actor.mu.Unlock()
		return nil, errors.New("runtime is not running")
	}
	client := actor.client
	tasks := append([]katashim.Task(nil), actor.tasks...)
	actor.mu.Unlock()
	return actor.usage.Measure(ctx, func() (*ateworkerpb.WorkloadStatsSample, map[string]uint64, error) {
		stats, err := client.Stats(ctx, tasks)
		if err != nil {
			return nil, nil, err
		}
		return kataSample(&actor.attribution, stats), stats.CPUUsageByTask, nil
	})
}

func (s *AteWorkerService) sweepStats(ctx context.Context) {
	var wg sync.WaitGroup
	for _, actor := range s.actorSnapshot() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					slog.ErrorContext(ctx, "Kata usage sample panicked", "actor_uid", actor.attribution.UID, "panic", recovered, "stack", string(debug.Stack()))
				}
			}()
			if !actor.usage.Sampling() {
				return
			}
			sampleCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			select {
			case s.statsSlots <- struct{}{}:
				defer func() { <-s.statsSlots }()
			case <-sampleCtx.Done():
				return
			}
			sample, err := measureActor(sampleCtx, actor)
			if err != nil {
				sample = actor.usage.WithEpoch(kataSample(&actor.attribution, nil))
			}
			if s.lookupActor(actor.attribution.UID) == actor {
				actor.usage.Periodic(sample, func() { s.usage.Emit(ctx, ateattr.StatsKindPeriodic, sample) })
			}
		}()
	}
	wg.Wait()
}

func (s *AteWorkerService) recordInitial(ctx context.Context, actor *hostedActor) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sample, err := measureActor(ctx, actor)
	if err != nil {
		slog.WarnContext(ctx, "No initial Kata usage sample", "actor_uid", actor.attribution.UID, "err", err)
		sample = nil
	}
	actor.usage.Initial(sample, func() { s.usage.Emit(ctx, ateattr.StatsKindInitial, sample) })
}

func (s *AteWorkerService) readFinal(ctx context.Context, actor *hostedActor) {
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if sample, err := measureActor(readCtx, actor); err == nil {
		actor.usage.Store(sample)
	}
}

func (s *AteWorkerService) recordFinal(ctx context.Context, actor *hostedActor) {
	pending := actor.usage.WithEpoch(kataSample(&actor.attribution, nil))
	actor.usage.Final(func(sample *ateworkerpb.WorkloadStatsSample) {
		if sample == nil {
			sample = pending
		}
		s.usage.Emit(ctx, ateattr.StatsKindFinal, sample)
	})
}

func kataSample(actor *resources.ActorAttribution, stats *katashim.TaskStats) *ateworkerpb.WorkloadStatsSample {
	sample := &ateworkerpb.WorkloadStatsSample{
		Atespace: actor.Ref.Atespace, ActorName: actor.Ref.Name, ActorUid: actor.UID,
		ActorTemplateAtespace: actor.TemplateAtespace, ActorTemplateName: actor.TemplateName,
		SandboxClass:       sandboxclass.Kata,
		ObservedAtUnixNano: time.Now().UnixNano(),
	}
	if stats != nil {
		sample.Source = ateworkerpb.StatsSource_STATS_SOURCE_GUEST_AGENT
		sample.MemoryCurrentBytes = stats.MemoryCurrentBytes
		sample.MemoryPeakBytes = stats.MemoryPeakBytes
		sample.MemoryWorkingSetBytes = stats.MemoryWorkingSetBytes
		sample.CpuUsageUsec = stats.CPUUsageUsec
	}
	return sample
}
