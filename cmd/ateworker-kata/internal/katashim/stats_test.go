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

package katashim

import (
	"context"
	"errors"
	"reflect"
	"testing"

	statsv2 "github.com/containerd/cgroups/v3/cgroup2/stats"
	taskapi "github.com/containerd/containerd/api/runtime/task/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestCollectTaskStatsContinuesAfterOneTaskFails(t *testing.T) {
	metrics, err := anypb.New(&statsv2.Metrics{
		CPU:    &statsv2.CPUStat{UsageUsec: 17},
		Memory: &statsv2.MemoryStat{Usage: 100, MaxUsage: 120, InactiveFile: 20},
	})
	if err != nil {
		t.Fatalf("encoding metrics: %v", err)
	}
	got, err := collectTaskStats(context.Background(), []Task{{ID: "bad"}, {ID: "good"}},
		func(_ context.Context, req *taskapi.StatsRequest) (*taskapi.StatsResponse, error) {
			if req.GetID() == "bad" {
				return nil, errors.New("task exited")
			}
			return &taskapi.StatsResponse{Stats: metrics}, nil
		})
	if err != nil {
		t.Fatalf("collectTaskStats() failed despite one usable task: %v", err)
	}
	want := &TaskStats{MemoryCurrentBytes: 100, MemoryPeakBytes: 120, MemoryWorkingSetBytes: 80, CPUUsageUsec: 17, CPUUsageByTask: map[string]uint64{"good": 17}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collectTaskStats() = %+v, want %+v", got, want)
	}
}

func TestCollectTaskStatsFailsWhenEveryTaskFails(t *testing.T) {
	_, err := collectTaskStats(context.Background(), []Task{{ID: "one"}, {ID: "two"}},
		func(context.Context, *taskapi.StatsRequest) (*taskapi.StatsResponse, error) {
			return nil, errors.New("task exited")
		})
	if err == nil {
		t.Fatal("collectTaskStats() succeeded with no usable task stats")
	}
}

func TestCollectTaskStatsDoesNotReturnPartialSampleAfterContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	metrics, err := anypb.New(&statsv2.Metrics{CPU: &statsv2.CPUStat{UsageUsec: 17}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = collectTaskStats(ctx, []Task{{ID: "first"}, {ID: "second"}}, func(_ context.Context, req *taskapi.StatsRequest) (*taskapi.StatsResponse, error) {
		if req.GetID() == "first" {
			cancel()
			return &taskapi.StatsResponse{Stats: metrics}, nil
		}
		return nil, errors.New("unexpected second read")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("collectTaskStats() error = %v, want context.Canceled", err)
	}
}
