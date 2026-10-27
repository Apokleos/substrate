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
	"fmt"
	"strings"

	statsv1 "github.com/containerd/cgroups/v3/cgroup1/stats"
	statsv2 "github.com/containerd/cgroups/v3/cgroup2/stats"
	taskapi "github.com/containerd/containerd/api/runtime/task/v3"
)

// TaskStats is the aggregate of every workload task in one sandbox.
type TaskStats struct {
	MemoryCurrentBytes    uint64
	MemoryPeakBytes       uint64
	MemoryWorkingSetBytes uint64
	CPUUsageUsec          uint64
	CPUUsageByTask        map[string]uint64
}

// Stats reads and aggregates guest task cgroup statistics.
func (c *Client) Stats(ctx context.Context, tasks []Task) (*TaskStats, error) {
	return collectTaskStats(ctx, tasks, c.tasks.Stats)
}

func collectTaskStats(ctx context.Context, tasks []Task, read func(context.Context, *taskapi.StatsRequest) (*taskapi.StatsResponse, error)) (*TaskStats, error) {
	total := &TaskStats{CPUUsageByTask: make(map[string]uint64, len(tasks))}
	var errs []error
	measured := 0
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := read(ctx, &taskapi.StatsRequest{ID: task.ID})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			errs = append(errs, fmt.Errorf("stats task %q: %w", task.ID, err))
			continue
		}
		cpu, err := addTaskStats(total, resp)
		if err != nil {
			errs = append(errs, fmt.Errorf("decode stats task %q: %w", task.ID, err))
			continue
		}
		total.CPUUsageByTask[task.ID] = cpu
		measured++
	}
	if measured == 0 && len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	return total, nil
}

func addTaskStats(total *TaskStats, resp *taskapi.StatsResponse) (uint64, error) {
	stats := resp.GetStats()
	if stats == nil {
		return 0, errors.New("task returned no stats")
	}
	switch {
	case strings.Contains(stats.GetTypeUrl(), "cgroups.v2"):
		var metrics statsv2.Metrics
		if err := stats.UnmarshalTo(&metrics); err != nil {
			return 0, err
		}
		current := metrics.GetMemory().GetUsage()
		inactive := metrics.GetMemory().GetInactiveFile()
		cpu := metrics.GetCPU().GetUsageUsec()
		total.MemoryCurrentBytes += current
		total.MemoryPeakBytes += metrics.GetMemory().GetMaxUsage()
		total.MemoryWorkingSetBytes += current - min(current, inactive)
		total.CPUUsageUsec += cpu
		return cpu, nil
	case strings.Contains(stats.GetTypeUrl(), "cgroups.v1"):
		var metrics statsv1.Metrics
		if err := stats.UnmarshalTo(&metrics); err != nil {
			return 0, err
		}
		current := metrics.GetMemory().GetUsage().GetUsage()
		inactive := metrics.GetMemory().GetTotalInactiveFile()
		cpu := metrics.GetCPU().GetUsage().GetTotal() / 1000
		total.MemoryCurrentBytes += current
		total.MemoryPeakBytes += metrics.GetMemory().GetUsage().GetMax()
		total.MemoryWorkingSetBytes += current - min(current, inactive)
		total.CPUUsageUsec += cpu
		return cpu, nil
	default:
		return 0, fmt.Errorf("unsupported task stats type %q", stats.GetTypeUrl())
	}
}
