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
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	"go.ate.dev/substrate/internal/resources"
)

func (s *AteWorkerService) prepareTaskLogs(actor resources.ActorAttribution, tasks []katashim.Task) ([]interface{ Close() error }, error) {
	var readers []interface{ Close() error }
	for _, task := range tasks {
		for _, stream := range []string{task.Stdout, task.Stderr} {
			if err := makeFIFO(stream); err != nil {
				closeAll(readers)
				return nil, err
			}
			pipe, err := s.actorLogger.StartJSONLogPipe(actor, task.CheckpointKey)
			if err != nil {
				closeAll(readers)
				return nil, err
			}
			reader := &fifoReader{path: stream, output: pipe, done: make(chan struct{})}
			readers = append(readers, reader)
			go reader.run()
		}
	}
	return readers, nil
}

type fifoReader struct {
	path   string
	output io.WriteCloser
	mu     sync.Mutex
	file   *os.File
	done   chan struct{}
}

func (r *fifoReader) run() {
	defer close(r.done)
	defer r.output.Close()
	// RDWR keeps setup non-blocking until the shim opens its writer. Close
	// releases the retained write end during actor teardown.
	f, err := os.OpenFile(r.path, os.O_RDWR, 0)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.file = f
	r.mu.Unlock()
	_, _ = io.Copy(r.output, f)
	_ = f.Close()
}

func (r *fifoReader) Close() error {
	r.mu.Lock()
	if r.file != nil {
		_ = r.file.Close()
	}
	r.mu.Unlock()
	_ = r.output.Close()
	return nil
}

func makeFIFO(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			return fmt.Errorf("create task FIFO %q: %w", path, err)
		}
		return nil
	case err != nil:
		return err
	case info.Mode()&os.ModeNamedPipe == 0:
		return fmt.Errorf("task IO path %q is not a FIFO", path)
	default:
		return nil
	}
}

func closeAll(closers []interface{ Close() error }) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}
