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
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"go.ate.dev/substrate/cmd/ateworker-kata/internal/erofscache"
	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	"go.ate.dev/substrate/internal/imagecache"
	"go.ate.dev/substrate/internal/ocispec"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

const writableUpperSize = int64(512 << 20)

func prepareTasks(ctx context.Context, actorUID, sandboxID string, dirs *ateworkerpb.ActorDirs, containers []*ateworkerpb.Container, restoring bool, erofs *erofscache.Cache) ([]katashim.Task, error) {
	tasks := make([]katashim.Task, 0, len(containers))
	for _, container := range containers {
		name := container.GetName()
		bundle := filepath.Join(dirs.GetOciBundleDir(), name)
		spec := ocispec.Build(ocispec.Options{ActorUID: actorUID, ActorDirs: dirs, Container: container})
		shapeKataSpec(spec)
		if err := ocispec.Save(bundle, spec); err != nil {
			return nil, err
		}
		var rootfs []katashim.RootfsMount
		var immutableRootfs *katashim.ImmutableRootfs
		if erofs == nil {
			rootfsPath := filepath.Join(bundle, "rootfs.raw")
			if !restoring {
				if err := imagecache.SetupBundleRootfs(bundle); err != nil {
					return nil, fmt.Errorf("compose rootfs for %q: %w", name, err)
				}
				if err := prepareRootfsFile(filepath.Join(bundle, "rootfs"), rootfsPath); err != nil {
					return nil, fmt.Errorf("build rootfs for %q: %w", name, err)
				}
			}
			rootfs = []katashim.RootfsMount{{Type: "ext4", Source: rootfsPath, Options: []string{"rw", "loop"}}}
		} else {
			artifact, err := erofs.Ensure(ctx, bundle)
			if err != nil {
				return nil, fmt.Errorf("prepare EROFS lower for %q: %w", name, err)
			}
			immutableRootfs = &katashim.ImmutableRootfs{
				Path: artifact.Path, SHA256: artifact.SHA256, Size: uint64(artifact.Size),
			}
			upper := filepath.Join(bundle, "rootfs-upper.raw")
			if !restoring {
				if err := prepareWritableUpper(upper); err != nil {
					return nil, fmt.Errorf("prepare writable rootfs upper for %q: %w", name, err)
				}
			}
			overlaySpec, err := imagecache.ReadSpec(bundle)
			if err != nil {
				return nil, fmt.Errorf("read rootfs overlay spec for %q: %w", name, err)
			}
			if overlaySpec == nil {
				return nil, fmt.Errorf("bundle for %q has no rootfs overlay spec", name)
			}
			mkdirOptions := make([]string, 0, len(overlaySpec.ExtraDirs))
			for _, dir := range overlaySpec.ExtraDirs {
				mkdirOptions = append(mkdirOptions, "X-containerd.mkdir.path="+dir)
			}
			rootfs = []katashim.RootfsMount{
				{Type: "ext4", Source: upper, Options: []string{"rw", "loop"}},
				{Type: "erofs", Source: artifact.Path, Options: []string{"ro", "loop"}},
				{Type: "overlay", Source: "overlay", Options: mkdirOptions},
			}
		}
		tasks = append(tasks, katashim.Task{
			CheckpointKey:   name,
			ID:              sandboxID + "-" + name,
			Bundle:          bundle,
			Rootfs:          rootfs,
			Stdout:          filepath.Join(bundle, "stdout.fifo"),
			Stderr:          filepath.Join(bundle, "stderr.fifo"),
			ImmutableRootfs: immutableRootfs,
		})
	}
	return tasks, nil
}

func prepareWritableUpper(output string) error {
	if info, err := os.Lstat(output); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("writable rootfs upper must be a regular file")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := output + ".partial"
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Truncate(writableUpperSize); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	cmd := exec.Command("mkfs.ext4", "-q", "-F", tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("mkfs.ext4: %w: %s", err, out)
	}
	if err := os.Rename(tmp, output); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func shapeKataSpec(spec *specs.Spec) {
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	namespaces := spec.Linux.Namespaces[:0]
	for _, namespace := range spec.Linux.Namespaces {
		if namespace.Type != specs.NetworkNamespace {
			namespaces = append(namespaces, namespace)
		}
	}
	spec.Linux.Namespaces = namespaces
	if spec.Linux.Resources == nil {
		shares := uint64(1024)
		spec.Linux.Resources = &specs.LinuxResources{CPU: &specs.LinuxCPU{Shares: &shares}}
	}
}

func prepareRootfsFile(rootfsDir, output string) error {
	if info, err := os.Lstat(output); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("rootfs output must be a regular file")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Stat(rootfsDir)
	if err != nil || !info.IsDir() {
		return errors.New("bundle rootfs directory is missing")
	}
	size, err := managedRootfsSize(rootfsDir)
	if err != nil {
		return err
	}
	tmp := output + ".partial"
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	cmd := exec.Command("mkfs.ext4", "-q", "-F", "-d", rootfsDir, tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("mkfs.ext4: %w: %s", err, out)
	}
	if err := os.Rename(tmp, output); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func managedRootfsSize(root string) (int64, error) {
	const (
		minimum = int64(512 << 20)
		reserve = int64(128 << 20)
		align   = int64(1 << 20)
	)
	var content int64
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 && content > int64(^uint64(0)>>1)-info.Size() {
			return errors.New("rootfs size overflow")
		}
		content += info.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	size := content + content/2 + reserve
	if size < minimum {
		size = minimum
	}
	return (size + align - 1) / align * align, nil
}
