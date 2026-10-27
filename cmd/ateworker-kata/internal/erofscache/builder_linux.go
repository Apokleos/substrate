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

package erofscache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.ate.dev/substrate/internal/imagecache"
)

func erofsBuilderID(mkfsPath string) (string, error) {
	cmd := exec.Command(mkfsPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query mkfs.erofs version: %w: %s", err, out)
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if line == "" {
		return "", errors.New("mkfs.erofs returned an empty version")
	}
	return line, nil
}

func (c *Cache) build(ctx context.Context, spec *imagecache.OverlaySpec, output string) (retErr error) {
	buildDir := filepath.Join(filepath.Dir(output), "image-view")
	for _, dir := range []string{
		buildDir,
		filepath.Join(buildDir, "rootfs"),
		filepath.Join(buildDir, "upper"),
		filepath.Join(buildDir, "work"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create EROFS image view directory: %w", err)
		}
	}
	if err := imagecache.WriteSpec(buildDir, spec); err != nil {
		return fmt.Errorf("write EROFS image view spec: %w", err)
	}
	if err := imagecache.SetupBundleRootfs(buildDir); err != nil {
		return fmt.Errorf("mount EROFS image view: %w", err)
	}
	defer func() {
		if err := imagecache.UnmountAllUnder(buildDir); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("unmount EROFS image view: %w", err))
		}
		if err := os.RemoveAll(buildDir); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove EROFS image view: %w", err))
		}
	}()

	cmd := exec.CommandContext(ctx, c.mkfsPath, output, filepath.Join(buildDir, "rootfs"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs.erofs: %w: %s", err, out)
	}
	return nil
}
