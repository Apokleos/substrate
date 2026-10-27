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

package resources

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FSCheckpointSubdir is the subdirectory under the checkpoint directory where
// durable-dir filesystem checkpoint files are stored.
const FSCheckpointSubdir = "fs"

// RootfsCheckpointSubdir is the subdirectory under the checkpoint directory
// where container rootfs filesystem checkpoint files are stored.
const RootfsCheckpointSubdir = "rootfs"

// ValidateSnapshotFileNames requires each name to be a distinct, canonical,
// local relative path. Actual file access must still use os.Root so symlinks
// cannot escape the checkpoint directory.
func ValidateSnapshotFileNames(files []string) error {
	seen := make(map[string]bool, len(files))
	for i, name := range files {
		dir := filepath.Dir(name)
		base := filepath.Base(name)
		switch {
		case !filepath.IsLocal(name) || name != filepath.Clean(name) || base == ".":
			return fmt.Errorf("snapshotFiles[%d] %q is not a canonical path in the checkpoint directory", i, name)
		case dir != "." && dir != FSCheckpointSubdir && dir != RootfsCheckpointSubdir && !inRuntimeSnapshotDir(dir):
			return fmt.Errorf("snapshotFiles[%d] %q is outside an allowed snapshot subdirectory", i, name)
		case seen[name]:
			return fmt.Errorf("snapshotFiles[%d] %q is duplicated", i, name)
		}
		seen[name] = true
	}
	return nil
}

func inRuntimeSnapshotDir(dir string) bool {
	for _, root := range []string{"kata", "storage", "vm"} {
		if dir == root || strings.HasPrefix(dir, root+"/") {
			return true
		}
	}
	return false
}
