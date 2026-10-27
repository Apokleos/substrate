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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCheckpoint(t *testing.T) {
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, checkpointRuntimeDir)
	write := func(rel, value string) checkpointVMState {
		t.Helper()
		path := filepath.Join(runtimeRoot, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(value))
		size := uint64(len(value))
		return checkpointVMState{
			File: rel, Format: vmArtifactRawFormat, LogicalSize: size, EncodedSize: size,
			SHA256: hex.EncodeToString(sum[:]),
		}
	}
	vm := write("vm/state", "vm")
	rootfsFile := write("storage/rootfs.sparse", "rootfs")
	direct := false
	manifest := checkpointManifest{
		FormatVersion: checkpointFormatVersion, Hypervisor: "qemu", VMVCPUs: 1, VMMemoryMB: 512,
		RuntimeFingerprint: "runtime", Tasks: []checkpointTask{{CheckpointKey: "main", TaskID: "task-main"}},
		VMState: []checkpointVMState{vm}, Rootfs: []checkpointRootfs{{
			CheckpointKey: "main", File: rootfsFile.File, LogicalSize: 512 << 20, EncodedSize: rootfsFile.EncodedSize, SHA256: rootfsFile.SHA256,
			Format: "kata-sparse-raw-v1", DeviceID: "rootfs", DriverOption: "virtio-blk", VirtPath: "/dev/vda",
			IsDirect: &direct, AIO: "threads",
		}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := ValidateCheckpoint(root)
	if err != nil {
		t.Fatalf("ValidateCheckpoint() error = %v", err)
	}
	if len(files) != 3 || files[0] != "kata/manifest.json" || files[1] != "kata/storage/rootfs.sparse" || files[2] != "kata/vm/state" {
		t.Fatalf("ValidateCheckpoint() files = %v", files)
	}
	if err := ValidateCheckpointForRestore(root); err == nil {
		t.Fatal("ValidateCheckpointForRestore() accepted writable files")
	}
	if err := PrepareCheckpointForRestore(root); err != nil {
		t.Fatalf("PrepareCheckpointForRestore() error = %v", err)
	}
	for _, relative := range files {
		info, err := os.Stat(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Errorf("mode for %q = %o, want 400", relative, info.Mode().Perm())
		}
	}
	if err := ValidateCheckpointForRestore(root); err != nil {
		t.Fatalf("ValidateCheckpointForRestore() error = %v", err)
	}

	if err := os.Chmod(filepath.Join(runtimeRoot, "vm/state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "vm/state"), []byte("xx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareCheckpointForRestore(root); err != nil {
		t.Fatalf("PrepareCheckpointForRestore() rejected structurally valid checkpoint: %v", err)
	}
	if err := ValidateCheckpointForRestore(root); err != nil {
		t.Fatalf("ValidateCheckpointForRestore() rejected structurally valid checkpoint: %v", err)
	}
	if _, err := SealCheckpointForRestore(root); err != nil {
		t.Fatalf("SealCheckpointForRestore() rejected shim-produced checkpoint structure: %v", err)
	}
	if _, err := ValidateCheckpoint(root); err == nil {
		t.Fatal("ValidateCheckpoint() accepted a modified artifact")
	}

	manifestPath := filepath.Join(runtimeRoot, "manifest.json")
	invalidDigests := []string{"", strings.Repeat("0", 63), strings.Repeat("g", 64), strings.Repeat("A", 64)}
	for _, digest := range invalidDigests {
		manifest.VMState[0].SHA256 = digest
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manifestPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manifestPath, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := ValidateCheckpointForRestore(root); err == nil {
			t.Errorf("ValidateCheckpointForRestore() accepted invalid digest %q", digest)
		}
	}
}

func TestValidateDragonballCheckpointVMInventory(t *testing.T) {
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, checkpointRuntimeDir)
	write := func(rel, value string) (uint64, string) {
		t.Helper()
		path := filepath.Join(runtimeRoot, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(value))
		return uint64(len(value)), hex.EncodeToString(sum[:])
	}
	memoryPath := filepath.Join(runtimeRoot, "vm/memory")
	if err := os.MkdirAll(filepath.Dir(memoryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	memory, err := os.OpenFile(memoryPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	if err := memory.Close(); err != nil {
		t.Fatal(err)
	}
	memorySHA := strings.Repeat("0", sha256.Size*2)
	stateSize, stateSHA := write("vm/state", "state")
	rootfsSize, rootfsSHA := write("storage/rootfs.sparse", "rootfs")
	direct := false
	manifest := checkpointManifest{
		FormatVersion: checkpointFormatVersion, Hypervisor: "dragonball", VMVCPUs: 1, VMMemoryMB: 128,
		RuntimeFingerprint: "runtime", Tasks: []checkpointTask{{CheckpointKey: "main", TaskID: "task-main"}},
		VMState: []checkpointVMState{
			{File: "vm/memory", Format: flatSparseArtifactFormat, LogicalSize: 128 << 20, EncodedSize: 128 << 20, SHA256: memorySHA},
			{File: "vm/state", Format: vmArtifactRawFormat, LogicalSize: stateSize, EncodedSize: stateSize, SHA256: stateSHA},
		},
		Rootfs: []checkpointRootfs{{
			CheckpointKey: "main", File: "storage/rootfs.sparse", LogicalSize: 512 << 20, EncodedSize: rootfsSize, SHA256: rootfsSHA,
			Format: sparseArtifactFormat, DeviceID: "rootfs", DriverOption: "virtio-blk", VirtPath: "/dev/vda",
			IsDirect: &direct, AIO: "threads",
		}},
	}
	writeManifest := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runtimeRoot, "manifest.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest()
	if _, err := ValidateCheckpoint(root); err != nil {
		t.Fatalf("ValidateCheckpoint() rejected Dragonball inventory: %v", err)
	}

	manifest.Hypervisor = "qemu"
	writeManifest()
	if _, err := ValidateCheckpoint(root); err == nil {
		t.Fatal("ValidateCheckpoint() accepted sparse VM memory for QEMU")
	}
}
