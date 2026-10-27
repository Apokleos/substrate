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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	checkpointFormatVersion  = 16
	checkpointRuntimeDir     = "kata"
	vmArtifactRawFormat      = "raw"
	sparseArtifactFormat     = "kata-sparse-raw-v1"
	flatSparseArtifactFormat = "dragonball-flat-sparse-v1"
	sparseChunkSize          = uint64(1024 * 1024)
	sparseHeaderSize         = uint64(32)
	sparseRecordSize         = uint64(16)
)

type checkpointManifest struct {
	FormatVersion      uint32              `json:"format_version"`
	Hypervisor         string              `json:"hypervisor"`
	Tasks              []checkpointTask    `json:"tasks"`
	Rootfs             []checkpointRootfs  `json:"rootfs"`
	NetworkMACs        [][]uint8           `json:"network_macs"`
	VMVCPUs            uint32              `json:"vm_vcpus"`
	VMMemoryMB         uint32              `json:"vm_memory_mb"`
	VMState            []checkpointVMState `json:"vm_state"`
	RuntimeFingerprint string              `json:"runtime_fingerprint"`
	Template           json.RawMessage     `json:"template,omitempty"`
}

type checkpointTask struct {
	CheckpointKey string `json:"checkpoint_key"`
	TaskID        string `json:"task_id"`
}

type checkpointVMState struct {
	File        string `json:"file"`
	Format      string `json:"format"`
	LogicalSize uint64 `json:"logical_size"`
	EncodedSize uint64 `json:"encoded_size"`
	SHA256      string `json:"sha256"`
}

type checkpointRootfs struct {
	CheckpointKey      string                     `json:"checkpoint_key"`
	File               string                     `json:"file"`
	Format             string                     `json:"format"`
	DeviceID           string                     `json:"device_id"`
	Index              uint64                     `json:"index"`
	DriverOption       string                     `json:"driver_option"`
	VirtPath           string                     `json:"virt_path"`
	IsDirect           *bool                      `json:"is_direct"`
	DiscardUnmap       bool                       `json:"discard_unmap"`
	AIO                string                     `json:"aio"`
	QueueSize          uint32                     `json:"queue_size"`
	NumQueues          uint64                     `json:"num_queues"`
	LogicalSectorSize  uint32                     `json:"logical_sector_size"`
	PhysicalSectorSize uint32                     `json:"physical_sector_size"`
	SerialOverride     string                     `json:"serial_override"`
	LogicalSize        uint64                     `json:"logical_size"`
	EncodedSize        uint64                     `json:"encoded_size"`
	SHA256             string                     `json:"sha256"`
	ImmutableLower     *checkpointImmutableRootfs `json:"immutable_lower,omitempty"`
}

type checkpointImmutableRootfs struct {
	DeviceID           string `json:"device_id"`
	Index              uint64 `json:"index"`
	DriverOption       string `json:"driver_option"`
	VirtPath           string `json:"virt_path"`
	IsDirect           *bool  `json:"is_direct"`
	DiscardUnmap       bool   `json:"discard_unmap"`
	AIO                string `json:"aio"`
	QueueSize          uint32 `json:"queue_size"`
	NumQueues          uint64 `json:"num_queues"`
	LogicalSectorSize  uint32 `json:"logical_sector_size"`
	PhysicalSectorSize uint32 `json:"physical_sector_size"`
	SerialOverride     string `json:"serial_override"`
	Size               uint64 `json:"size"`
	SHA256             string `json:"sha256"`
}

// ValidateCheckpoint validates the format-15 identity and every referenced
// artifact, then returns all regular files relative to root for atelet.
func ValidateCheckpoint(root string) ([]string, error) {
	return validateCheckpoint(root, true)
}

// inspectCheckpointForRestore validates checkpoint structure without reading
// every artifact payload. The shim verifies artifact contents before use.
func inspectCheckpointForRestore(root string) ([]string, error) {
	return validateCheckpoint(root, false)
}

func validateCheckpoint(root string, verifyContents bool) ([]string, error) {
	validationStarted := time.Now()
	var hashElapsed time.Duration
	if !filepath.IsAbs(root) {
		return nil, errors.New("checkpoint path must be absolute")
	}
	runtimeRoot := filepath.Join(root, checkpointRuntimeDir)
	manifestBytes, err := readRegularFile(filepath.Join(runtimeRoot, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read checkpoint manifest: %w", err)
	}
	var manifest checkpointManifest
	dec := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode checkpoint manifest: %w", err)
	}
	if manifest.FormatVersion != checkpointFormatVersion {
		return nil, fmt.Errorf("checkpoint format %d, require %d", manifest.FormatVersion, checkpointFormatVersion)
	}
	if manifest.Hypervisor == "" || manifest.RuntimeFingerprint == "" || manifest.VMVCPUs == 0 || manifest.VMMemoryMB == 0 {
		return nil, errors.New("checkpoint manifest lacks runtime identity")
	}
	if len(manifest.Tasks) == 0 || len(manifest.Tasks) != len(manifest.Rootfs) || len(manifest.VMState) == 0 {
		return nil, errors.New("checkpoint task, rootfs, or VM-state inventory is empty or mismatched")
	}

	taskKeys := make(map[string]bool, len(manifest.Tasks))
	taskIDs := make(map[string]bool, len(manifest.Tasks))
	for _, task := range manifest.Tasks {
		if task.CheckpointKey == "" || !ValidID(task.TaskID) || taskKeys[task.CheckpointKey] || taskIDs[task.TaskID] {
			return nil, fmt.Errorf("invalid or duplicate checkpoint task %q=%q", task.CheckpointKey, task.TaskID)
		}
		taskKeys[task.CheckpointKey] = true
		taskIDs[task.TaskID] = true
	}
	rootfsKeys := make(map[string]bool, len(manifest.Rootfs))
	for _, item := range manifest.Rootfs {
		if item.CheckpointKey == "" || !taskKeys[item.CheckpointKey] || rootfsKeys[item.CheckpointKey] {
			return nil, fmt.Errorf("invalid or duplicate rootfs key %q", item.CheckpointKey)
		}
		if item.Format != "kata-sparse-raw-v1" || item.LogicalSize == 0 || item.EncodedSize == 0 || item.DeviceID == "" || item.DriverOption == "" || item.VirtPath == "" || item.AIO == "" {
			return nil, fmt.Errorf("rootfs %q lacks managed-device identity", item.CheckpointKey)
		}
		if err := validateArtifact(runtimeRoot, item.File, item.EncodedSize, item.SHA256, verifyContents, &hashElapsed); err != nil {
			return nil, fmt.Errorf("validate rootfs %q: %w", item.CheckpointKey, err)
		}
		if lower := item.ImmutableLower; lower != nil {
			if lower.DeviceID == "" || lower.DeviceID == item.DeviceID || lower.DriverOption == "" || lower.VirtPath == "" || lower.AIO == "" || lower.Size == 0 || !validSHA256(lower.SHA256) {
				return nil, fmt.Errorf("rootfs %q has invalid immutable lower identity", item.CheckpointKey)
			}
		}
		rootfsKeys[item.CheckpointKey] = true
	}
	seenVM := make(map[string]bool, len(manifest.VMState))
	dragonballMemory := false
	dragonballState := false
	for _, item := range manifest.VMState {
		clean := filepath.Clean(item.File)
		if filepath.Dir(clean) != "vm" || filepath.Base(clean) == "." || seenVM[clean] {
			return nil, fmt.Errorf("invalid or duplicate VM-state path %q", item.File)
		}
		if item.LogicalSize == 0 || item.EncodedSize == 0 {
			return nil, fmt.Errorf("VM state %q has an invalid size", item.File)
		}
		switch item.Format {
		case vmArtifactRawFormat:
			if item.LogicalSize != item.EncodedSize {
				return nil, fmt.Errorf("raw VM state %q has different logical and encoded sizes", item.File)
			}
		case sparseArtifactFormat:
			chunks := 1 + (item.LogicalSize-1)/sparseChunkSize
			if item.LogicalSize > ^uint64(0)-sparseHeaderSize ||
				chunks > (^uint64(0)-item.LogicalSize-sparseHeaderSize)/sparseRecordSize ||
				item.EncodedSize > item.LogicalSize+sparseHeaderSize+chunks*sparseRecordSize {
				return nil, fmt.Errorf("sparse VM state %q exceeds its canonical size bound", item.File)
			}
		case flatSparseArtifactFormat:
			if item.LogicalSize != item.EncodedSize {
				return nil, fmt.Errorf("flat sparse VM state %q has different logical and file sizes", item.File)
			}
		default:
			return nil, fmt.Errorf("VM state %q has unsupported format %q", item.File, item.Format)
		}
		if manifest.Hypervisor == "dragonball" {
			switch {
			case clean == "vm/memory" && item.Format == flatSparseArtifactFormat && item.LogicalSize == uint64(manifest.VMMemoryMB)*1024*1024:
				dragonballMemory = true
			case clean == "vm/state" && item.Format == vmArtifactRawFormat:
				dragonballState = true
			default:
				return nil, fmt.Errorf("unexpected Dragonball VM state %q", item.File)
			}
		} else if item.Format != vmArtifactRawFormat {
			return nil, fmt.Errorf("non-Dragonball VM state %q is sparse", item.File)
		}
		// The shim verifies the flat sparse logical digest. Its digest is over
		// canonical non-zero chunks rather than the file's physical byte stream.
		verifyArtifactContents := verifyContents && item.Format != flatSparseArtifactFormat
		if err := validateArtifact(runtimeRoot, item.File, item.EncodedSize, item.SHA256, verifyArtifactContents, &hashElapsed); err != nil {
			return nil, fmt.Errorf("validate VM state %q: %w", item.File, err)
		}
		seenVM[clean] = true
	}
	if manifest.Hypervisor == "dragonball" && (!dragonballMemory || !dragonballState || len(manifest.VMState) != 2) {
		return nil, errors.New("dragonball checkpoint requires memory and state VM artifacts")
	}

	var files []string
	err = filepath.WalkDir(runtimeRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("checkpoint entry %q is not a regular file", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	totalElapsed := time.Since(validationStarted)
	structureElapsed := totalElapsed - hashElapsed
	slog.Info("Kata checkpoint seal phase completed", "checkpoint_root", root, "stage", "structure-validation", "elapsed_us", structureElapsed.Microseconds(), "file_count", len(files))
	if verifyContents {
		slog.Info("Kata checkpoint seal phase completed", "checkpoint_root", root, "stage", "payload-sha256", "elapsed_us", hashElapsed.Microseconds())
	}
	return files, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

// PrepareCheckpointForRestore validates a downloaded checkpoint and makes its
// files immutable. Kata clones artifacts into private writable paths during
// restore and rejects writable source files.
func PrepareCheckpointForRestore(root string) error {
	files, err := inspectCheckpointForRestore(root)
	if err != nil {
		return err
	}
	return makeCheckpointReadOnly(root, files)
}

// SealCheckpointForRestore validates the structure of a checkpoint produced
// by the shim, makes its files immutable, and returns the artifact list. The
// shim records content digests while it creates the artifacts.
func SealCheckpointForRestore(root string) ([]string, error) {
	files, err := inspectCheckpointForRestore(root)
	if err != nil {
		return nil, err
	}
	if err := makeCheckpointReadOnly(root, files); err != nil {
		return nil, err
	}
	return files, nil
}

func makeCheckpointReadOnly(root string, files []string) error {
	startedAt := time.Now()
	for _, relative := range files {
		path, err := confinedPath(root, filepath.FromSlash(relative))
		if err != nil {
			return err
		}
		if err := os.Chmod(path, 0o400); err != nil {
			return fmt.Errorf("make checkpoint artifact %q read-only: %w", relative, err)
		}
	}
	slog.Info("Kata checkpoint seal phase completed", "checkpoint_root", root, "stage", "chmod-readonly", "elapsed_us", time.Since(startedAt).Microseconds(), "file_count", len(files))
	return nil
}

// ValidateCheckpointForRestore validates a preserved checkpoint without
// changing it and requires the source files to already be read-only.
func ValidateCheckpointForRestore(root string) error {
	files, err := inspectCheckpointForRestore(root)
	if err != nil {
		return err
	}
	for _, relative := range files {
		path, err := confinedPath(root, filepath.FromSlash(relative))
		if err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o222 != 0 {
			return fmt.Errorf("checkpoint artifact %q is writable", relative)
		}
	}
	return nil
}

func validateArtifact(root, relative string, size uint64, digest string, verifyContents bool, hashElapsed *time.Duration) error {
	if !validSHA256(digest) {
		return fmt.Errorf("invalid SHA-256 %q", digest)
	}
	path, err := confinedPath(root, relative)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != size {
		return fmt.Errorf("invalid type or size: got %d, require %d", info.Size(), size)
	}
	if !verifyContents {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	hashStarted := time.Now()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	*hashElapsed += time.Since(hashStarted)
	got := hex.EncodeToString(h.Sum(nil))
	if got != digest {
		return fmt.Errorf("sha256 mismatch: got %s, require %s", got, digest)
	}
	return nil
}

func confinedPath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("invalid manifest path %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest path escapes checkpoint: %q", relative)
	}
	return filepath.Join(root, clean), nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.ReadFile(path)
}
