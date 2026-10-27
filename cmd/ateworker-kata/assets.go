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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim"
	"go.ate.dev/substrate/internal/resources"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func runtimeAssetIdentities(a runtimeAssets, digests map[string]string) ([]katashim.RuntimeAssetIdentity, error) {
	files := []struct {
		name string
		path string
	}{
		{assetQEMU, a.vmm},
		{assetKernel, a.kernel},
		{assetInitrd, a.initrd},
		{assetImage, a.image},
	}
	identities := make([]katashim.RuntimeAssetIdentity, 0, len(files))
	for _, file := range files {
		if file.path == "" {
			continue
		}
		digest := digests[file.name]
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
			return nil, fmt.Errorf("runtime asset %q has no valid verified SHA-256 identity", file.name)
		}
		info, err := os.Stat(file.path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("inspect runtime asset %q identity: %w", file.name, err)
		}
		identities = append(identities, katashim.RuntimeAssetIdentity{
			Path: file.path, Size: uint64(info.Size()), SHA256: digest,
		})
	}
	return identities, nil
}

const (
	assetShim       = "kata-shim"
	assetQEMU       = "kata-qemu"
	assetQEMUData   = "kata-qemu-data"
	assetDragonball = "kata-dragonball"
	assetFirmware   = "kata-firmware"
	assetKernel     = "kata-kernel"
	assetImage      = "kata-image"
	assetInitrd     = "kata-initrd"
	assetConfig     = "kata-config"
)

type runtimeAssets struct {
	shim, vmm, qemuData, firmware, kernel, image, initrd, config string
	effectiveConfig                                              []byte
}

func resolveRuntimeAssets(root string, paths map[string]string) (runtimeAssets, error) {
	var validationErrors field.ErrorList
	for name, path := range paths {
		if name == assetQEMUData {
			validationErrors = append(validationErrors, resources.ValidateRuntimeAssetDir(root, path, field.NewPath("runtime_asset_paths").Key(name))...)
		} else {
			validationErrors = append(validationErrors, resources.ValidateRuntimeAssetPath(root, path, field.NewPath("runtime_asset_paths").Key(name))...)
		}
	}
	if len(validationErrors) > 0 {
		return runtimeAssets{}, resources.ToAPIError(validationErrors)
	}
	if paths[assetDragonball] != "" {
		return runtimeAssets{}, fmt.Errorf("%q is invalid because Dragonball is built into kata-shim", assetDragonball)
	}
	if (paths[assetImage] == "") == (paths[assetInitrd] == "") {
		return runtimeAssets{}, errors.New("runtime assets must contain exactly one of kata-image or kata-initrd")
	}
	a := runtimeAssets{
		shim: paths[assetShim], vmm: paths[assetQEMU], qemuData: paths[assetQEMUData], firmware: paths[assetFirmware], kernel: paths[assetKernel],
		image: paths[assetImage], initrd: paths[assetInitrd], config: paths[assetConfig],
	}
	for name, path := range map[string]string{
		assetShim: a.shim, assetKernel: a.kernel, assetConfig: a.config,
	} {
		if path == "" {
			return runtimeAssets{}, fmt.Errorf("runtime assets are missing %q", name)
		}
	}
	for name, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if name == assetQEMUData && err == nil && info.IsDir() {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return runtimeAssets{}, fmt.Errorf("runtime asset %q is not a regular file: %w", name, err)
		}
	}
	executables := map[string]string{assetShim: a.shim}
	if a.vmm != "" {
		executables[assetQEMU] = a.vmm
	}
	for name, path := range executables {
		info, _ := os.Stat(path)
		if info.Mode().Perm()&0o111 == 0 {
			return runtimeAssets{}, fmt.Errorf("runtime asset %q is not executable", name)
		}
	}
	effective, err := renderRuntimeConfig(a)
	if err != nil {
		return runtimeAssets{}, err
	}
	if err := validateRuntimeConfigText(a, string(effective)); err != nil {
		return runtimeAssets{}, err
	}
	a.effectiveConfig = effective
	return a, nil
}

func validateRuntimeConfig(a runtimeAssets) error {
	data, err := renderRuntimeConfig(a)
	if err != nil {
		return err
	}
	return validateRuntimeConfigText(a, string(data))
}

func validateRuntimeConfigText(a runtimeAssets, text string) error {
	for name, path := range map[string]string{"selected-vmm": a.vmm, assetQEMUData: a.qemuData, assetFirmware: a.firmware, assetKernel: a.kernel, assetImage: a.image, assetInitrd: a.initrd} {
		if path != "" && !strings.Contains(text, filepath.Clean(path)) {
			return fmt.Errorf("kata config does not reference verified asset %q", name)
		}
	}
	sharedFS, passFD, dan, resourceAnnotations := 0, false, false, false
	hypervisorName, hypervisorNames := "", 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if strings.HasPrefix(line, "shared_fs") && strings.Contains(line, "=") {
			sharedFS++
			if strings.TrimSpace(strings.SplitN(line, "=", 2)[1]) != `"none"` {
				return fmt.Errorf("kata config requires shared_fs = \"none\"")
			}
		}
		if strings.HasPrefix(line, "passfd_listener_port") && strings.Contains(line, "=") {
			passFD = strings.TrimSpace(strings.SplitN(line, "=", 2)[1]) == "0"
		}
		if strings.HasPrefix(line, "dan_conf") && strings.Contains(line, "=") {
			dan = strings.Trim(strings.TrimSpace(strings.SplitN(line, "=", 2)[1]), `"`) == katashimDANDir()
		}
		if strings.HasPrefix(line, "hypervisor_name") && strings.Contains(line, "=") {
			hypervisorNames++
			hypervisorName = strings.Trim(strings.TrimSpace(strings.SplitN(line, "=", 2)[1]), `"`)
		}
		if strings.HasPrefix(line, "enable_annotations") && strings.Contains(line, "=") && strings.Contains(line, `"default_vcpus"`) && strings.Contains(line, `"default_memory"`) {
			resourceAnnotations = true
		}
	}
	if sharedFS != 1 || !passFD || !dan || !resourceAnnotations {
		return errors.New("kata config must contain one shared_fs=none, passfd_listener_port=0, the ateworker-kata DAN directory, and enable default_vcpus/default_memory annotations")
	}
	if hypervisorNames != 1 {
		return errors.New("kata config must contain exactly one hypervisor_name")
	}
	switch hypervisorName {
	case "qemu":
		if a.vmm == "" || a.qemuData == "" {
			return fmt.Errorf("QEMU config requires %q and %q assets", assetQEMU, assetQEMUData)
		}
	case "dragonball":
		if a.vmm != "" || a.qemuData != "" || a.firmware != "" {
			return errors.New("dragonball is built into kata-shim and must not use QEMU assets")
		}
	case "":
		return errors.New("kata config hypervisor_name must not be empty")
	default:
		return fmt.Errorf("unsupported Kata hypervisor %q", hypervisorName)
	}
	return nil
}

// renderRuntimeConfig derives an actor-local configuration from the verified
// base config. The base asset is commonly a hard link into atelet's cache and
// must remain immutable; only the selected hypervisor section is rewritten.
func renderRuntimeConfig(a runtimeAssets) ([]byte, error) {
	data, err := os.ReadFile(a.config)
	if err != nil {
		return nil, err
	}
	hypervisor := "dragonball"
	replacements := map[string]string{
		"kernel": a.kernel,
		"image":  a.image,
		"initrd": a.initrd,
	}
	if a.vmm != "" {
		hypervisor = "qemu"
		replacements["path"] = a.vmm
		replacements["qemu_data_dir"] = a.qemuData
		if a.firmware != "" {
			replacements["firmware"] = a.firmware
		}
	}
	for key, value := range replacements {
		if value == "" {
			delete(replacements, key)
		}
	}
	found := make(map[string]bool, len(replacements))
	section := ""
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		if section != "hypervisor."+hypervisor {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value, ok := replacements[key]
		if !ok {
			continue
		}
		if found[key] {
			return nil, fmt.Errorf("kata config contains duplicate %s.%s", section, key)
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		lines[i] = indent + key + " = " + strconv.Quote(filepath.Clean(value))
		found[key] = true
	}
	for key := range replacements {
		if !found[key] {
			return nil, fmt.Errorf("kata config is missing %s.%s", "hypervisor."+hypervisor, key)
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func materializeRuntimeConfig(root string, a *runtimeAssets) error {
	path := filepath.Join(root, ".kata-config.effective")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create effective Kata config: %w", err)
	}
	if _, err := f.Write(a.effectiveConfig); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write effective Kata config: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close effective Kata config: %w", err)
	}
	a.config = path
	return nil
}

func katashimDANDir() string { return "/run/kata-containers/dans" }
