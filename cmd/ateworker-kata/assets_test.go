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

//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeAssetIdentitiesBindVerifiedFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel := filepath.Join(dir, "kernel")
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image, []byte("image"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
	}
	identities, err := runtimeAssetIdentities(runtimeAssets{kernel: kernel, image: image}, map[string]string{
		assetKernel: digest("kernel"), assetImage: digest("image"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 || identities[0].Path != kernel || identities[0].Size != 6 {
		t.Fatalf("runtimeAssetIdentities() = %#v", identities)
	}
	if _, err := runtimeAssetIdentities(runtimeAssets{kernel: kernel}, nil); err == nil {
		t.Fatal("runtimeAssetIdentities() accepted a missing verified digest")
	}
}

func TestValidateRuntimeConfigAllowsFirmwareFromQEMUData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	config := filepath.Join(dir, "configuration.toml")
	assets := runtimeAssets{
		vmm:      filepath.Join(dir, "qemu"),
		qemuData: filepath.Join(dir, "qemu-data"),
		kernel:   filepath.Join(dir, "vmlinuz"),
		initrd:   filepath.Join(dir, "initrd.img"),
		config:   config,
	}
	contents := "[hypervisor.qemu]\n" +
		"path = \"" + assets.vmm + "\"\n" +
		"qemu_data_dir = \"" + assets.qemuData + "\"\n" +
		"kernel = \"" + assets.kernel + "\"\n" +
		"initrd = \"" + assets.initrd + "\"\n" +
		"hypervisor_name = \"qemu\"\n" +
		"shared_fs = \"none\"\npassfd_listener_port = 0\n" +
		"enable_annotations = [\"default_vcpus\", \"default_memory\"]\n" +
		"dan_conf = \"" + katashimDANDir() + "\"\n"
	if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeConfig(assets); err != nil {
		t.Fatalf("validateRuntimeConfig() with QEMU data firmware failed: %v", err)
	}

	assets.firmware = filepath.Join(dir, "bios-256k.bin")
	if err := validateRuntimeConfig(assets); err == nil {
		t.Fatal("validateRuntimeConfig() succeeded without the firmware path")
	}
	contents += "firmware = \"" + assets.firmware + "\"\n"
	if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeConfig(assets); err != nil {
		t.Fatalf("validateRuntimeConfig() failed: %v", err)
	}
	rendered, err := renderRuntimeConfig(assets)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{assets.vmm, assets.qemuData, assets.kernel, assets.initrd, assets.firmware} {
		if !strings.Contains(string(rendered), path) {
			t.Errorf("rendered config does not contain %q", path)
		}
	}
}

func TestValidateRuntimeConfigAllowsBuiltinDragonball(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	config := filepath.Join(dir, "configuration.toml")
	assets := runtimeAssets{
		kernel: filepath.Join(dir, "vmlinuz"),
		image:  filepath.Join(dir, "rootfs.img"),
		config: config,
	}
	contents := "[hypervisor.dragonball]\n" +
		"path = \"\"\n" +
		"kernel = \"" + assets.kernel + "\"\n" +
		"image = \"" + assets.image + "\"\n" +
		"hypervisor_name = \"dragonball\"\n" +
		"shared_fs = \"none\"\npassfd_listener_port = 0\n" +
		"enable_annotations = [\"default_vcpus\", \"default_memory\"]\n" +
		"dan_conf = \"" + katashimDANDir() + "\"\n"
	if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeConfig(assets); err != nil {
		t.Fatalf("validateRuntimeConfig() with built-in Dragonball failed: %v", err)
	}

	assets.vmm = filepath.Join(dir, "qemu")
	if err := validateRuntimeConfig(assets); err == nil {
		t.Fatal("validateRuntimeConfig() accepted a QEMU asset with Dragonball")
	}
}
