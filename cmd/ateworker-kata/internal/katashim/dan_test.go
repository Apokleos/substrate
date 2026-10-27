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
	"os"
	"testing"
)

func TestWriteHostTapDANConfig(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteHostTapDANConfig(dir, "sandbox-1", HostTapDANConfig{
		NetNSPath: "/run/netns/actor", TapName: "tap0_kata", GuestMAC: "02:a8:1e:00:00:02",
		IPAddresses: []string{"169.254.17.2/30"}, MTU: 1500,
	})
	if err != nil {
		t.Fatalf("WriteHostTapDANConfig() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("DAN config was not written: %v", err)
	}
	if err := RemoveDANConfig(dir, "sandbox-1"); err != nil {
		t.Fatalf("RemoveDANConfig() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("DAN config remains after removal: %v", err)
	}
}

func TestWriteHostTapDANConfigRejectsMissingNetNS(t *testing.T) {
	_, err := WriteHostTapDANConfig(t.TempDir(), "sandbox-1", HostTapDANConfig{
		TapName: "tap0_kata", GuestMAC: "02:a8:1e:00:00:02", IPAddresses: []string{"169.254.17.2/30"}, MTU: 1500,
	})
	if err == nil {
		t.Fatal("WriteHostTapDANConfig() accepted an empty network namespace")
	}
}
