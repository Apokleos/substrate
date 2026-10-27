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
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/ttrpc"
	sandboxapi "go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim/sandboxapi"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestImmutableRootfsOptions(t *testing.T) {
	tasks := []Task{{
		CheckpointKey: "app",
		ID:            "sandbox-app",
		ImmutableRootfs: &ImmutableRootfs{
			Path: "/cache/rootfs.erofs", SHA256: strings.Repeat("a", 64), Size: 4096,
		},
	}}
	for _, test := range []struct {
		name        string
		includePath bool
		wantPath    string
	}{{name: "checkpoint"}, {name: "restore", includePath: true, wantPath: "/cache/rootfs.erofs"}} {
		t.Run(test.name, func(t *testing.T) {
			options, err := immutableRootfsOptions(tasks, test.includePath)
			if err != nil {
				t.Fatal(err)
			}
			var entries []immutableRootfsOptionEntry
			if err := json.Unmarshal([]byte(options[immutableRootfsOption]), &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].CheckpointKey != "app" || entries[0].Path != test.wantPath || entries[0].Size != 4096 {
				t.Fatalf("entries = %+v", entries)
			}
		})
	}
}

func TestAddRuntimeAssetOptions(t *testing.T) {
	identities := []RuntimeAssetIdentity{{Path: "/runtime/kernel", Size: 6, SHA256: "a"}}
	options, err := addRuntimeAssetOptions(nil, identities)
	if err != nil {
		t.Fatal(err)
	}
	var got []RuntimeAssetIdentity
	if err := json.Unmarshal([]byte(options[runtimeAssetIdentityOption]), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != identities[0] {
		t.Fatalf("addRuntimeAssetOptions() = %#v", got)
	}
}

func TestAddTrustedLocalCheckpointOption(t *testing.T) {
	if got := addTrustedLocalCheckpointOption(nil, false); got != nil {
		t.Fatalf("untrusted options = %#v, want nil", got)
	}
	got := addTrustedLocalCheckpointOption(nil, true)
	if got[trustedLocalCheckpointOption] != "true" {
		t.Fatalf("trusted option = %#v", got)
	}
}

type shutdownSandboxService struct {
	sandboxapi.TTRPCSandboxService
	err    error
	calls  int
	onCall func()
}

func (s *shutdownSandboxService) ShutdownSandbox(context.Context, *sandboxapi.ShutdownSandboxRequest) (*sandboxapi.ShutdownSandboxResponse, error) {
	s.calls++
	if s.onCall != nil {
		s.onCall()
	}
	return &sandboxapi.ShutdownSandboxResponse{}, s.err
}

func startSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		if !processExited(cmd.Process.Pid) {
			_ = cmd.Process.Kill()
		}
	})
	return cmd
}

func TestCreateTaskRequestPreservesRootfsMounts(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(bundle, "upper.raw")
	lower := filepath.Join(bundle, "lower.erofs")
	req, err := createTaskRequest(Task{
		ID: "sandbox-app", Bundle: bundle,
		Rootfs: []RootfsMount{
			{Type: "ext4", Source: upper, Options: []string{"rw", "loop"}},
			{Type: "erofs", Source: lower, Options: []string{"ro", "loop"}},
			{Type: "overlay", Source: "overlay", Options: []string{"X-containerd.mkdir.path=/run/ate"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Rootfs) != 3 {
		t.Fatalf("rootfs mounts = %d, want 3", len(req.Rootfs))
	}
	for i, want := range []RootfsMount{
		{Type: "ext4", Source: upper, Options: []string{"rw", "loop"}},
		{Type: "erofs", Source: lower, Options: []string{"ro", "loop"}},
		{Type: "overlay", Source: "overlay", Options: []string{"X-containerd.mkdir.path=/run/ate"}},
	} {
		got := req.Rootfs[i]
		if got.Type != want.Type || got.Source != want.Source || strings.Join(got.Options, ",") != strings.Join(want.Options, ",") {
			t.Errorf("rootfs[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestCreateTaskRequestRejectsRelativeBlockSource(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := createTaskRequest(Task{
		ID: "sandbox-app", Bundle: bundle,
		Rootfs: []RootfsMount{{Type: "erofs", Source: "relative.erofs"}},
	})
	if err == nil {
		t.Fatal("createTaskRequest succeeded with relative block source")
	}
}

func TestDeleteDoesNotTerminateShimWhenShutdownFails(t *testing.T) {
	cmd := startSleep(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	sbx := &shutdownSandboxService{err: errors.New("injected shutdown failure")}
	c := &Client{id: "sandbox-1", bundle: bundle, pid: cmd.Process.Pid, sbx: sbx}
	if err := c.Delete(context.Background(), nil); err == nil {
		t.Fatal("Delete() succeeded, want shutdown error")
	}
	if processExited(cmd.Process.Pid) {
		t.Fatal("Delete() terminated shim after ShutdownSandbox failed")
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("bundle removed after ShutdownSandbox failed: %v", err)
	}
}

func TestWaitForShimExitNotification(t *testing.T) {
	cmd := startSleep(t)
	exited := make(chan struct{})
	c := &Client{pid: cmd.Process.Pid, exited: exited}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	close(exited)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.waitForShimExit(ctx); err != nil {
		t.Fatalf("waitForShimExit(): %v", err)
	}
}

func TestWaitForShimExitNotificationHonorsContext(t *testing.T) {
	cmd := startSleep(t)
	c := &Client{pid: cmd.Process.Pid, exited: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.waitForShimExit(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForShimExit() error = %v, want deadline exceeded", err)
	}
}

func TestDeleteConvergesWhenShutdownResponseIsLost(t *testing.T) {
	cmd := startSleep(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	clientConn, shimConn := net.Pipe()
	transportClosed := make(chan struct{})
	allowExit := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, shimConn)
		close(transportClosed)
		<-allowExit
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		_ = shimConn.Close()
	}()
	t.Cleanup(func() {
		select {
		case <-allowExit:
		default:
			close(allowExit)
		}
	})
	sbx := &shutdownSandboxService{err: errors.New("injected lost response")}
	c := &Client{
		id: "sandbox-1", bundle: bundle, pid: cmd.Process.Pid,
		client: ttrpc.NewClient(clientConn), sbx: sbx,
	}
	if err := c.Delete(context.Background(), nil); err == nil {
		t.Fatal("Delete() succeeded while the ambiguous shim was still running")
	}
	select {
	case <-transportClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("Delete() did not close the ambiguous shutdown transport")
	}
	close(allowExit)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !processExited(cmd.Process.Pid) {
		time.Sleep(50 * time.Millisecond)
	}
	if err := c.Delete(context.Background(), nil); err != nil {
		t.Fatalf("Delete() retry after shim exit: %v", err)
	}
	if sbx.calls != 1 {
		t.Fatalf("ShutdownSandbox calls = %d, want 1", sbx.calls)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Fatalf("bundle remains after converged cleanup: %v", err)
	}
}

func TestReconnectTransport(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "shim.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	c := &Client{endpoint: "unix://" + socket, transportClosed: true}
	if err := c.reconnectTransport(context.Background()); err != nil {
		t.Fatalf("reconnectTransport(): %v", err)
	}
	conn := <-accepted
	t.Cleanup(func() { _ = conn.Close() })
	if c.client == nil || c.sbx == nil || c.ckpt == nil || c.tasks == nil || c.transportClosed {
		t.Fatal("reconnectTransport() did not rebuild all typed clients")
	}
	c.closeTransport()
}

func TestDeleteRetriesAmbiguousShutdownOnFreshTransport(t *testing.T) {
	cmd := startSleep(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	socket := filepath.Join(t.TempDir(), "shim.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := ttrpc.NewServer()
	if err != nil {
		t.Fatalf("new ttrpc server: %v", err)
	}
	retried := &shutdownSandboxService{onCall: func() {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
	}}
	sandboxapi.RegisterTTRPCSandboxService(srv, retried)
	go func() { _ = srv.Serve(context.Background(), listener) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = listener.Close()
	})

	first := &shutdownSandboxService{err: errors.New("injected unaccepted shutdown")}
	c := &Client{
		id: "sandbox-1", bundle: bundle, pid: cmd.Process.Pid,
		endpoint: "unix://" + socket, sbx: first,
	}
	if err := c.Delete(context.Background(), nil); err == nil {
		t.Fatal("first Delete() succeeded, want ambiguous shutdown error")
	}
	if processExited(cmd.Process.Pid) {
		t.Fatal("first Delete() terminated the live shim")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Delete(ctx, nil); err != nil {
		t.Fatalf("Delete() retry over fresh transport: %v", err)
	}
	if first.calls != 1 || retried.calls != 1 {
		t.Fatalf("shutdown calls = first:%d retry:%d, want 1 and 1", first.calls, retried.calls)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Fatalf("bundle remains after retried cleanup: %v", err)
	}
}

func TestDeleteWaitsForAcknowledgedShutdownAndCanRetry(t *testing.T) {
	cmd := startSleep(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	sbx := &shutdownSandboxService{}
	c := &Client{id: "sandbox-1", bundle: bundle, pid: cmd.Process.Pid, sbx: sbx}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.Delete(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Delete() error = %v, want deadline exceeded", err)
	}
	if processExited(cmd.Process.Pid) {
		t.Fatal("Delete() force-terminated shim after wait deadline")
	}
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatalf("finish fake shim cleanup: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Delete(ctx, nil); err != nil {
		t.Fatalf("Delete() retry: %v", err)
	}
	if sbx.calls != 1 {
		t.Fatalf("ShutdownSandbox calls = %d, want 1", sbx.calls)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Fatalf("bundle remains after completed cleanup: %v", err)
	}
}

func TestDeleteClosesTransportAfterAcknowledgedShutdown(t *testing.T) {
	cmd := startSleep(t)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	clientConn, shimConn := net.Pipe()
	t.Cleanup(func() { _ = shimConn.Close() })
	go func() {
		_, _ = io.Copy(io.Discard, shimConn)
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
	}()
	sbx := &shutdownSandboxService{}
	c := &Client{
		id: "sandbox-1", bundle: bundle, pid: cmd.Process.Pid,
		client: ttrpc.NewClient(clientConn), sbx: sbx,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Delete(ctx, nil); err != nil {
		t.Fatalf("Delete(): %v", err)
	}
	if sbx.calls != 1 {
		t.Fatalf("ShutdownSandbox calls = %d, want 1", sbx.calls)
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Fatalf("bundle remains after completed cleanup: %v", err)
	}
}

func TestStartRollsBackShimWhenStartCommandFails(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "spawned.pid")
	shim := filepath.Join(t.TempDir(), "fake-shim")
	script := `#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
if [ "$last" = "delete" ]; then
  if [ -f shim.pid ]; then kill -KILL "$(cat shim.pid)" 2>/dev/null || true; fi
  exit 0
fi
if [ "$last" = "start" ]; then
  sleep 300 >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "$pid" > shim.pid
  printf '%s\n' "$pid" > "$FAKE_SHIM_PID_FILE"
  exit 42
fi
exit 1
`
	if err := os.WriteFile(shim, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake shim: %v", err)
	}
	t.Setenv("FAKE_SHIM_PID_FILE", pidFile)
	_, err := Start(context.Background(), Config{
		Binary: shim, KataConfig: filepath.Join(t.TempDir(), "configuration.toml"),
		Root: root, SandboxID: "sandbox-1",
	})
	if err == nil {
		t.Fatal("Start() succeeded, want fake start error")
	}
	data, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("read spawned pid: %v", readErr)
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if parseErr != nil {
		t.Fatalf("parse spawned pid: %v", parseErr)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !processExited(pid) {
		time.Sleep(50 * time.Millisecond)
	}
	if !processExited(pid) {
		t.Fatalf("spawned shim process %d survived failed Start", pid)
	}
	if _, statErr := os.Stat(filepath.Join(root, "sandbox-1")); !os.IsNotExist(statErr) {
		t.Fatalf("shim bundle remains after failed Start: %v", statErr)
	}
}

func TestParseBootstrap(t *testing.T) {
	got, err := parseBootstrap([]byte(`{"version":3,"address":"unix:///run/test.sock","protocol":"ttrpc"}`))
	if err != nil {
		t.Fatalf("parseBootstrap() error = %v", err)
	}
	if got.Address != "unix:///run/test.sock" {
		t.Fatalf("parseBootstrap() address = %q", got.Address)
	}
	for _, bad := range []string{
		`{"version":2,"address":"unix:///run/test.sock","protocol":"ttrpc"}`,
		`{"version":3,"address":"tcp://127.0.0.1:1","protocol":"ttrpc"}`,
	} {
		if _, err := parseBootstrap([]byte(bad)); err == nil {
			t.Errorf("parseBootstrap(%s) succeeded, want error", bad)
		}
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"ate-123", "actor.name_1"} {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "..", "a/b", "actor id"} {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true", id)
		}
	}
}

func TestRuntimeOptions(t *testing.T) {
	const path = "/var/lib/ate/static-files/runsc-config"
	data, err := runtimeOptions(path)
	if err != nil {
		t.Fatalf("runtimeOptions() error = %v", err)
	}
	options := &anypb.Any{}
	if err := proto.Unmarshal(data, options); err != nil {
		t.Fatalf("unmarshal bootstrap Any: %v", err)
	}
	if options.TypeUrl != runtimeOptionsTypeURL {
		t.Fatalf("type URL = %q, want %q", options.TypeUrl, runtimeOptionsTypeURL)
	}
	number, wireType, n := protowire.ConsumeTag(options.Value)
	if n < 0 || number != 2 || wireType != protowire.BytesType {
		t.Fatalf("config_path tag = (%d, %v, %d), want field 2 bytes", number, wireType, n)
	}
	got, n := protowire.ConsumeString(options.Value[n:])
	if n < 0 || got != path {
		t.Fatalf("config_path = %q, want %q", got, path)
	}
}

func TestEnsureSandboxSpecSetsCgroupPath(t *testing.T) {
	dir := t.TempDir()
	if err := ensureSandboxSpec(dir, "sandbox-1"); err != nil {
		t.Fatalf("ensureSandboxSpec() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	if !strings.Contains(string(data), `"cgroupsPath":"ateworker-kata/sandbox-1"`) {
		t.Fatalf("config.json does not contain the sandbox cgroup path: %s", data)
	}
}

func TestSandboxAnnotations(t *testing.T) {
	got, err := sandboxAnnotations(CreateSandboxRequest{
		Annotations: map[string]string{"keep": "value"},
		CPUMilli:    1501, MemoryBytes: 513<<20 + 1,
	})
	if err != nil {
		t.Fatalf("sandboxAnnotations() error = %v", err)
	}
	if got[annotationDefaultVCPUs] != "2" || got[annotationDefaultMemory] != "514" || got["keep"] != "value" {
		t.Fatalf("sandboxAnnotations() = %v", got)
	}
	if _, err := sandboxAnnotations(CreateSandboxRequest{CPUMilli: 1}); err == nil {
		t.Fatal("sandboxAnnotations() accepted a missing memory limit")
	}
}

func TestPodSandboxConfig(t *testing.T) {
	config := podSandboxConfig("actor-1", map[string]string{"z": "last", "a": "first"})
	if config.TypeUrl != "runtime.v1.PodSandboxConfig" {
		t.Fatalf("type URL = %q", config.TypeUrl)
	}
	value := config.Value
	number, wireType, n := protowire.ConsumeTag(value)
	if n < 0 || number != 2 || wireType != protowire.BytesType {
		t.Fatalf("hostname tag = (%d, %v, %d)", number, wireType, n)
	}
	hostname, nValue := protowire.ConsumeString(value[n:])
	if nValue < 0 || hostname != "actor-1" {
		t.Fatalf("hostname = %q", hostname)
	}
	value = value[n+nValue:]
	var got []string
	for len(value) > 0 {
		number, wireType, n = protowire.ConsumeTag(value)
		if n < 0 || number != 7 || wireType != protowire.BytesType {
			t.Fatalf("annotation tag = (%d, %v, %d)", number, wireType, n)
		}
		entry, nEntry := protowire.ConsumeBytes(value[n:])
		if nEntry < 0 {
			t.Fatalf("invalid annotation entry: %d", nEntry)
		}
		_, _, keyTag := protowire.ConsumeTag(entry)
		key, keyLen := protowire.ConsumeString(entry[keyTag:])
		entry = entry[keyTag+keyLen:]
		_, _, valueTag := protowire.ConsumeTag(entry)
		entryValue, valueLen := protowire.ConsumeString(entry[valueTag:])
		if keyTag < 0 || keyLen < 0 || valueTag < 0 || valueLen < 0 {
			t.Fatal("invalid annotation map entry")
		}
		got = append(got, key+"="+entryValue)
		value = value[n+nEntry:]
	}
	if strings.Join(got, ",") != "a=first,z=last" {
		t.Fatalf("annotations = %v", got)
	}
}
