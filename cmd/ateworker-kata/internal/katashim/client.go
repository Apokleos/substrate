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

// Package katashim drives the Kata shim wire APIs needed by ateworker-kata.
package katashim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	taskapi "github.com/containerd/containerd/api/runtime/task/v3"
	containerdtypes "github.com/containerd/containerd/api/types"
	tasktypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/ttrpc"
	sandboxapi "go.ate.dev/substrate/cmd/ateworker-kata/internal/katashim/sandboxapi"
	"go.ate.dev/substrate/internal/pidfd"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	supportedShimBootstrapVersion = 3
	vmRestoredTaskCheckpoint      = "vm-restored-v1"
	kataShimConfigPathEnv         = "KATA_SHIM_CONFIG_PATH"
	runtimeOptionsTypeURL         = "type.googleapis.com/runtimeoptions.v1.Options"
	annotationDefaultVCPUs        = "io.katacontainers.config.hypervisor.default_vcpus"
	annotationDefaultMemory       = "io.katacontainers.config.hypervisor.default_memory"
	immutableRootfsOption         = "io.katacontainers.checkpoint.rootfs.immutable"
)

// Config identifies one shim process. Every path is private to the selected
// version of the runtime assets; no process-global Kata configuration is used.
type Config struct {
	Binary     string
	KataConfig string
	Root       string
	SandboxID  string
	Namespace  string
	Address    string
}

// Task is one workload container managed by the sandbox shim.
type Task struct {
	CheckpointKey   string
	ID              string
	Bundle          string
	Rootfs          []RootfsMount
	Terminal        bool
	Stdin           string
	Stdout          string
	Stderr          string
	Options         *anypb.Any
	ImmutableRootfs *ImmutableRootfs
}

// ImmutableRootfs identifies the node-local readonly lower used by a task.
type ImmutableRootfs struct {
	Path   string
	SHA256 string
	Size   uint64
}

type immutableRootfsOptionEntry struct {
	CheckpointKey string `json:"checkpoint_key"`
	Path          string `json:"path,omitempty"`
	Size          uint64 `json:"size"`
	SHA256        string `json:"sha256"`
}

func immutableRootfsOptions(tasks []Task, includePath bool) (map[string]string, error) {
	entries := make([]immutableRootfsOptionEntry, 0, len(tasks))
	for _, task := range tasks {
		if task.ImmutableRootfs == nil {
			continue
		}
		identity := task.ImmutableRootfs
		_, digestErr := hex.DecodeString(identity.SHA256)
		if identity.Size == 0 || len(identity.SHA256) != sha256.Size*2 || digestErr != nil || (includePath && !filepath.IsAbs(identity.Path)) {
			return nil, fmt.Errorf("task %q has invalid immutable rootfs identity", task.ID)
		}
		entry := immutableRootfsOptionEntry{
			CheckpointKey: task.CheckpointKey,
			Size:          identity.Size,
			SHA256:        strings.ToLower(identity.SHA256),
		}
		if includePath {
			entry.Path = identity.Path
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	value, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("encode immutable rootfs inventory: %w", err)
	}
	return map[string]string{immutableRootfsOption: string(value)}, nil
}

// RootfsMount is one host-side mount passed to the Kata Task API.
type RootfsMount struct {
	Type    string
	Source  string
	Options []string
}

// CreateSandboxRequest is the input used by ateworker-kata.
type CreateSandboxRequest struct {
	Hostname    string
	NetNSPath   string
	Annotations map[string]string
	CPUMilli    int64
	MemoryBytes int64
}

// Client owns one shim process and its typed TTRPC clients.
type Client struct {
	id       string
	bundle   string
	pid      int
	endpoint string
	exited   <-chan struct{}

	mu                sync.Mutex
	closed            bool
	shutdownRequested bool
	transportClosed   bool
	client            *ttrpc.Client
	sbx               sandboxapi.TTRPCSandboxService
	ckpt              sandboxapi.TTRPCCheckpointService
	tasks             taskapi.TTRPCTaskService
}

type bootstrapResult struct {
	Version  int    `json:"version"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

// Start launches the shim and connects to its Sandbox, Checkpoint, and Task APIs.
func Start(ctx context.Context, cfg Config) (_ *Client, retErr error) {
	if !filepath.IsAbs(cfg.Binary) || !filepath.IsAbs(cfg.KataConfig) || !filepath.IsAbs(cfg.Root) {
		return nil, errors.New("shim binary, Kata config, and root must be absolute paths")
	}
	if !ValidID(cfg.SandboxID) {
		return nil, fmt.Errorf("invalid sandbox ID %q", cfg.SandboxID)
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "ateworker-kata"
	}
	if cfg.Address == "" {
		cfg.Address = "unix:///run/ateworker-kata/shim.sock"
	}
	bundle := filepath.Join(cfg.Root, cfg.SandboxID)
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return nil, fmt.Errorf("create shim bundle: %w", err)
	}
	startAttempted := false
	defer func() {
		if retErr != nil {
			if startAttempted {
				rollbackStartedShim(cfg.Binary, argsForShim(cfg, bundle), bundle, cfg.KataConfig)
			}
			_ = os.RemoveAll(bundle)
		}
	}()
	if err := ensureSandboxSpec(bundle, cfg.SandboxID); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(filepath.Join(bundle, "log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create shim log: %w", err)
	}
	if err := logFile.Close(); err != nil {
		return nil, fmt.Errorf("close shim log: %w", err)
	}

	args := argsForShim(cfg, bundle)
	cleanup := exec.Command(cfg.Binary, append(args, "delete")...)
	cleanup.Dir = bundle
	cleanup.Env = append(os.Environ(), kataShimConfigPathEnv+"="+cfg.KataConfig)
	_, _ = cleanup.CombinedOutput()

	bootstrapInput, err := runtimeOptions(cfg.KataConfig)
	if err != nil {
		return nil, fmt.Errorf("encode Kata runtime options: %w", err)
	}
	cmd := exec.CommandContext(ctx, cfg.Binary, append(args, "start")...)
	cmd.Dir = bundle
	cmd.Stdin = bytes.NewReader(bootstrapInput)
	startAttempted = true
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("start Kata shim: %w: %s", err, strings.TrimSpace(string(out)))
	}
	boot, err := parseBootstrap(out)
	if err != nil {
		return nil, err
	}
	pidBytes, err := os.ReadFile(filepath.Join(bundle, "shim.pid"))
	if err != nil {
		return nil, fmt.Errorf("read shim.pid: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("invalid shim.pid %q", strings.TrimSpace(string(pidBytes)))
	}
	exited, err := pidfd.Exited(pid)
	if err != nil {
		slog.Warn("Kata shim pidfd unavailable; using polling", "pid", pid, "err", err)
	}

	conn, err := net.DialTimeout("unix", strings.TrimPrefix(boot.Address, "unix://"), 10*time.Second)
	if err != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		return nil, fmt.Errorf("dial shim %q: %w", boot.Address, err)
	}
	tc := ttrpc.NewClient(conn)
	return &Client{
		id: cfg.SandboxID, bundle: bundle, pid: pid, endpoint: boot.Address, exited: exited,
		client: tc,
		sbx:    sandboxapi.NewTTRPCSandboxClient(tc),
		ckpt:   sandboxapi.NewTTRPCCheckpointClient(tc),
		tasks:  taskapi.NewTTRPCTaskClient(tc),
	}, nil
}

func argsForShim(cfg Config, bundle string) []string {
	return []string{"-id", cfg.SandboxID, "-namespace", cfg.Namespace, "-address", cfg.Address, "-bundle", bundle, "-publish-binary", "/bin/true"}
}

func rollbackStartedShim(binary string, args []string, bundle, config string) {
	var pid int
	if pidBytes, err := os.ReadFile(filepath.Join(bundle, "shim.pid")); err == nil {
		pid, _ = strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cleanup := exec.CommandContext(cleanupCtx, binary, append(args, "delete")...)
	cleanup.Dir = bundle
	cleanup.Env = append(os.Environ(), kataShimConfigPathEnv+"="+config)
	_, _ = cleanup.CombinedOutput()
	if pid > 0 && !processExited(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && !processExited(pid) {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// runtimeOptions builds the legacy Any accepted on shim start's stdin. The
// nested runtimeoptions.v1.Options message has config_path at field 2. Passing
// the version-pinned path this way lets the shim hand it to its child through
// KATA_SHIM_CONFIG_PATH without using the operator-only KATA_CONF_FILE override.
func runtimeOptions(configPath string) ([]byte, error) {
	value := protowire.AppendTag(nil, 2, protowire.BytesType)
	value = protowire.AppendString(value, configPath)
	return proto.Marshal(&anypb.Any{TypeUrl: runtimeOptionsTypeURL, Value: value})
}

func parseBootstrap(out []byte) (*bootstrapResult, error) {
	var boot bootstrapResult
	if err := json.Unmarshal(out, &boot); err != nil {
		return nil, fmt.Errorf("decode shim bootstrap: %w", err)
	}
	if boot.Version != supportedShimBootstrapVersion {
		return nil, fmt.Errorf("shim bootstrap version %d, require %d", boot.Version, supportedShimBootstrapVersion)
	}
	if boot.Protocol != "ttrpc" || !strings.HasPrefix(boot.Address, "unix://") {
		return nil, fmt.Errorf("unsupported shim endpoint %q+%q", boot.Protocol, boot.Address)
	}
	return &boot, nil
}

func ensureSandboxSpec(bundle, sandboxID string) error {
	if err := os.MkdirAll(filepath.Join(bundle, "rootfs"), 0o700); err != nil {
		return err
	}
	spec := fmt.Sprintf(`{"ociVersion":"1.2.0","process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/pause"],"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":"ateworker-kata/%s","namespaces":[]}}`, sandboxID)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(spec), 0o600); err != nil {
		return fmt.Errorf("write sandbox spec: %w", err)
	}
	return nil
}

// CreateSandbox creates the Kata sandbox but does not start it.
func (c *Client) CreateSandbox(ctx context.Context, req CreateSandboxRequest) error {
	annotations, err := sandboxAnnotations(req)
	if err != nil {
		return err
	}
	_, err = c.sbx.CreateSandbox(ctx, &sandboxapi.CreateSandboxRequest{
		SandboxID: c.id, BundlePath: c.bundle, Hostname: req.Hostname,
		NetnsPath: req.NetNSPath, Annotations: annotations,
	})
	if err != nil {
		return fmt.Errorf("create Kata sandbox %q: %w", c.id, err)
	}
	return nil
}

func resourceAnnotations(cpuMilli, memoryBytes int64) (map[string]string, error) {
	if cpuMilli <= 0 || memoryBytes <= 0 {
		return nil, errors.New("positive CPU and memory limits are required")
	}
	// Kata's default_vcpus is a VM CPU count, so a fractional CPU request must
	// still receive one whole virtual CPU. Memory is expressed in MiB and
	// rounded up so the VM never receives less than the scheduler reserved.
	vcpus := (cpuMilli + 999) / 1000
	memoryMiB := (memoryBytes + (1 << 20) - 1) >> 20
	annotations := map[string]string{
		annotationDefaultVCPUs:  strconv.FormatInt(vcpus, 10),
		annotationDefaultMemory: strconv.FormatInt(memoryMiB, 10),
	}
	return annotations, nil
}

func sandboxAnnotations(req CreateSandboxRequest) (map[string]string, error) {
	resources, err := resourceAnnotations(req.CPUMilli, req.MemoryBytes)
	if err != nil {
		return nil, err
	}
	annotations := cloneMap(req.Annotations)
	for key, value := range resources {
		annotations[key] = value
	}
	return annotations, nil
}

// podSandboxConfig encodes only the PodSandboxConfig fields consumed by Kata
// restore: hostname (field 2) and annotations (field 7). Keeping this small
// avoids pulling the complete Kubernetes CRI API into ateworker-kata.
func podSandboxConfig(hostname string, annotations map[string]string) *anypb.Any {
	value := protowire.AppendTag(nil, 2, protowire.BytesType)
	value = protowire.AppendString(value, hostname)
	keys := make([]string, 0, len(annotations))
	for key := range annotations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := protowire.AppendTag(nil, 1, protowire.BytesType)
		entry = protowire.AppendString(entry, key)
		entry = protowire.AppendTag(entry, 2, protowire.BytesType)
		entry = protowire.AppendString(entry, annotations[key])
		value = protowire.AppendTag(value, 7, protowire.BytesType)
		value = protowire.AppendBytes(value, entry)
	}
	return &anypb.Any{TypeUrl: "runtime.v1.PodSandboxConfig", Value: value}
}

// StartSandbox starts a previously created Kata sandbox.
func (c *Client) StartSandbox(ctx context.Context) error {
	resp, err := c.sbx.StartSandbox(ctx, &sandboxapi.StartSandboxRequest{SandboxID: c.id})
	if err != nil {
		return fmt.Errorf("start Kata sandbox %q: %w", c.id, err)
	}
	if resp.GetPid() == 0 || resp.GetCreatedAt() == nil {
		return errors.New("kata StartSandbox returned no pid or creation time")
	}
	return nil
}

// WaitSandbox waits for the sandbox to exit. Callers use it to notice an
// unexpected shim/VMM exit instead of retaining a dead actor as running.
func (c *Client) WaitSandbox(ctx context.Context) (*sandboxapi.WaitSandboxResponse, error) {
	resp, err := c.sbx.WaitSandbox(ctx, &sandboxapi.WaitSandboxRequest{SandboxID: c.id})
	if err != nil {
		return nil, fmt.Errorf("wait for Kata sandbox %q: %w", c.id, err)
	}
	return resp, nil
}

// CreateAndStartTasks creates then starts all tasks.
func (c *Client) CreateAndStartTasks(ctx context.Context, tasks []Task) (retErr error) {
	created := make([]string, 0, len(tasks))
	defer func() {
		if retErr == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		for i := len(created) - 1; i >= 0; i-- {
			_ = c.killAndDeleteTask(cleanupCtx, created[i])
		}
	}()
	for _, task := range tasks {
		req, err := createTaskRequest(task)
		if err != nil {
			return err
		}
		if _, err := c.tasks.Create(ctx, req); err != nil {
			return fmt.Errorf("create task %q: %w", task.ID, err)
		}
		created = append(created, task.ID)
	}
	for _, task := range tasks {
		if _, err := c.tasks.Start(ctx, &taskapi.StartRequest{ID: task.ID}); err != nil {
			return fmt.Errorf("start task %q: %w", task.ID, err)
		}
	}
	return nil
}

func createTaskRequest(task Task) (*taskapi.CreateTaskRequest, error) {
	if !ValidID(task.ID) || !filepath.IsAbs(task.Bundle) || len(task.Rootfs) == 0 {
		return nil, errors.New("task ID, absolute bundle, and rootfs mounts are required")
	}
	if _, err := os.Stat(filepath.Join(task.Bundle, "config.json")); err != nil {
		return nil, fmt.Errorf("task %q bundle: %w", task.ID, err)
	}
	rootfs := make([]*containerdtypes.Mount, 0, len(task.Rootfs))
	for _, mount := range task.Rootfs {
		if mount.Type == "" || mount.Source == "" {
			return nil, errors.New("rootfs mount type and source are required")
		}
		if mount.Type != "overlay" && !filepath.IsAbs(mount.Source) {
			return nil, fmt.Errorf("rootfs %s source must be absolute: %q", mount.Type, mount.Source)
		}
		rootfs = append(rootfs, &containerdtypes.Mount{
			Type: mount.Type, Source: mount.Source, Options: append([]string(nil), mount.Options...),
		})
	}
	return &taskapi.CreateTaskRequest{
		ID: task.ID, Bundle: task.Bundle, Terminal: task.Terminal,
		Stdin: task.Stdin, Stdout: task.Stdout, Stderr: task.Stderr,
		Rootfs:  rootfs,
		Options: task.Options,
	}, nil
}

// Checkpoint writes one runtime-owned checkpoint to output.
const runtimeAssetIdentityOption = "io.katacontainers.checkpoint.runtime-assets"
const trustedLocalCheckpointOption = "io.katacontainers.checkpoint.trusted-local"

// RuntimeAssetIdentity describes content atelet already verified before it
// hard-linked the runtime asset into the actor's private asset directory.
type RuntimeAssetIdentity struct {
	Path   string `json:"path"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

func addRuntimeAssetOptions(options map[string]string, identities []RuntimeAssetIdentity) (map[string]string, error) {
	if len(identities) == 0 {
		return options, nil
	}
	data, err := json.Marshal(identities)
	if err != nil {
		return nil, fmt.Errorf("encode runtime asset identities: %w", err)
	}
	if options == nil {
		options = make(map[string]string, 1)
	}
	options[runtimeAssetIdentityOption] = string(data)
	return options, nil
}

func addTrustedLocalCheckpointOption(options map[string]string, trusted bool) map[string]string {
	if !trusted {
		return options
	}
	if options == nil {
		options = make(map[string]string, 1)
	}
	options[trustedLocalCheckpointOption] = "true"
	return options
}

func (c *Client) Checkpoint(ctx context.Context, output string, tasks []Task, identities []RuntimeAssetIdentity) error {
	if err := prepareEmptyDir(output); err != nil {
		return fmt.Errorf("prepare checkpoint output: %w", err)
	}
	runtimeOutput := filepath.Join(output, checkpointRuntimeDir)
	if err := prepareEmptyDir(runtimeOutput); err != nil {
		return fmt.Errorf("prepare Kata checkpoint output: %w", err)
	}
	containers := make([]*sandboxapi.CheckpointContainer, 0, len(tasks))
	for _, task := range tasks {
		if task.CheckpointKey == "" || !ValidID(task.ID) {
			return errors.New("checkpoint task key and ID are required")
		}
		containers = append(containers, &sandboxapi.CheckpointContainer{ID: task.ID, Name: task.CheckpointKey})
	}
	options, err := immutableRootfsOptions(tasks, false)
	if err != nil {
		return err
	}
	options, err = addRuntimeAssetOptions(options, identities)
	if err != nil {
		return err
	}
	if _, err := c.ckpt.Checkpoint(ctx, &sandboxapi.CheckpointRequest{
		SandboxID: c.id, OutputPath: runtimeOutput, Containers: containers, Options: options,
	}); err != nil {
		return fmt.Errorf("checkpoint Kata sandbox %q: %w", c.id, err)
	}
	return nil
}

// Restore restores the VM and adopts its task records into Task v3.
func (c *Client) Restore(ctx context.Context, checkpoint, netns, hostname string, tasks []Task, identities []RuntimeAssetIdentity, cpuMilli, memoryBytes int64, trustedLocal bool) (_ []string, retErr error) {
	annotations, err := resourceAnnotations(cpuMilli, memoryBytes)
	if err != nil {
		return nil, err
	}
	containers := make([]*sandboxapi.RestoreContainer, 0, len(tasks))
	for _, task := range tasks {
		if task.CheckpointKey == "" || !ValidID(task.ID) || !filepath.IsAbs(task.Bundle) {
			return nil, errors.New("restore task key, ID, and absolute bundle are required")
		}
		containers = append(containers, &sandboxapi.RestoreContainer{ID: task.ID, Name: task.CheckpointKey})
	}
	options, err := immutableRootfsOptions(tasks, true)
	if err != nil {
		return nil, err
	}
	options, err = addRuntimeAssetOptions(options, identities)
	if err != nil {
		return nil, err
	}
	options = addTrustedLocalCheckpointOption(options, trustedLocal)
	restoreRPCStarted := time.Now()
	resp, err := c.ckpt.Restore(ctx, &sandboxapi.RestoreRequest{
		SandboxID: c.id, CheckpointPath: filepath.Join(checkpoint, checkpointRuntimeDir),
		SandboxConfig: podSandboxConfig(hostname, annotations), NetnsPath: netns,
		Containers: containers, Options: options,
	})
	slog.Info("Kata shim restore phase completed", "sandbox_id", c.id, "stage", "restore-rpc", "elapsed_us", time.Since(restoreRPCStarted).Microseconds(), "success", err == nil)
	if err != nil {
		return nil, fmt.Errorf("restore Kata sandbox %q: %w", c.id, err)
	}
	if err := validateRestoreResult(containers, resp); err != nil {
		return nil, err
	}

	adopted := make([]string, 0, len(tasks))
	defer func() {
		if retErr == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		for i := len(adopted) - 1; i >= 0; i-- {
			_ = c.killAndDeleteTask(cleanupCtx, adopted[i])
		}
	}()
	adoptStarted := time.Now()
	for _, task := range tasks {
		if _, err := c.tasks.Create(ctx, &taskapi.CreateTaskRequest{
			ID: task.ID, Bundle: task.Bundle, Terminal: task.Terminal,
			Stdin: task.Stdin, Stdout: task.Stdout, Stderr: task.Stderr,
			Options: task.Options, Checkpoint: vmRestoredTaskCheckpoint,
		}); err != nil {
			return nil, fmt.Errorf("adopt VM-restored task %q: %w", task.ID, err)
		}
		adopted = append(adopted, task.ID)
	}
	slog.Info("Kata shim restore phase completed", "sandbox_id", c.id, "stage", "task-adopt", "elapsed_us", time.Since(adoptStarted).Microseconds(), "task_count", len(adopted))
	stateStarted := time.Now()
	for _, id := range adopted {
		state, err := c.tasks.State(ctx, &taskapi.StateRequest{ID: id})
		if err != nil {
			return nil, fmt.Errorf("state restored task %q: %w", id, err)
		}
		if state.GetStatus() != tasktypes.Status_CREATED {
			return nil, fmt.Errorf("restored task %q is %s, require CREATED", id, state.GetStatus())
		}
	}
	slog.Info("Kata shim restore phase completed", "sandbox_id", c.id, "stage", "task-state", "elapsed_us", time.Since(stateStarted).Microseconds(), "task_count", len(adopted))
	return adopted, nil
}

// StartRestoredTasks starts tasks returned in CREATED state by Restore.
func (c *Client) StartRestoredTasks(ctx context.Context, ids []string) error {
	startedAt := time.Now()
	started := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := c.tasks.Start(ctx, &taskapi.StartRequest{ID: id}); err != nil {
			for _, startedID := range started {
				_, _ = c.tasks.Kill(context.WithoutCancel(ctx), &taskapi.KillRequest{ID: startedID, Signal: uint32(syscall.SIGKILL), All: true})
			}
			return fmt.Errorf("start restored task %q: %w", id, err)
		}
		started = append(started, id)
	}
	slog.Info("Kata shim restore phase completed", "sandbox_id", c.id, "stage", "task-start", "elapsed_us", time.Since(startedAt).Microseconds(), "task_count", len(started))
	return nil
}

// Delete stops and deletes tasks, asks the sandbox to shut down, and closes the shim.
func (c *Client) Delete(ctx context.Context, tasks []Task) error {
	deleteStarted := time.Now()
	if processExited(c.pid) {
		return c.Close()
	}
	if c.shutdownHasStarted() {
		if err := c.waitForShimExit(ctx); err != nil {
			return err
		}
		return c.Close()
	}
	if c.transportNeedsReconnect() {
		if err := c.reconnectTransport(ctx); err != nil {
			if processExited(c.pid) {
				return c.Close()
			}
			return fmt.Errorf("reconnect to Kata shim %d: %w", c.pid, err)
		}
	}
	var gracefulErrs []error
	tasksStarted := time.Now()
	for i := len(tasks) - 1; i >= 0; i-- {
		if err := c.killAndDeleteTask(ctx, tasks[i].ID); err != nil {
			gracefulErrs = append(gracefulErrs, err)
		}
	}
	slog.Info("Kata shim cleanup phase completed", "sandbox_id", c.id, "stage", "task-kill-delete", "elapsed_us", time.Since(tasksStarted).Microseconds(), "task_count", len(tasks))
	shutdownStarted := time.Now()
	if _, err := c.sbx.ShutdownSandbox(ctx, &sandboxapi.ShutdownSandboxRequest{SandboxID: c.id}); err != nil {
		gracefulErrs = append(gracefulErrs, fmt.Errorf("shutdown sandbox %q: %w", c.id, err))
		// The request may have reached the shim even though its response was
		// lost. Drop this transport so accepted shutdown can finish; a live
		// shim is reconnected on the next lifecycle retry.
		c.closeTransport()
		if processExited(c.pid) {
			return c.Close()
		}
		return errors.Join(gracefulErrs...)
	}
	slog.Info("Kata shim cleanup phase completed", "sandbox_id", c.id, "stage", "shutdown-sandbox-rpc", "elapsed_us", time.Since(shutdownStarted).Microseconds())
	c.markShutdownStarted()
	// runtime-rs stops its ttrpc server only after all accepted connections are
	// gone. Close our transport after shutdown is acknowledged so the shim can
	// finish its own cleanup and exit; this does not terminate the shim process.
	c.closeTransport()
	waitStarted := time.Now()
	if err := c.waitForShimExit(ctx); err != nil {
		return errors.Join(append(gracefulErrs, err)...)
	}
	slog.Info("Kata shim cleanup phase completed", "sandbox_id", c.id, "stage", "wait-shim-exit", "elapsed_us", time.Since(waitStarted).Microseconds())
	closeErr := c.Close()
	slog.Info("Kata shim cleanup phase completed", "sandbox_id", c.id, "stage", "delete-total", "elapsed_us", time.Since(deleteStarted).Microseconds())
	if closeErr == nil {
		// Once the exact shim process is gone, task and sandbox cleanup errors no
		// longer describe live resources and must not pin the actor indefinitely.
		return nil
	}
	return errors.Join(append(gracefulErrs, closeErr)...)
}

func (c *Client) closeTransport() {
	c.mu.Lock()
	tc := c.client
	c.transportClosed = true
	c.client = nil
	c.sbx = nil
	c.ckpt = nil
	c.tasks = nil
	c.mu.Unlock()
	if tc != nil {
		_ = tc.Close()
	}
}

func (c *Client) transportNeedsReconnect() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transportClosed && !c.closed
}

func (c *Client) reconnectTransport(ctx context.Context) error {
	c.mu.Lock()
	if !c.transportClosed || c.closed {
		c.mu.Unlock()
		return nil
	}
	endpoint := c.endpoint
	c.mu.Unlock()

	if !strings.HasPrefix(endpoint, "unix://") {
		return fmt.Errorf("unsupported shim endpoint %q", endpoint)
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", strings.TrimPrefix(endpoint, "unix://"))
	if err != nil {
		return err
	}
	tc := ttrpc.NewClient(conn)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = tc.Close()
		return nil
	}
	if !c.transportClosed {
		_ = tc.Close()
		return nil
	}
	c.client = tc
	c.sbx = sandboxapi.NewTTRPCSandboxClient(tc)
	c.ckpt = sandboxapi.NewTTRPCCheckpointClient(tc)
	c.tasks = taskapi.NewTTRPCTaskClient(tc)
	c.transportClosed = false
	return nil
}

func (c *Client) shutdownHasStarted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shutdownRequested
}

func (c *Client) markShutdownStarted() {
	c.mu.Lock()
	c.shutdownRequested = true
	c.mu.Unlock()
}

func (c *Client) waitForShimExit(ctx context.Context) error {
	if c.exited != nil {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Kata shim %d to finish sandbox cleanup: %w", c.pid, ctx.Err())
		case <-c.exited:
		}
		backoff := time.Millisecond
		for !processExited(c.pid) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("wait for Kata shim %d to be reaped: %w", c.pid, ctx.Err())
			case <-time.After(backoff):
				backoff = min(backoff*2, 50*time.Millisecond)
			}
		}
		return nil
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if processExited(c.pid) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Kata shim %d to finish sandbox cleanup: %w", c.pid, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (c *Client) killAndDeleteTask(ctx context.Context, id string) error {
	_, _ = c.tasks.Kill(ctx, &taskapi.KillRequest{ID: id, Signal: uint32(syscall.SIGKILL), All: true})
	_, deleteErr := c.tasks.Delete(ctx, &taskapi.DeleteRequest{ID: id})
	if deleteErr != nil {
		return fmt.Errorf("delete task %q: %w", id, deleteErr)
	}
	return nil
}

// Close releases client resources after the shim has completed sandbox cleanup.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	tc, pid, endpoint, bundle := c.client, c.pid, c.endpoint, c.bundle
	c.mu.Unlock()
	if pid > 0 && !processExited(pid) {
		return fmt.Errorf("refusing to close live Kata shim process %d", pid)
	}

	var errs []error
	if tc != nil {
		_ = tc.Close()
	}
	if socket := strings.TrimPrefix(endpoint, "unix://"); socket != endpoint {
		if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll(bundle); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func processExited(pid int) bool {
	var status syscall.WaitStatus
	if waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); err == nil && waited == pid {
		return true
	}
	return syscall.Kill(pid, 0) != nil
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// ValidID reports whether id is safe as a shim and filesystem component.
func ValidID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func prepareEmptyDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(path, 0o700)
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("directory must be empty")
	}
	return nil
}

func validateRestoreResult(requested []*sandboxapi.RestoreContainer, resp *sandboxapi.RestoreResponse) error {
	if resp == nil || len(resp.GetContainers()) != len(requested) {
		return errors.New("restore response container inventory does not match request")
	}
	want := make(map[string]bool, len(requested))
	for _, c := range requested {
		if c.GetName() == "" || want[c.GetName()] {
			return errors.New("restore request has an empty or duplicate checkpoint key")
		}
		want[c.GetName()] = true
	}
	for _, c := range resp.GetContainers() {
		if c.GetName() == "" || !want[c.GetName()] {
			return fmt.Errorf("restore returned unknown checkpoint key %q", c.GetName())
		}
		if c.GetTaskCheckpointImage() != "" {
			return fmt.Errorf("restore returned unsupported task checkpoint image for %q", c.GetName())
		}
		delete(want, c.GetName())
	}
	if len(want) != 0 {
		return errors.New("restore response omitted requested containers")
	}
	return nil
}
