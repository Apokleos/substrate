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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/imagecache"
)

func TestCacheKeyStableAndSensitiveToInputs(t *testing.T) {
	c := newTestCache(t, "builder-a", func(_ context.Context, _ *imagecache.OverlaySpec, output string) error {
		return os.WriteFile(output, []byte("artifact"), 0o600)
	})
	layerA := filepath.Join(t.TempDir(), strings.Repeat("a", 64))
	layerB := filepath.Join(t.TempDir(), strings.Repeat("b", 64))
	spec := &imagecache.OverlaySpec{ImageDigest: "sha256:" + strings.Repeat("c", 64), Layers: []string{layerA, layerB}}
	key1, err := c.cacheKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := c.cacheKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	if key1 != key2 {
		t.Fatalf("same input produced keys %q and %q", key1, key2)
	}
	reversed := &imagecache.OverlaySpec{ImageDigest: spec.ImageDigest, Layers: []string{layerB, layerA}}
	key3, err := c.cacheKey(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if key3 == key1 {
		t.Fatal("reversing layer order did not change cache key")
	}
	c.builderID = "builder-b"
	key4, err := c.cacheKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	if key4 == key1 {
		t.Fatal("changing builder identity did not change cache key")
	}
}

func TestEnsureBuildsOnceAndStripsInstanceFields(t *testing.T) {
	var calls atomic.Int32
	var gotSpec *imagecache.OverlaySpec
	c := newTestCache(t, "builder", func(_ context.Context, spec *imagecache.OverlaySpec, output string) error {
		calls.Add(1)
		gotSpec = spec
		return os.WriteFile(output, []byte("erofs contents"), 0o600)
	})
	bundle := writeBundleSpec(t, &imagecache.OverlaySpec{
		ImageDigest: "sha256:" + strings.Repeat("a", 64),
		Layers:      []string{filepath.Join(t.TempDir(), strings.Repeat("b", 64))},
		ExtraDirs:   []string{"/run/actor-private"},
		ImageVolumes: []imagecache.ImageVolumeOverlay{{
			Name: "tools", Layers: []string{filepath.Join(t.TempDir(), strings.Repeat("c", 64))},
		}},
	})
	first, err := c.Ensure(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Ensure(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("builder called %d times, want 1", calls.Load())
	}
	if first != second {
		t.Fatalf("cache hit returned %+v, want %+v", second, first)
	}
	if len(gotSpec.ExtraDirs) != 0 || len(gotSpec.ImageVolumes) != 0 {
		t.Fatalf("image-only spec contains instance fields: %+v", gotSpec)
	}
	if gotSpec.ImageDigest == "" || len(gotSpec.Layers) != 1 {
		t.Fatalf("image-only spec lost image identity: %+v", gotSpec)
	}
	if info, err := os.Stat(first.Path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o444 {
		t.Fatalf("artifact mode = %o, want 444", info.Mode().Perm())
	}
}

func TestEnsureConcurrentBuildsOnce(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	c := newTestCache(t, "builder", func(_ context.Context, _ *imagecache.OverlaySpec, output string) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return os.WriteFile(output, []byte("artifact"), 0o600)
	})
	bundle := writeBundleSpec(t, testOverlaySpec(t))

	const workers = 6
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Ensure(context.Background(), bundle)
			errs <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("builder called %d times, want 1", calls.Load())
	}
}

func TestEnsureBuildFailureLeavesNoPublishedArtifact(t *testing.T) {
	c := newTestCache(t, "builder", func(_ context.Context, _ *imagecache.OverlaySpec, output string) error {
		if err := os.WriteFile(output, []byte("partial"), 0o600); err != nil {
			return err
		}
		return errors.New("injected failure")
	})
	bundle := writeBundleSpec(t, testOverlaySpec(t))
	if _, err := c.Ensure(context.Background(), bundle); err == nil {
		t.Fatal("Ensure succeeded, want injected failure")
	}
	entries, err := os.ReadDir(c.artifactsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("artifact directory contains %v after failed build", entries)
	}
}

func TestEnsureRebuildsSizeMismatch(t *testing.T) {
	var calls atomic.Int32
	c := newTestCache(t, "builder", func(_ context.Context, _ *imagecache.OverlaySpec, output string) error {
		calls.Add(1)
		return os.WriteFile(output, []byte("artifact"), 0o600)
	})
	bundle := writeBundleSpec(t, testOverlaySpec(t))
	artifact, err := c.Ensure(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact.Path, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ensure(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("builder called %d times, want 2", calls.Load())
	}
}

func TestEnsureCacheHitDoesNotRehashArtifact(t *testing.T) {
	var calls atomic.Int32
	c := newTestCache(t, "builder", func(_ context.Context, _ *imagecache.OverlaySpec, output string) error {
		calls.Add(1)
		return os.WriteFile(output, []byte("artifact"), 0o600)
	})
	bundle := writeBundleSpec(t, testOverlaySpec(t))
	first, err := c.Ensure(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(first.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.Path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(first.Path, 0o444); err != nil {
		t.Fatal(err)
	}
	second, err := c.Ensure(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("builder called %d times, want 1", calls.Load())
	}
	if second.SHA256 != first.SHA256 {
		t.Fatalf("cache hit digest = %q, want stored digest %q", second.SHA256, first.SHA256)
	}
}

func TestEnsureLockHonorsContext(t *testing.T) {
	c := newTestCache(t, "builder", func(_ context.Context, _ *imagecache.OverlaySpec, output string) error {
		return os.WriteFile(output, []byte("artifact"), 0o600)
	})
	spec := testOverlaySpec(t)
	key, err := c.cacheKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := c.lock(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	bundle := writeBundleSpec(t, spec)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Ensure(ctx, bundle); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ensure error = %v, want context deadline exceeded", err)
	}
}

func newTestCache(t *testing.T, builderID string, build buildFunc) *Cache {
	t.Helper()
	root := t.TempDir()
	c := &Cache{
		root:          root,
		locksDir:      filepath.Join(root, "locks"),
		artifactsDir:  filepath.Join(root, "artifacts"),
		builderID:     builderID,
		buildArtifact: build,
	}
	if err := c.initialize(); err != nil {
		t.Fatal(err)
	}
	return c
}

func writeBundleSpec(t *testing.T, spec *imagecache.OverlaySpec) string {
	t.Helper()
	bundle := t.TempDir()
	if err := imagecache.WriteSpec(bundle, spec); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func testOverlaySpec(t *testing.T) *imagecache.OverlaySpec {
	t.Helper()
	return &imagecache.OverlaySpec{
		ImageDigest: "sha256:" + strings.Repeat("a", 64),
		Layers:      []string{filepath.Join(t.TempDir(), strings.Repeat("b", 64))},
	}
}
