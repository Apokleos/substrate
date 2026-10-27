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

// Package erofscache materializes immutable EROFS images from atelet's OCI
// layer descriptions for reuse by ateworker-kata actors on one node.
package erofscache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.ate.dev/substrate/internal/imagecache"
	"golang.org/x/sys/unix"
)

const (
	schemaVersion    = 1
	artifactFileName = "rootfs.erofs"
	metadataFileName = "metadata.json"
	lockPollInterval = 25 * time.Millisecond
)

// Artifact is one immutable EROFS image in the node-local cache.
type Artifact struct {
	Path   string
	SHA256 string
	Size   int64
}

type buildKey struct {
	SchemaVersion int      `json:"schemaVersion"`
	ImageDigest   string   `json:"imageDigest"`
	LayerIDs      []string `json:"layerIDs"`
	BuilderID     string   `json:"builderID"`
}

type metadata struct {
	SchemaVersion int    `json:"schemaVersion"`
	CacheKey      string `json:"cacheKey"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	BuilderID     string `json:"builderID"`
}

type buildFunc func(context.Context, *imagecache.OverlaySpec, string) error

// Cache owns ateworker-kata's node-local derived EROFS artifacts. It deliberately
// does not own the OCI layers from which those artifacts are built.
type Cache struct {
	root          string
	locksDir      string
	artifactsDir  string
	mkfsPath      string
	builderID     string
	buildArtifact buildFunc
}

// New creates a cache rooted at root. mkfsPath must name an absolute,
// executable mkfs.erofs binary.
func New(root, mkfsPath string) (*Cache, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("EROFS cache root must be absolute: %q", root)
	}
	if !filepath.IsAbs(mkfsPath) {
		return nil, fmt.Errorf("mkfs.erofs path must be absolute: %q", mkfsPath)
	}
	info, err := os.Stat(mkfsPath)
	if err != nil {
		return nil, fmt.Errorf("stat mkfs.erofs: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("mkfs.erofs is not an executable regular file: %q", mkfsPath)
	}
	builderID, err := erofsBuilderID(mkfsPath)
	if err != nil {
		return nil, err
	}
	c := &Cache{
		root:         filepath.Clean(root),
		locksDir:     filepath.Join(root, "locks"),
		artifactsDir: filepath.Join(root, "artifacts"),
		mkfsPath:     mkfsPath,
		builderID:    builderID,
	}
	c.buildArtifact = c.build
	if err := c.initialize(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cache) initialize() error {
	for _, dir := range []string{c.root, c.locksDir, c.artifactsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create EROFS cache directory %q: %w", dir, err)
		}
	}
	return nil
}

// Ensure returns the immutable EROFS artifact for bundlePath, building and
// atomically publishing it on a cache miss.
func (c *Cache) Ensure(ctx context.Context, bundlePath string) (Artifact, error) {
	if !filepath.IsAbs(bundlePath) {
		return Artifact{}, fmt.Errorf("bundle path must be absolute: %q", bundlePath)
	}
	spec, err := imagecache.ReadSpec(bundlePath)
	if err != nil {
		return Artifact{}, fmt.Errorf("read rootfs overlay spec: %w", err)
	}
	if spec == nil {
		return Artifact{}, fmt.Errorf("bundle %q has no rootfs overlay spec", bundlePath)
	}
	key, err := c.cacheKey(spec)
	if err != nil {
		return Artifact{}, err
	}
	unlock, err := c.lock(ctx, key)
	if err != nil {
		return Artifact{}, err
	}
	defer unlock()

	artifactDir := filepath.Join(c.artifactsDir, key)
	artifact, err := c.load(artifactDir, key)
	if err == nil {
		return artifact, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		if removeErr := os.RemoveAll(artifactDir); removeErr != nil {
			return Artifact{}, errors.Join(err, fmt.Errorf("remove invalid EROFS artifact: %w", removeErr))
		}
	}

	tmpDir, err := os.MkdirTemp(c.artifactsDir, "."+key+".tmp-")
	if err != nil {
		return Artifact{}, fmt.Errorf("create EROFS artifact temporary directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	output := filepath.Join(tmpDir, artifactFileName)
	imageOnly := &imagecache.OverlaySpec{
		ImageDigest: spec.ImageDigest,
		Layers:      append([]string(nil), spec.Layers...),
	}
	if err := c.buildArtifact(ctx, imageOnly, output); err != nil {
		return Artifact{}, fmt.Errorf("build EROFS artifact: %w", err)
	}
	digest, size, err := hashFile(output)
	if err != nil {
		return Artifact{}, fmt.Errorf("hash EROFS artifact: %w", err)
	}
	if err := os.Chmod(output, 0o444); err != nil {
		return Artifact{}, fmt.Errorf("make EROFS artifact read-only: %w", err)
	}
	if err := syncPath(output); err != nil {
		return Artifact{}, fmt.Errorf("sync EROFS artifact: %w", err)
	}
	meta := metadata{
		SchemaVersion: schemaVersion,
		CacheKey:      key,
		SHA256:        digest,
		Size:          size,
		BuilderID:     c.builderID,
	}
	if err := writeMetadata(filepath.Join(tmpDir, metadataFileName), meta); err != nil {
		return Artifact{}, err
	}
	if err := syncDir(tmpDir); err != nil {
		return Artifact{}, fmt.Errorf("sync EROFS artifact directory: %w", err)
	}
	if err := os.Rename(tmpDir, artifactDir); err != nil {
		return Artifact{}, fmt.Errorf("publish EROFS artifact: %w", err)
	}
	published = true
	if err := syncDir(c.artifactsDir); err != nil {
		return Artifact{}, fmt.Errorf("sync EROFS artifacts directory: %w", err)
	}
	return Artifact{Path: filepath.Join(artifactDir, artifactFileName), SHA256: digest, Size: size}, nil
}

func (c *Cache) cacheKey(spec *imagecache.OverlaySpec) (string, error) {
	if spec.ImageDigest == "" {
		return "", errors.New("rootfs overlay spec has no image digest")
	}
	layers := make([]string, 0, len(spec.Layers))
	for _, layer := range spec.Layers {
		if !filepath.IsAbs(layer) {
			return "", fmt.Errorf("rootfs layer path must be absolute: %q", layer)
		}
		id := filepath.Base(filepath.Clean(layer))
		if !validSHA256Hex(id) {
			return "", fmt.Errorf("rootfs layer path has no SHA-256 DiffID basename: %q", layer)
		}
		layers = append(layers, id)
	}
	b, err := json.Marshal(buildKey{
		SchemaVersion: schemaVersion,
		ImageDigest:   spec.ImageDigest,
		LayerIDs:      layers,
		BuilderID:     c.builderID,
	})
	if err != nil {
		return "", fmt.Errorf("encode EROFS cache key: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Cache) load(dir, key string) (Artifact, error) {
	b, err := os.ReadFile(filepath.Join(dir, metadataFileName))
	if err != nil {
		return Artifact{}, err
	}
	var meta metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Artifact{}, fmt.Errorf("decode EROFS artifact metadata: %w", err)
	}
	if meta.SchemaVersion != schemaVersion || meta.CacheKey != key || meta.BuilderID != c.builderID {
		return Artifact{}, errors.New("EROFS artifact metadata does not match cache key")
	}
	if !validSHA256Hex(meta.SHA256) || meta.Size < 0 {
		return Artifact{}, errors.New("EROFS artifact metadata has invalid digest or size")
	}
	path := filepath.Join(dir, artifactFileName)
	info, err := os.Lstat(path)
	if err != nil {
		return Artifact{}, err
	}
	if !info.Mode().IsRegular() {
		return Artifact{}, errors.New("EROFS artifact is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return Artifact{}, errors.New("EROFS artifact is group or world writable")
	}
	if info.Size() != meta.Size {
		return Artifact{}, fmt.Errorf("EROFS artifact size is %d, metadata records %d", info.Size(), meta.Size)
	}
	return Artifact{Path: path, SHA256: meta.SHA256, Size: meta.Size}, nil
}

func (c *Cache) lock(ctx context.Context, key string) (func(), error) {
	path := filepath.Join(c.locksDir, key+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open EROFS cache lock: %w", err)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock EROFS cache key: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
}

func writeMetadata(path string, meta metadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode EROFS artifact metadata: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create EROFS artifact metadata: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("write EROFS artifact metadata: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync EROFS artifact metadata: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close EROFS artifact metadata: %w", err)
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func validSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
