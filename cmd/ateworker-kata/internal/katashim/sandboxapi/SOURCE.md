# Sandbox API source

`sandbox.proto` is the temporary wire contract used by the matching experimental
Kata runtime-rs build. It is based on containerd's Sandbox v1 API and adds the
separate Checkpoint service and restore network namespace field that have not
yet shipped in a stable Go module.

This package is private to `ateworker-kata`; it does not imply that ateworker-kata runs
or embeds containerd. Replace it with the released upstream module once that
module exposes the same wire contract.

The matching runtime-rs dependency is `containerd-shim-protos` revision
`12b343d45de49311de0f6614f3f1c2097a0c8ae9`. Generated Go files must be produced
with `protoc-gen-go` and `protoc-gen-go-ttrpc` from this source.

This directory is excluded from the repository's generic gRPC protobuf
generator. Regeneration also requires the containerd API proto include root,
so it is intentionally performed only when the pinned wire revision changes.
