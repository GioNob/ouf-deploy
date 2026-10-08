# Provider v2 frame compiler

The existing observer compares the entire effective OCI document with an exact
policy. Docker generates rootfs, namespace, cgroup and metadata-file paths at
task creation. This compiler builds that exact policy from an independently
reviewed OCI template, independent image/launch inputs and a Docker context.
It never takes the observed OCI document as an input.

Only seven closed runtime slots can change. Application arguments, user,
environment (except the explicit HOSTNAME slot), capabilities, seccomp,
resources, hooks and all remaining fields stay exactly as reviewed. The output
uses the existing observer policy v1; compilation grants no authority.

The owner reviewer and runtime-shape schema used in CI are pinned to Semantic
Registry commit `3505a2f6bfde9c3905b76a5e670ebc30b40d3d6d`. Unit tests exercise
cross-container, namespace, source, command, privilege, seccomp and resource
drift. The native test uses an isolated dockerd and a capture runtime that
refuses create before runc execution. Its template is synthetic and built from
the captured fixture solely to check Engine shape compatibility; that test is
not independent target-template approval or deployment acceptance.

## Remaining production integration

1. Authenticate the complete reviewed template and image/launch inputs. The
   compiler accepts data; it cannot establish who approved that data.
2. Bind context to the exact owned Docker transaction independently of the
   OCI being checked. In particular, authenticate the network namespace name
   and installer-selected bundle/metadata parents; syntax is not custody proof.
3. Add a source-bound pre-create compilation/intent-issuance phase to the
   runtime adapter. The current immutable intentRef exists before Docker
   generates the paths, so the compiler alone cannot resolve that ordering.
4. Connect the existing node observer, signed live acceptance and installer
   approval to that transaction, then test the full actual create/start path
   and rejection cases before changing the target allowlist.

No target command, signing, container start or runtime change is provided here.
The two target candidates remain stopped and their existing allowlist empty.
