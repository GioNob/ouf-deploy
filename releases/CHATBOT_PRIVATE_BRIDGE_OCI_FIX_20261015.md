# Private bridge OCI expectation — 2026-10-15

The complete target readback confirms exactly37 structural differences: an
expected network namespace path absent from native OCI, and all36 environment
positions. OCI version is1.3.0 on both sides; the four mount metadata witnesses
and native network compiler pass. Registry remains paused/running, PID3484588,
restart0, transitionv13 /nextPhase6 /ATTEST IN_FLIGHT. Six prior phases are
APPLIED. The cancelled worker has1 attempt,1 publication, cumulative2 grants;
admission is BLOCKEDv3, attestation issuance claim absent. No target mutation
was performed by either diagnostic. Environment value equality is not yet proven.

## Corrected independent expectation

Source24d36d23e7c7183b7895e1dc823d3c06428412b2 corrects two compiler/caller
errors. The non-TTY Linux Docker environment is independently derived from the
signed request: explicit audited PATH and Docker HOSTNAME default slots first,
then configured entries in request order. Recompilation of retained proposals
requires exactly the same environment map and changes only its expected order.
It rejects duplicate entries, missing audited PATH, unsupported TTY/link/hostname
overrides, and value drift. It never sorts or rewrites observed OCI.

A named-bridge creation gets a fresh runc network namespace, so its expected
OCI entry has no path. SandboxKey is still an independently checked live kernel
identity: its inode must equal the staged PID network namespace. Shared/host/
container network modes or an unrelated endpoint are rejected. Full OCI hashes,
image, request, flags, mounts, source custody and downstream acceptance stay bound.
The old files and journals are not overwritten by this correction.

## Evidence on the same source

All six CI checks passed on the exact source:

| Check | Evidence |
| --- | --- |
| Complete cohort |324tests /43suites /0skip; run38776032264 |
| Docker29.8.1 /overlayfs /systemd |25tests /4suites /0skip; run38776031941 |
| Online IAM |PASS; run38776032561 |
| Independent token owner installer |PASS; run38776032180 |
| HUMAN/Ed25519 authority |PASS; run38776031948 |
| Legacy retirement |PASS; run38776032879 |

The Docker test now compares the ENTIRE native OCI with a policy compiled from
the independent versioned baseline and signed creation inputs. It uses two real
file binds and two directory binds, finite CPU/memory/PID limits,36 environment
rows, nonroot/capability-drop/no-new-privileges and the file-only root mode.
It reproduces the old37 positional/namespace differences and then proves exact
full equality with the corrected compiler, including the live sandbox inode.
The native application is still a static HTTP fixture. Full FileOnlyNodeOwner
attestation/token admission and actual Spring/CSV E2E are not proven by this test.

An initial CI trial failed on a test assertion indexing an omitted false
root.readonly field; the corrected assertion applies OCI's false default. It
changes no expected policy. This development failure is retained in machine
qualification evidence. Upstream Moby daemon/container/{container,env}.go also
shows the default-slot/override ordering; actual29.8.1 qualification above is
the version-specific evidence used here, not a claim about an unavailable tag.

## Next action: read-only candidate proof on the existing paused VPS

Run scripts/read-chatbot-bridge-proposal-20261015.py from this evidence checkpoint.
Only sudo read access is needed. No Keycloak login, device code or APPROVO.
The reader embeds the six independently hash-pinned pure compiler modules from
the qualified source and reads the fixed original signed review/bundle. It
compiles a PROPOSAL from those existing inputs, not from observed OCI. It reports
whether environment names/values match, whether the corrected ordered environment
and the entire corrected OCI match, and verifies SandboxKey/PID kernel identity.
It does not publish the proposal, issue a signature or accept an attestation.

If the full candidate OCI matches, it additionally runs the frozen original
rootfs sealer against the host-side image view and qualified packaged seal,
within180seconds (whole reader maximum240seconds). Before scanning, all four
private binds must be absent from that image view by inode comparison, so no
credential/token bind content is scanned. It reads image file content, returns
only seal equality and file counts/bytes, and never reads client-secret or token
files. A scan-start record makes the bounded wait visible. This is intended to
find the next original image-seal check before another runtime approval cycle.

Five new reader cases and15 supporting preparation cases pass locally, zero
skips. They cover exact independent candidate compilation, extra native drift,
compiler tampering, complete-reader handoff through END, actual frozen rootfs
sealing and denial before scanning a private bind view. Native process/Engine
observations in the reader entrypoint test are explicit fixtures.

There is NO new runtime delivery command at this checkpoint. The old runtime
window/start claim/global reservation cannot be reused. A later recovery must
preserve the six APPLIED phases, paused generation, all consumed claims and
cumulative2 grants, and explicitly account for the unfinished unsigned
attestation under a fresh reviewed action. No recovery profile for that boundary
is implemented yet. Candidate-vs-VPS equality and current rootfs proof are still
required; do not present this component fix as operational or E2E completion.
