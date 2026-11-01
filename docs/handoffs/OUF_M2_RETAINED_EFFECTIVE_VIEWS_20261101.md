# Retained effective kernel views and live metadata input

1November2026, Europe/Rome. Actual static success de4546d0/39426368 is recorded:
13files/3937bytes,17static declarations in25RO4RW/33original nodes;7token mounts
and1live Gateway store excluded from contents. Five input scopes are consumed,
all preserved, cumulative22direct Engine GETs. Never replay/reset/delete them.
Agent has the public receipt, not the private target files or a VPS shell.

The new current-static observer rehashes the exact accepted13file candidate at
execution. The effective-view observer reads kernel mountinfo/fdinfo and O_PATH
metadata: match declared25RO4RW binds with the actual ten processes, same source
and effective-view inode, held descriptor mount ID/per-mount flags and no nested
shadowing. Entire mount tables stay stable before/after and at interval end.
Controller7 joins15typed owners/28reads under one invocation fence, observing
static bytes and kernel views at both boundaries. This is not an atomic global
snapshot or a complete native checkpoint.

The new standalone input below supplies actual target kernel/live metadata
needed for the private review. It is not execution of the typed controller and
it does not instantiate a fake parent/runtime owner. It pins staticde/394,
original metadata46/result599/seed14 and all five exact protected scope layouts,
static claim/profile, boot/root/allten process generations. ZERO Engine, mounted
file contents, SQL/IAM/native commands/lifecycle. Static contents are NOT
rehashed by this input; static full9field custody must match the existing hash
capture, and the typed current-byte owner still must rehash at execution. Current
container Docker configuration explicitly NOT freshly observed. The kernel
input cannot replace current-runtime/bearer/artifact/owner policy admission.

It observes25RO4RW effective bindings plus metadata of7renewable token leaves
and1live SQLite mainfile. No token/key/SQLite body, hashes or decoded claims are
read. No mounted directory enumeration. Token inode/time/value renewal between
independent observations is allowed; within an individual token observation the
named host/effective leaf is stable. SQLite size/time may change while active;
its dev/inode/mode/uid/gid/nlink source/view identity is stable. Metadata-only
custody differences against the old capture are recorded privately and counted
publicly, never learned as expected policy. Live membership, effective credential
readability and issuer/signature/audience/scope/expiry/revocation/current owner
authentication still require independent native owners.

One new scope/control,1attempt90s,128kernel reads/16MiBkernel metadata,
mountinfo262144bytes/4096rows, fdinfo8192bytes, privateoutput8MiB. New6th control,
cumulative22GET unchanged; no runtime budget reset/grant or old attempt rearm.
Root700/files600/create-once; output
/etc/ouf/deploy-snapshots/m2-retained-kernel-views-de4546d0-20261101-v1.
Outer100s+kill5. On STOP or interruption preserve this and every old scope,
return the public result; no automatic retry/repair. No authority/apply/acceptance.

## Qualified immutable delivery

- Source91a0aeaf1664a387e1d9559ced604f5fb449b37f, eleven closed sources;
  sourceMapd3c6d1f4496f87336b27fd088f2cf5273dd18b6349bf778c4c95b4b1a8b37d0a.
- Capsule00de07a457442903041ad8b47899458bb283c714,
  SHA2564ddb3625fd961bbd1cd40866227b3ff95af478b791f6058806a5414e9355d811,
  162016bytes. Actual isolated11source import checked without target entrypoint.
- Launchera60b4d6d88e9f96ee3620dc845642f9504b91d33,
  SHA256c180ed3ebb307e13169fee64ee9bb1594ba8b76b72184173b96877226e7c8482.
  Both immutable capsule and launcher raw URL bytes independently read back.
- Source CI41302293479 PASS15tests/3suites: unit5/capsule5/native5, both
  logs124835589869/124835590076 read. Current-owner compatibility41302293325
  PASS33/4 (7static-intake+5kernel+16controller+5native), both logs
  124835589382/124835589556 read. All original235/eight sealed static sources
  and old capture/hash/reconciliation capsules remain byte-exact.
- Final qualification: 41302674676 PASS19tests/4suites; unit14/native5, both final logs124836690015/124836690213 read.
- General qualification after shared primitive extraction: 41302293317 PASS209tests/29suites; protocol192/24 at job124835589749, plus nativeIAM4/DB4in2suites/process2/TLS7. All5logs read, zero failure/error/skip/ResourceWarning.
- Native Docker29.8.1/ten UID10001scratch processes, actual original five-stage
  producer outputs before the new input. FD allowlist proves no mounted content;
  exact views/8live leaves, changed permission recorded without policy adoption,
  changed effective RO with unchanged Docker declaration denied, live symlink
  not followed, actual PID restart denied. Final qualification includes token
  renewal and active SQLite WAL writer/checkpoints during the new collection.
  Fixture SQL writes and namespace mutation helpers exist only in disposable CI;
  production observer/capture executes no SQL, setns/mount command or lifecycle.
- Publisher41302293479/job124835590076/artifact13082135784 ZIP
  937c6514986c0e26187f26c19c925cf66538ff883fbf8f099049d90c5513b55f.
  Pinned official gh2.97.0 offline attestation verify on hosted runner;
  downloaded certificate/source/ref/workflow/repo1409074354/owner96419716 and
  exact signed subject read back; local export equals artifact and committed
  capsule bytes. No local cryptographic trust-chain rerun claimed.
- Prior static intake420125ec: general203/28, targeted26/3 PASS. Kernel owner
  productionbb3872b0 with final fixture9b90f266: general209/29, targeted33/4 PASS.
  Native negative fixture fixes never relaxed production guards. All these
  qualifications are disposable/source proofs, not OUF target E2E or admission.
- Kernel contract: https://www.kernel.org/doc/html/latest/filesystems/proc.html,
  sections3.5and3.8 (per-mount options and descriptor mount IDs).

## One necessary operator input

Run exactly once on the VPS; return only public JSON:

```bash
(
  set -e
  ouf_capture_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_capture_tmp"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/a60b4d6d88e9f96ee3620dc845642f9504b91d33/scripts/launch-m2-retained-effective-views-20261101.sh \
    -o "$ouf_capture_tmp/run.sh"
  printf '%s  %s\n' c180ed3ebb307e13169fee64ee9bb1594ba8b76b72184173b96877226e7c8482 "$ouf_capture_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  bash "$ouf_capture_tmp/run.sh"
)
```

Expected success: EFFECTIVE_VIEWS_AND_LIVE_METADATA_CAPTURED_NOT_ADMITTED.
All full custody/live owner policy/bearer/complete-runtime artifacts/current
execution package/private review/current HUMAN+dualrole/E2E/two clients remain
open. No old HUMAN/role authority reuse, upload/profile/acquisition/activation
replay or inferred acceptance. Preserve M1/Teatri8/8technical6/6functional and
same Farmacie61rows10cols10OPEN/ministerial STRING. Loading ends UDP/all61outcomes,
then graph search, then vertical/API delta. The old Oct14file-first/four-mount
package assembler must not stand for a new M2 seven-mount package; current
retained originals/newOnboardingV38/newSemantic/selectedMCP payloads require a
coherent separately reviewed publisher composition, not blind retained rebuilds.
