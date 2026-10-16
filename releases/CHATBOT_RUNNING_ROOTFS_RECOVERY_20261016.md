# Running Registry rootfs correction

The completed target diagnostic found all 9,302 independent pre-Java entries
unchanged. Its eight additional entries were under `tmp`: seven directories and
one 32,768-byte file, whose content changed between scans. Full OCI and the
released process generation matched; the three backups, empty failed MCP claim,
ten Registry effects and cumulative five grants remained unchanged. The target
diagnostic redacted new names and content, so it did not itself identify the
producer of those additions or grant acceptance.

The original archived Registry image was then started in disposable CI on
Docker 29.8.1/containerd, with the same Java arguments, uid/gid, capability and
NoNewPrivs restrictions and four private mount targets. Its pre-Java seal matched
the retained independent seal exactly. A synthetic PostgreSQL database and
public-only OIDC metadata allowed Java to reach liveness UP with IAM enabled.
There was no signing service, token grant or authorization bundle. The fixture
did not contact the VPS and does not prove production readiness or chatbot
acceptance.

Run [38832922101](https://github.com/GioNob/ouf-deploy/actions/runs/38832922101)
on `a599054050de5597e36d513464f182f8e022c2a1` reproduced all eight additions,
including their sizes, ownership, modes, link counts and directory depths:

| Runtime entry | Required form |
| --- | --- |
| JVM data directory | `tmp/hsperfdata_ouf`, uid/gid 10001, mode 0755 |
| JVM data file | `tmp/hsperfdata_ouf/1`, 32,768 bytes, mode 0600, one link |
| Empty Tomcat document root | One `tmp/tomcat-docbase.8080.<decimal>` directory, mode 0700 |
| Tomcat working tree | One `tmp/tomcat.8080.<decimal>` directory, mode 0700, with exactly `work/Tomcat/localhost/ROOT` |

The new `ouf.chatbot-running-registry-rootfs.v1` predicate scans every entry
using the unchanged original v1 sealer. It validates these eight entries and
replays the remaining canonical entry stream against the original seal. No
other path, content, sealed metadata, xattr, symlink or hard-link difference is accepted;
there is no blanket `/tmp` exclusion and no adoption of the target's observed
digest as a baseline.

The one mutable file must be a bounded HotSpot PerfData v2 buffer with the exact
193-field schema and immutable string constants independently captured in CI.
Kernel namespace PID 1, device/inode, mapping permissions, mapping length and
the same process root must bind it to the already verified Java generation.
Two complete scans must preserve the runtime identities and all original image
entries. Counter values and change timestamps may advance between scans;
timestamps remain checked within each bounded read and are not part of the
original v1 semantic seal or kernel identity. A different schema, producer, file or
directory structure blocks before review. The original paused-image predicate
remains unchanged. Docker health log samples can advance during observation;
configuration, lifecycle flags, restart count and generation remain exact, and
fresh application readiness is separately checked by its existing owner.

The complete new HUMAN action binds this qualification and the new source
closure. Old signatures are historical evidence only. The same continuation
fence, ten applied Registry effects, five consumed grants, finite worker limits
and one-new-MCP-dump limit remain in force. No Registry create, start, signal,
attestation or migration admission is replayed. The original archives and
failed MCP claim remain retained.

## Qualification and handoff

Runtime source: `b93e3570bd3e43b6c8e99d2237743bb819e43304`.
The exact native predicate passed
[38834092542](https://github.com/GioNob/ouf-deploy/actions/runs/38834092542):
15 unit tests plus the real frozen-image process, four native denial cases and
an explicit timestamp change between full scans. The immutable image seal and
kernel file identity remained unchanged. The fixture rejects an extra file,
changed original-image permissions, changed runtime-directory permissions and
a different process. Artifact `12018408528` has SHA-256
`5912397af3b2f4c7b30310cc4c61a55421db2a6c5ba5e98abb2c105000092a57`.

The backup qualification passed
[38834092522](https://github.com/GioNob/ouf-deploy/actions/runs/38834092522):
79 tests across seven suites, with no failures, errors or skips.

The complete signed delivery workflow passed
[38834092511](https://github.com/GioNob/ouf-deploy/actions/runs/38834092511):
418 tests across 56 suites, with no failures, errors or skips, on the exact
runtime source. This includes actual running token mounts and TLS owners,
retained grant histories, signed continuation and revocation, real service
fencing, four-database archives and owner acceptance joins. Targeted backup
cases overlap the full suite and are not 79 additional distinct cases.
Complete hashes, prior development failures and fixture limits are recorded in
`evidence/chatbot-running-rootfs-recovery-qualification-20261016.json`.

Preparation capsule SHA-256:
`a861526474956c81633d8e85cb50c633084ed932a8065cb9fdcdafc88dd6c6b2`.
Delivery script SHA-256:
`4b2d66a66cbda7335e328481fcb93925d605ead3ec1c3767b3f057401b13a3fd`.
Operational launcher SHA-256:
`98cfc6e87bfacc144bb2bf859b893ceaaf886f1698c0cb47d8444b0947b92425`.

The new launcher is `scripts/launch-chatbot-running-backup-recovery-20261016.sh`.
It reuses the exact original package and downloads a new source capsule. It
first repeats the complete read-only retained-history and current-native
preflight on the VPS. This is the first target execution of the typed runtime
delta checks; an unqualified target difference remains a block.

The installer prepares the private full review before asking for
`APPROVO <review-hash>`. This fresh decision is required by `AGENTS.md` and
resilience policy v3 for the changed source, backup plan and new finite session.
It cannot be supplied by development delegation. Run the new launcher once;
preserve its log and journals on any stop. Old failed launchers are not retries
for this release.

Qualification and publication issue no runtime authority and do not establish
CSV/chatbot end-to-end acceptance. That remains dependent on successful target
execution and the actual owner-observed CSV interaction.
# Superseded operational entry point: phase 2 pause

The launcher below was executed and approved on the VPS. Its new delivery stopped at `MCP_MIGRATION_ROLE_NATIVE_IDENTITY_DRIFT` after backup and migration-container creation. **Do not rerun this consumed launcher.** Follow the [stable roadmap](../docs/CHATBOT_CSV_ROADMAP.md) and [phase 2 readback](CHATBOT_MCP_PHASE2_READBACK_20261016.md). The qualified running-rootfs result remains historical evidence; it is not permission to replay the action.

