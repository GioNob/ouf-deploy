# After APPROVO: reconcile authority, effects and custody — 2026-10-19

Technical8/8, functional4/6. Operator output proves private capsule completion a0dd0cd5…, sourceclosure be575708…, native refresh186→188 and preserved window, then APPROVO accepted for review55384120… in dvf517sr. Subsequent PRIVATE_FILE_CUSTODY_REQUIRED is not proof of zero authority or zero effects. Do not replay launcher/capsule, signature issuance or logical-scope claim. [Operator receipt](../evidence/source-revision-after-approval-stop-20261019.json).

Static source: the runtime private_file reader checks root UID/GID,0600,regular file,single link,bounds. NativePorts.guard_current calls it for the private review and retained MCP metadata before a stage effect is claimed; later it also checks backups. Preparation reads MCP metadata using its separately qualified hash-bound reader. A custody difference is a candidate, not a target finding. Do not chmod/chown, relax generic private custody or accept expired authority from this hypothesis.

One readonly diagnostic pins capsule completion/case/package and approved review/sourceclosure; execution plan must hash to the reviewed source scope. Closed bounded file inventory records presence of issuer/decision/mandate/authority/signatures, logical claim and native effect journal. It does not validate/reuse authority as current or call any issuer. Journal hash stays internal and is never printed. Report shows nextStage/effects, expiry, backup presence and a stat-only/capped exact-hash probe of private-review and retained MCP bindings. The readonly public-file hash probe can report matching0644root metadata while explicitly reporting strict runtime private custody failure; this is diagnostic, not runtime acceptance or a custody change. Image archives are stat-only. No dump/bearer/key file is opened.

Current old/unchanged containers are selected only by approved plan IDs and bound Unix Engine socket; exact GET /v1.44/containers/{id}/json, bounded replies, secret config retained only in memory and compared by digests. Only stable process/generation equality and running flags are printed. No Docker exec, SQL, refresh, IAM, service lifecycle, migration, route/publication/job effect or journal write. Existing HUMAN journal is read only for exact public binding, state/attempts/window; credentials and journal hashes remain unprinted. Snapshots and execution inventory are checked for stability. Unknown files/links/custody or binding drift stop. Live authority signatures/application migration are not accepted merely from file presence; outcome of runtime mutations remains pending target read.

PET consulted: original Onboarding1.6 §§109.14–109.15, current owner authority and retained evidence, expired challenges and operational dependency signals. No complete PET compliance inferred. Qualification PASS: run39204570304/job117904496683,7tests in actual isolated root fixture. Tests invoke the unchanged real native private_file reader to reproduce its0644 denial while the diagnostic confirms exact bytes; neither reader nor target permissions are changed. Root shim refuses tampered helper before protected reads. Diagnostic Git blob34ac58ec3561eed917f5575f1fb22f073dd86b9f and SHA256a813cdf54f36c3619c8f70d4a173ce5533a99dc86bf41029e3f37d56fab99ab3 were independently read back through the GitHub API. LauncherSHAe2624c1592d5b9c68266c09057566e544ebad2798927b7b2e174e989d4c22b20. [Qualification receipt](../evidence/source-revision-after-approval-custody-read-qualified-20261019.json). Protected target read remains pending; no runtime outcome inferred from fixtures. Existing physical sudo is required for root-private target evidence; no new runtime decision requested.

## One readonly VPS command

```bash
(
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || exit 1
ouf_read_dir="$(mktemp -d "$HOME/ouf-after-approval-read.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/launch-source-revision-after-approval-custody-read-20261019.sh?ref=3284dea67536ae067636d0ece434ccbb4c626626' --jq '.content' | base64 --decode > "$ouf_read_dir/read.sh"
printf '%s  %s\n' 'e2624c1592d5b9c68266c09057566e544ebad2798927b7b2e174e989d4c22b20' "$ouf_read_dir/read.sh" | sha256sum --check
bash "$ouf_read_dir/read.sh"
)
```

Return final redacted JSON. After STOP preserve log and do not rerun any old launcher or accept/reissue consumed/expired authority.
