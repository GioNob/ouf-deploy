# Mounted token lifetime integration defect — 2026-10-15

The target execution at source b7d24c57d6e45e71994ac3f99f56f249d83cde22
passed six-effect/history/native OCI/rootfs preflight and entered private frame
observation. It failed in OnlineIamAdmission.admit line239: AUTHORITY_EXPIRED.
Review2380132af8e47de185894fde156470e162dab784942c8615778e7620e7f8fc60;
authority8c59697f46b3ce1b54d1cff1acf1f08dde6c4087062d28e379465d9a76ec570a.
The reader's I/O deadline is at most30 seconds and its signed minimum remaining
is30 seconds. Passing deadline+30 as token expiry creates a ceiling under60
seconds, whereas the independently compiled owner profile requires90 seconds.
That caller defect alone forces rejection even when online IAM admits the
actual token's identity, audience, scopes and true expiry. The existing suites
separately tested native mounts and actual installed IAM owner; they did not
join those two at the mount observer's lifetime argument. The prior CI success
was real but incomplete integration coverage.

Fix: DomainOwner exposes an explicit fail-closed mounted-token admission seam.
InstalledTokenOwner implements it only for the current ACTIVE observer. It uses
the existing worker's durable wall and monotonic expiry, never the mount's I/O
deadline, validates current signed authority/source/history/admission, checks
both minimums, then runs unchanged online IAM validation and verifies unchanged
journal/admission. Both clocks bound the window conservatively. Observer reads
never extend lifetime, publish, grant, modify counters or relax the90-second
owner minimum. Existing generic admission and grant checks stay unchanged.

New hosted-root integration tests join actual readonly mount namespaces with
the actual signed installed owner and real TLS introspection. They reproduce
the old60-second rejection with a valid300-second issuer token, then verify
fresh mount observation, durable-short window refusal, larger mount minimum,
issuer expiry/revocation, inode rotation, current HUMAN revocation and concurrent
publication-window change. Only the preexisting HUMAN/legacy-unit fixtures are
synthetic. Mount-only synthetic fixtures explicitly implement their synthetic
seam and never claim IAM acceptance.

Qualification is PENDING at this source checkpoint. The latest failed target's
worker/journal/claim must be read before another runtime continuation can be
prepared. Do not rerun the prior launcher or reuse its consumed fixed claim.
The latest worker's actual grant count and persisted state are not established
by the user status alone. Six-effect prefix and DB fence were proven before
this run, but must be reconciled against its retained records. CSV chatbot E2E
and complete private frame/node acceptance remain unproven.
