# Retained V11 combined mount declaration correction — 12 October 2026

The operator reported exit1, `RETAINED_V11_SOURCE_EXPECTATIONS_BLOCKED`, reason `EXACT_GATED_SIX_MOUNT_REQUEST_REQUIRED`, before any source-content hashing or protected writes. [Reported target block](../evidence/retained-v11-source-expectations-blocked-target-20261012.json). No R12, runtime, database, budget or authority change occurred in that report.

The old preparer imposed `len(HostConfig.Binds)==6`. That source-side assumption is incorrect for Docker requests which retain mounts through `HostConfig.Mounts`; the original creation compiler preserves all retained HostConfig fields and appends only four Binds. The old reason also conflated hash and shape failures. The precise target representation has not been independently read back in this session.

The corrected program preserves the EXACT same parent intake005f6a… and request37b517… byte hashes, both metadata seals, readonly source scopes, protected custody, bounds, atomic no-replace publication and no-authority flags. It separates byte-hash denial from shape denial and counts Binds PLUS Mounts. Six distinct, non-shadowing readonly targets are required; malformed/writable/missing/extra declarations are denied. No request field is rewritten and no automatic runtime retry is introduced.

Regression exercises the complete private preparation with four Binds plus two structured readonly Mounts, including preserved original request bytes and no private output. Eleven source/publication tests and four sealed-delivery tests pass locally. The native workflow verifies root/10001 custody and actual POSIX atomic publication on synthetic private source fixtures; target execution remains pending.

Program source `58f8235cbecf5b41f538c0df1158d43ff5c2b23f`, SHA256 `c89caa119ef7c4fea07ac6a65dd5d2b173c144cf6a802e646929418acc859d56`. Launcher SHA256 `70bb1d1d3bb4d5ab2be79bb022547eb6e7b9fe97ce05308d2472af20b7412e44`. Both sources are checked before sudo and rechecked before root execution; the original atomic publisher remains byte-exact.

The old checksum-pinned launcher is superseded for this preparation task and remains in history. The corrected launcher does not read the sources until the exact request and combined declaration checks succeed. It still hashes the two contents privately and creates two new expectation/reference files plus manifest only. Hash capture does not authenticate source policy, accept all six native mounts, grant HUMAN/signature authority, start V11 or produce a CSV run/ACK/search result.
