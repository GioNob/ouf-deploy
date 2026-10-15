# Next chatbot/VPS action — 2026-10-15

Latest target evidence: evidence/chatbot-bridge-proposal-target-20261015.json.
Candidate24d36d23 independently matches COMPLETE target OCI, including all
environment values/order and private namespace. The next image rootfs seal
differs:9302entries,1719645735bytes. No attestation was accepted.

Native run38781095495/source36861be7 PASS on both exact Docker29.8.1 stores.
Both original v1 seals EXACTLY reproduce the original package:9301entries,
1719645735bytes,510f56436da3e36b700b244e5e2476db9d4984216866e412b0484f951bfdb8a2.
The store-only hypothesis was REFUTED for these inputs. No policy weakening.
Read evidence/chatbot-frozen-rootfs-baselines-20261015.json and
releases/CHATBOT_ROOTFS_BASELINE_DIAGNOSIS_20261015.md.

Next target action is ONLY scripts/read-chatbot-rootfs-entry-diff-20261015.py.
Its embedded independent CI records reconstruct the exact retained package
seal before comparison. It reuses the original unchanged sealer, captures
every target entry, and reports exact differing fields without exclusions.
It requires sudo only, no IAM/device/APPROVO. No token/credential content,
signing, journal/config changes, grants, DB/IAM calls or container operations.

Preserve target six APPLIED effects, paused generation, cumulative2 grants,
cancelled worker, blocked admission and original/global claims. No old runtime
relaunch, CREATE/STAGE/SIGUSR1/grant replay, policy overwrite or budget reset.
Current boundary governed recovery is not implemented or authorized.

Reader exact-source CI38782162247/job116584868336 PASS:8 tests,0 skips.
Deliver ONLY reader84271d380d414a2fe211ac78f71c28b06d9e0e11, SHA256
dbdcd40d90a2c5294623bc8777c1584d01a8704477e85004a1de362dad25c1bb.
Await its complete ROOTFS_ENTRY_DIFFERENCES and END before runtime changes.
