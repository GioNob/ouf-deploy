# Retained V11 source usage references — 12 October 2026

The [operator-reported metadata diagnosis](../evidence/retained-v11-metadata-diagnosed-target-20261012.json) isolates inode/mtime/ctime change of the sole member in retained mount0, with root0/group10001/mode0440 unchanged. Directory0 remains mode0750 and the same member set; its times changed. Retained file1 remains unchanged at uid/gid10001/mode0400. No source bytes were read or private baseline written.

This is consistent with atomic member replacement but proves neither byte integrity nor legitimate rotation. The inspected R12 Coordinator PrivateJournal replaces a root-private0600 journal, so neither its atomic write pattern nor this440 custody proves it wrote the retained member. No attribution is made.

The [new reader](../scripts/read-retained-v11-source-usage.py) verifies the SAME sealed005f… parent,37b517… request and metadata seals. It reports only exact file/configtree/container-path references by environment VARIABLE NAME and mount index/kind/type. It does not open mounted sources, scan arbitrary credentials, print environment VALUES/source paths/member names, update an intake or call native runtime/network commands. A textual consumer reference is not writer identity or rotation authority; empty references explicitly mean no direct reference was found, not no consumer.

Pinned program source `8bfb64d163d3bcdc2a9afe42e8d7b309ee1cd424`, SHA256 `7afa2cba1c8892707c5eba2e76615863e1155fa0ea7f59d7421dde4b21b04916`. [Launcher](retained-v11-source-usage-20261012.sh) SHA256 `8d878ea8498cadc82815515efd3935c34ffdb8744724847b8aec7db64ce7af0e`. It reuses the unchanged pinned planner and atomic primitives only for exact private intake/request reads. All three sources are checked before sudo and before isolated root execution. Deadline120seconds, no shared lease lock, source acceptance, retry or budget renewal.

Four source-usage/redaction/private-parent tests and four delivery tests pass locally; the dedicated disposable native-root workflow validates selected parent integrity, no source reads/writes and secret-value redaction. Fixture qualification does not diagnose the target writer.

The new target output is still required to identify the consumer contract in source. Writer/owner evidence, governed replacement handling, six-mount policy/acceptance and fresh HUMAN/signature authority remain open. Do not refresh source metadata merely because custody is unchanged, stop R12 ad hoc, replay claims or reset history. No new CSV run/ACK/search evidence is produced by this reader.
