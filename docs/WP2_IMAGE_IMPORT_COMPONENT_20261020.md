# WP2 — claimed-once image import component

The adapter consumes the exact retained qualified archive through one verified
open file descriptor. It never downloads, rebuilds, retags, recreates or repeats
the completed archive/JAR/SQL audit. Existing file bytes/metadata are verified
against the retained authenticated binding; that is custody, not a new audit.
The selected native image ID, source label, config projection and complete
rootfs diff-ID sequence must match. Profile paths, Engine, Docker program,
empty credential-free config directory and archive ancestry are explicit.

An exact already-present image is adopted without a load. Otherwise the native
attempt marker is persisted before the sole Docker load. Ambiguous completion
retains the claim and permits exact image GET reconciliation only. Neither an
absent image after a lost response nor another component instance permits load
replay. The held archiveFD is not replaced by a reopened pathname. Output and
duration are bounded; credentials/environment are not inherited.

Private file readers retain their1MiB default. The public archive path can use
an explicit maximum2GiB; its inode/full metadata and ancestry are checked before
and after consumption. Metadata-only guard checks do not repeat archive audit
or copy archive bytes for every guard.

Eleven local tests PASS with actual FDs, Ed25519 and private CAS, and a synthetic
Docker loader. Real Docker import/response loss and the full native rollout
still require representative isolated qualification. G2 remains OPEN, current
technical8/8 and functional4/6 unchanged; no target operations or authority.
