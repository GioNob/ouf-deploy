#!/usr/bin/env bash
# Independently compile retained Semantic intent, then read OCI and peer links.
set -euo pipefail
if (( $# != 0 )); then printf '%s\n' 'Usage: retained Semantic peer read (no arguments)' >&2; exit 2; fi
umask 077
ouf_peer_source_dir=$(mktemp -d /tmp/ouf-semantic-peer.XXXXXX)
trap 'rm -rf -- "$ouf_peer_source_dir"' EXIT
ouf_peer_source='8f99ad0a91e7276cf479b65b24d646a227328fc6'
while read -r ouf_peer_hash ouf_peer_path; do
  mkdir -p -- "$ouf_peer_source_dir/$(dirname -- "$ouf_peer_path")"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$ouf_peer_source/$ouf_peer_path" \
    -o "$ouf_peer_source_dir/$ouf_peer_path"
  printf '%s  %s\n' "$ouf_peer_hash" "$ouf_peer_source_dir/$ouf_peer_path" | sha256sum -c -
done <<'SHA256'
80c7b789c735a562f5c04b3a9b56120716b933053f3e8e247e5fff21ceed1edc  scripts/read-retained-semantic-peer-20261109.py
94649eefceddc348c92172872bf0cb180c21bd057ae84f7b371d9b2aa6c6259f  scripts/reconcile-discovery-placeholder-20261109.py
4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67  scripts/read-discovery-lifecycle-20261109.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  scripts/read-analysis-discovery-runtime-20261107.py
2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1  scripts/upgrade-semantic-application-20261108.py
4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b  tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py
36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d  tools/semantic_frame_compiler/compile_creation_frame_policy.py
a6a1f5fac3dfab9fde02402bc6c4ed422c068f0d7a4837a09fe92c9bbb7f4d24  tools/semantic_frame_compiler/compile_retained_semantic_peer.py
ea86df348ace963d41d3a24ab3b9bea693c3b3ba36e181a1aaec5f7e97333b63  tools/semantic_frame_compiler/containerd-overlayfs-southbound.json
SHA256
sudo python3 -I -B -S "$ouf_peer_source_dir/scripts/read-retained-semantic-peer-20261109.py"
