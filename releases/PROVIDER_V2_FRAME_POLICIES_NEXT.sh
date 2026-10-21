#!/bin/bash
# Compile unsigned private drafts only; no runtime/allowlist/signing/start change.
set -euo pipefail
umask 077
test "$(id -un)" = oufadmin
oufDir="$(mktemp -d)"
trap 'rm -rf -- "$oufDir"' EXIT
oufGh='/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
test -x "$oufGh"
for oufFile in prepare_provider_v2_frame_policies.py build_role_frame_template.py compile_creation_frame_policy.py containerd-overlayfs-adapter.json containerd-overlayfs-southbound.json; do
  "$oufGh" api -H 'Accept: application/vnd.github.raw+json' \
    "repos/GioNob/ouf-deploy/contents/tools/semantic_frame_compiler/$oufFile?ref=8e5b271599a4663bf961f8f4c5585d7edee0c9dc" > "$oufDir/$oufFile"
done
sudo /bin/bash -s -- "$oufDir" <<'OUF_ROOT'
set -euo pipefail
umask 077
oufRoot="$(mktemp -d /etc/ouf/deploy-snapshots/semantic-v2-frame-policy-source-XXXXXXXX)"
for oufFile in prepare_provider_v2_frame_policies.py build_role_frame_template.py compile_creation_frame_policy.py containerd-overlayfs-adapter.json containerd-overlayfs-southbound.json; do
  install -m 600 "$1/$oufFile" "$oufRoot/$oufFile"
done
cd "$oufRoot"
sha256sum -c <<'OUF_HASHES'
acf510ed401c776ac52f11053bc97c20bc49786fac8bdc54d592ca0ae274a06c  prepare_provider_v2_frame_policies.py
64f71f1c1414a87fda7e98a4402bef2b12ff8c5a917766810412825cca54f00c  build_role_frame_template.py
36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d  compile_creation_frame_policy.py
6dc554812c9298baffeb1ef7314eb2f43d7d4e5e41aea791f506a723f527b41e  containerd-overlayfs-adapter.json
ea86df348ace963d41d3a24ab3b9bea693c3b3ba36e181a1aaec5f7e97333b63  containerd-overlayfs-southbound.json
OUF_HASHES
exec /usr/bin/python3.13 -I -B -c 'import runpy,sys; sys.path.insert(0,sys.argv[1]); runpy.run_path(sys.argv[1]+"/prepare_provider_v2_frame_policies.py",run_name="__main__")' "$oufRoot"
OUF_ROOT
