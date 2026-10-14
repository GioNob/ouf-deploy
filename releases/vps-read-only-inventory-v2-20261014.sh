#!/usr/bin/env bash
# One read-only collection; exact qualified source, no delivery or IAM login.
set -euo pipefail
umask 077
OUF_INV_COMMIT=8dd4c06b26c2c3a0e0545e8f733b8d58a20275de
OUF_INV_SHA=b0e9f78178452873be69b7e8870a185c6966ea1640231ffb7952ed102aaa4058
OUF_INV_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$OUF_INV_GH" ]]; then
  OUF_INV_GH="$(command -v gh || true)"
fi
[[ -x "$OUF_INV_GH" ]] || { printf 'GH_UNAVAILABLE_NO_SUDO_EXECUTED\n' >&2; exit 1; }
OUF_INV_STAGE="$(mktemp -d "$HOME/ouf-vps-inventory-v2.XXXXXXXX")"
"$OUF_INV_GH" api \
  "repos/GioNob/ouf-deploy/contents/scripts/collect-vps-inventory.py?ref=$OUF_INV_COMMIT" \
  --jq '.content' > "$OUF_INV_STAGE/source.b64"
base64 --decode "$OUF_INV_STAGE/source.b64" > "$OUF_INV_STAGE/read.py"
printf '%s  %s\n' "$OUF_INV_SHA" "$OUF_INV_STAGE/read.py" | sha256sum --check
printf 'Raccolta unica CLI/API e inventario; limite 240 secondi, nessun login IAM.\n'
sudo /usr/bin/python3 -I -B "$OUF_INV_STAGE/read.py" |
  tee "$OUF_INV_STAGE/inventory-full.json" |
  /usr/bin/python3 -I -B -c '
import json,sys
d=json.load(sys.stdin)
a=d.get("areas",{})
selected={"engine","engineApiVersions","containerInventory","registryObservationChannels","registryHistoricalComparison","registryNativeRunc","stableAllContainers","stableNativeTool","ownerActiveGrants","existingTeatriInput","iamEffectiveCatalogue","gatewayLiveRoutes","currentRuntimeAuthorityLedger","retainedRecoveryHistory","freshMcpRead","historicalReview","historicalDeclaration","historicalCreationRequest","coordinationIntake"}
d["areas"]={k:v for k,v in a.items() if k in selected or k.startswith("database/") or v.get("status")!="OBSERVED"}
t=d["areas"].get("containerInventory",{})
if t.get("status")=="OBSERVED":
    v=t["data"]
    owners={"ouf-semantic","ouf-onboarding","ouf-ingestion","ouf-udp","ouf-mcp","ouf-postgres","ouf-keycloak","ouf-apisix","ouf-gateway-control-plane"}
    t["data"]={k:x for k,x in v.items() if k!="oufContainers"}
    t["data"]["selectedOwnerContainers"]={k:x for k,x in v["oufContainers"].items() if k in owners}
t=d["areas"].get("gatewayLiveRoutes",{})
if t.get("status")=="OBSERVED":
    v=t["data"]
    t["data"]={k:x for k,x in v.items() if k!="routes"}
    t["data"]["routeIds"]=[r["id"] for r in v["routes"]]
d["displayProfile"]="SELECTED_DIAGNOSIS_FULL_REPORT_RETAINED"
print(json.dumps(d,sort_keys=True,separators=(",",":")),flush=True)
'
printf 'INVENTORY_FULL_REPORT=%s\n' "$OUF_INV_STAGE/inventory-full.json"
