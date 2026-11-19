#!/usr/bin/env python3
"""Build a new onboarding configuration that points at a different managed file.

Input is the parent configuration (output of sql/onb_version_configuration.sql)
and the new asset metadata (output of sql/onb_asset_profile.sql). Every
reference to the old asset, profile, staging object, hash and size is replaced;
the script fails if any old identifier is left anywhere in the document.
Optionally relabels every data-access label. Prints the leaf-level diff that
must be shown to the owner before onboarding_clone_put.py is run.
"""
import argparse
import copy
import json


def walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}[{index}]")
    else:
        yield path, node


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--parent-config", required=True, help="JSON file with the parent configuration object")
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--staging-ref", required=True)
    parser.add_argument("--content-hash", required=True)
    parser.add_argument("--size", required=True, type=int)
    parser.add_argument("--label", help="replace every data-access label, e.g. RESTRICTED")
    parser.add_argument("--out", required=True, help='writes {"configuration": {...}}')
    args = parser.parse_args()

    loaded = json.load(open(args.parent_config, encoding="utf-8"))
    parent = loaded.get("configuration", loaded)
    cfg = copy.deepcopy(parent)
    ep = cfg["extractionProfile"]
    rt = ep["runtime"]
    old_ids = {rt["assetId"], rt["fileProfileId"], rt["stagingRef"], rt["contentHash"]}

    schema_ref = f"profile://managed-files/{args.asset_id}/profiles/{args.profile_id}"
    cfg["bundle"]["schemaRef"] = schema_ref
    if "extractionProfileRef" in cfg["bundle"]:
        cfg["bundle"]["extractionProfileRef"] = f"file-{args.profile_id}"
    ep["profileId"] = f"file-{args.profile_id}"
    ep["selection"] = {"assetId": args.asset_id, "fileProfileId": args.profile_id}
    rt.update(assetId=args.asset_id, fileProfileId=args.profile_id,
              stagingRef=args.staging_ref, contentHash=args.content_hash)
    rt["execution"].update(expectedSize=args.size, sourceSchemaRef=schema_ref)
    if args.label:
        for policy in cfg.get("dataAccessPolicies", []):
            policy["label"] = args.label
        for prop in rt.get("udp", {}).get("materialization", {}).get("properties", []):
            prop["accessLabel"] = args.label

    leftovers = [p for p, v in walk(cfg) if any(old in str(v) for old in old_ids)]
    if leftovers:
        raise SystemExit("old file references still present at: " + ", ".join(leftovers))

    before, after = dict(walk(parent)), dict(walk(cfg))
    changed = [(k, before[k], after[k]) for k in before if before[k] != after.get(k)]
    labels = [c for c in changed if c[0].endswith(".label") or c[0].endswith(".accessLabel")]
    for path, old, new in changed:
        if (path, old, new) not in labels:
            print(f"{path}\n   old: {old}\n   new: {new}")
    if labels:
        print(f"labels changed: {len(labels)} ({labels[0][1]} -> {labels[0][2]})")
    print("total changed leaves:", len(changed))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"configuration": cfg}, f, ensure_ascii=False)


if __name__ == "__main__":
    main()
