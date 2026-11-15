"""Inventory of hash-pinned, root-custodied trust anchors (generation zero)."""
import hashlib
import re
import time

from tools.operational_signals import M, atomic_status, public, require
from tools.semantic_provider_r3.install_common import Arguments

SCHEMA = "ouf.trust-window-status.v1"
INVENTORY = "ouf.trust-window-inventory.v1"
SLUG = re.compile(r"[a-z0-9-]{1,64}")


def slug(value):
    return type(value) is str and SLUG.fullmatch(value) is not None


def pinned(path, digest):
    require(M.hashed(digest), "TRUST_WINDOW_HASH_REQUIRED")
    raw = M.private_bytes(M.absolute(path))
    require(hashlib.sha256(raw).hexdigest() == digest, "TRUST_WINDOW_HASH_MISMATCH")
    return raw


def expiration(raw):
    """Reuse the anchor validator and its key-mandate windows, without a ledger input."""
    value = M.decode(raw)
    policy = M.anchor(raw, value.get("installationRef"), value.get("entityRef"))
    # All declared roles/mandates bound by this policy, including expired/revoked ones.
    # Do not hide the earliest boundary by selecting only currently valid keys.
    return min(key["expiresAt"] for key in policy["keys"])


def observe(args):
    inventory = M.decode(pinned(args.inventory, args.inventory_sha256))
    require(set(inventory) == {"schema", "windows"} and inventory["schema"] == INVENTORY
            and type(inventory["windows"]) is list and len(inventory["windows"]) <= 16,
            "TRUST_WINDOW_INVENTORY_INVALID")
    windows, refs = [], set()
    for row in inventory["windows"]:
        require(type(row) is dict and set(row) == {"ref", "policyPath", "policySha256", "liveConsumers"}
                and slug(row["ref"]) and row["ref"] not in refs
                and type(row["liveConsumers"]) is list and len(row["liveConsumers"]) <= 16
                and all(slug(v) for v in row["liveConsumers"])
                and len(set(row["liveConsumers"])) == len(row["liveConsumers"]),
                "TRUST_WINDOW_INVENTORY_INVALID")
        refs.add(row["ref"])
        raw = pinned(row["policyPath"], row["policySha256"])
        windows.append({"ref": row["ref"], "policySha256": row["policySha256"],
                        "expiresAt": expiration(raw), "liveConsumers": sorted(row["liveConsumers"])})
    return {"schema": SCHEMA, "checkedAt": int(time.time()), "windows": sorted(windows, key=lambda w: w["ref"])}


def arguments(argv=None):
    parser = Arguments(description="Read hash-pinned trust-window inventory")
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--status-path", default="/var/lib/ouf-trust-windows/status.json")
    return parser.parse_args(argv)


def main(argv=None):
    try:
        args = arguments(argv)
        value = observe(args)
        destination = M.absolute(args.status_path)
        require(destination != M.absolute(args.inventory), "TRUST_WINDOW_SEPARATE_STATUS_REQUIRED")
        # Never overwrite an inventoried input, even through an explicitly chosen output path.
        inventory = M.decode(pinned(args.inventory, args.inventory_sha256))
        require(all(destination != M.absolute(w["policyPath"]) for w in inventory["windows"]),
                "TRUST_WINDOW_SEPARATE_STATUS_REQUIRED")
        atomic_status(destination, value)
    except Exception as error:
        print(public(error), flush=True)
        return 1
    print("TRUST_WINDOW_STATUS_WRITTEN", flush=True)
    return 0
