"""Independent readback of the installed supervisor, signed epoch and live nft members."""
from contextlib import contextmanager
import json
import time

from mandate import digest, need
from semantic_identity_v25 import semantic_command, semantic_observe
from store import bound, read, trusted


def live_members(elems, expected, max_seconds, remaining):
    # libnftables JSON reports "expires" in whole seconds (kernel milliseconds / 1000).
    need(sorted(e["elem"]["val"] for e in elems) == sorted(expected) and expected
         and all(type(e["elem"]["expires"]) is int and
                 0 < remaining < e["elem"]["expires"] <= max_seconds for e in elems),
         "LEASE_EXPIRED")


@contextmanager
def verified(sup, profile, cid, version):
    import fcntl
    spec, coord = sup["semanticIngress"], sup["coordinator"]
    need(spec["profile"] == profile, "INSTALLED_PROFILE_DRIFT")
    epoch, _ = semantic_observe(profile, spec["commands"])
    need(epoch["containerId"] == cid, "EPOCH_CID_DRIFT")
    owner = json.loads(bound(coord["ownerConfiguration"]).read_bytes())
    with trusted(coord["commonLockPath"]).open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = read(sup["statusPath"])
        lease = read(coord["journalPath"])
        age_ms = state["lastSemanticVerifiedAgeMs"]
        elapsed = time.time() - state["updatedAt"]
        need(state["state"] == "ACTIVE" and state["authorizationSequence"] == version
             and state["semanticEpoch"] == digest(epoch) and state["lastSemanticTick"]["outcome"] == "VERIFIED"
             and type(age_ms) is int and age_ms >= 0 and elapsed >= 0
             and age_ms/1000 + elapsed <= sup["leaseRenewal"]["semanticFullObservationSeconds"]
             and lease["state"] == "LEASE_READY" and lease["leaseAuthorized"] is True,
             "INGRESS_VERIFICATION_REQUIRED")
        deadline = time.monotonic() + sup["leaseRenewal"]["semanticTickBudgetSeconds"]
        def members(family, table, name):
            argv = ["-j", "-n", "list", "set", family, table, name]
            obj, = [r["set"] for r in json.loads(semantic_command(coord["nftBinding"], argv,
                    deadline=deadline))["nftables"] if "set" in r]
            need((obj["family"], obj["table"], obj["name"]) == (family, table, name), "NFT_BINDING")
            return obj["elem"]
        address = profile["ipv4"]
        port = epoch["binding"]
        need(members("bridge", spec["table"], "semantic_port") in ([port["hostIfindex"]], [port["hostInterface"]]),
             "INGRESS_PORT_DRIFT")
        addresses = lease["leaseAddresses"]
        flows = owner["kernel"]["providerFlows"]
        need(addresses and len(addresses) == len(flows) and all(addresses), "LEASE_MEMBERS_EMPTY")
        for family in ("bridge", "inet"):
            need(members(family, spec["table"], "semantic_open") == [address], "INGRESS_CLOSED")
            for index, expected in enumerate(addresses):
                remaining = deadline - time.monotonic()
                elems = members(family, owner["kernel"]["tableName"], f"provider_{index}")
                live_members(elems, expected, flows[index]["leaseSeconds"], remaining)
        need(time.monotonic() < deadline, "VERIFICATION_TIMEOUT")
        yield deadline
