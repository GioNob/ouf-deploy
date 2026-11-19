"""R-022 (task-85): sola lettura. Campiona ogni secondo timeout/expires dei set nft provider_N.

Nessuna scrittura nft; scrive solo /home/oufadmin/r3diag/sets.jsonl. Uso: sudo python3 r3-readback-capture.py [secondi]
"""
import json, re, subprocess, sys, time

NFT = "/usr/sbin/nft"
OUT = "/home/oufadmin/r3diag/sets.jsonl"
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 720


def nft_json(args):
    r = subprocess.run([NFT, "-j", *args], capture_output=True, timeout=5)
    return json.loads(r.stdout or b"{}") if r.returncode == 0 else {}


def provider_tables():
    found = set()
    for item in nft_json(["list", "sets"]).get("nftables", []):
        s = item.get("set")
        if s and re.fullmatch("provider_[0-9]+", s.get("name", "")):
            found.add((s["family"], s["table"]))
    return sorted(found)


tables = provider_tables()
end = time.monotonic() + DURATION
with open(OUT, "a") as out:
    out.write(json.dumps({"tables": tables}) + chr(10))
    while time.monotonic() < end:
        row = {"t": round(time.time(), 3), "m": round(time.monotonic(), 3), "s": []}
        for family, table in tables:
            for item in nft_json(["list", "table", family, table]).get("nftables", []):
                s = item.get("set")
                if not s or not re.fullmatch("provider_[0-9]+", s.get("name", "")):
                    continue
                elems = [e.get("elem", {}) for e in s.get("elem", [])]
                row["s"].append({"f": family, "n": s["name"],
                                 "e": [{"timeout": e.get("timeout"), "expires": e.get("expires")}
                                       for e in elems if isinstance(e, dict)]})
        out.write(json.dumps(row) + chr(10))
        out.flush()
        time.sleep(1)
