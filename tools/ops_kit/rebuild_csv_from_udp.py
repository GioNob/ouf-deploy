#!/usr/bin/env python3
"""Rebuild a managed CSV from the canonical payloads UDP received for a run.

Column order and column->property mapping come from the onboarding
configuration of the source that produced the run (extractionProfile.projection
and semanticMapping.propertyMappings). The payloads come from
sql/udp_source_payloads.sql. With --expect-sha256 the script proves the rebuilt
bytes are identical to the originally uploaded file (managed_file_asset.content_hash).
"""
import argparse
import csv
import hashlib
import io
import json


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--payloads", required=True, help="JSON array of canonicalPayload objects")
    parser.add_argument("--config", required=True, help="configuration of the source that produced the payloads")
    parser.add_argument("--bom", action="store_true", help="prefix a UTF-8 BOM")
    parser.add_argument("--crlf", action="store_true", help="use CRLF line endings")
    parser.add_argument("--expect-sha256", help="hex digest or sha256:<hex> the output must match")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    loaded = json.load(open(args.config, encoding="utf-8"))
    cfg = loaded.get("configuration", loaded)
    columns = next(iter(cfg["extractionProfile"]["projection"].values()))
    mapping = {m["sourceField"]: m["targetPropertyIri"] for m in cfg["semanticMapping"]["propertyMappings"]}
    delimiter = cfg["extractionProfile"]["runtime"].get("csvDelimiter", ",")
    rows = json.load(open(args.payloads, encoding="utf-8"))

    missing = [c for c in columns if c not in mapping]
    if missing:
        raise SystemExit(f"columns without mapping: {missing}")
    for index, row in enumerate(rows):
        absent = [mapping[c] for c in columns if mapping[c] not in row]
        if absent:
            raise SystemExit(f"payload {index} lacks {absent}")

    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=delimiter, lineterminator="\r\n" if args.crlf else "\n",
                        quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[mapping[c]] for c in columns])
    data = (b"\xef\xbb\xbf" if args.bom else b"") + buf.getvalue().encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"{args.out}: {len(rows)} rows, {len(data)} bytes, sha256:{digest}")
    if args.expect_sha256:
        expected = args.expect_sha256.removeprefix("sha256:").lower()
        if digest != expected:
            raise SystemExit(f"MISMATCH: expected sha256:{expected}; try toggling --bom/--crlf")
        print("BYTE_IDENTICAL_TO_EXPECTED")


if __name__ == "__main__":
    main()
