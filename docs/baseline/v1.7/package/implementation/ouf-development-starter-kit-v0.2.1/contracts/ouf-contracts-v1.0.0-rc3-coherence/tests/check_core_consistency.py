#!/usr/bin/env python3
import json, sys
from pathlib import Path

def fail(errors, msg):
    errors.append(msg)

def eq(errors, a, b, label):
    if a != b:
        fail(errors, f"{label}: {a!r} != {b!r}")

def seteq(errors, a, b, label):
    if set(a or []) != set(b or []):
        fail(errors, f"{label}: {a!r} != {b!r}")

def check(doc):
    e = doc["CanonicalDataEnvelope"]
    h = doc["HandoffPayload"]
    l = doc["LineageRecord"]
    errors=[]

    eq(errors, e["ingestionId"], h["ingestionId"], "CC-01 envelope->handoff ingestionId")
    eq(errors, e["ingestionId"], l["ingestionId"], "CC-01 envelope->lineage ingestionId")
    eq(errors, e["runId"], h["ingestionRunId"], "CC-02 run identity")
    eq(errors, e["runId"], l["ingestionRunId"], "CC-02 run identity")
    eq(errors, e["sourceId"], h["sourceIdentity"]["sourceId"], "CC-03 sourceId")
    eq(errors, e["sourceId"], l["source"]["sourceId"], "CC-03 sourceId")

    for field, hfield, lfield, cid in [
        ("typeCode","typeCode","typeCode","CC-04"),
        ("sourceObjectId","sourceObjectId","sourceObjectId","CC-05"),
    ]:
        if e.get(field) is not None:
            eq(errors, e.get(field), h["sourceIdentity"].get(hfield), f"{cid} envelope->handoff")
            eq(errors, e.get(field), l["source"].get(lfield), f"{cid} envelope->lineage")

    expected_schema = f'{e["sourceSchemaId"]}@{e["sourceSchemaVersion"]}'
    eq(errors, expected_schema, h["contractRefs"]["sourceSchemaRef"], "CC-06 source schema ref")
    eq(errors, expected_schema, l["contracts"]["sourceSchemaRef"], "CC-06 source schema ref")

    expected_bundle = f'{e["configurationBundleId"]}@{e["configurationBundleVersion"]}'
    eq(errors, expected_bundle, h["contractRefs"]["bundleRef"], "CC-07 bundle ref")
    eq(errors, expected_bundle, l["contracts"]["bundleRef"], "CC-07 bundle ref")

    eq(errors, h["contractRefs"]["semanticPublicationSetRef"], l["contracts"]["semanticPublicationSetRef"], "CC-08 semantic ref")
    eq(errors, h["contractRefs"]["adapterProfileRef"], l["contracts"]["adapterProfileRef"], "CC-09 adapter ref")
    seteq(errors, h["contractRefs"].get("mappingRefs"), l["contracts"].get("mappingRefs"), "CC-10 mapping refs")

    eq(errors, e["acquiredAt"], h["acquiredAt"], "CC-11 acquiredAt")
    eq(errors, e["acquiredAt"], l["times"]["acquiredAt"], "CC-11 acquiredAt")

    if h["sourceIdentity"].get("observedAt") is not None:
        eq(errors, e["observedAt"], h["sourceIdentity"]["observedAt"], "CC-12 observedAt")
    if l["source"].get("sourceObservedAt") is not None:
        eq(errors, e["observedAt"], l["source"]["sourceObservedAt"], "CC-12 observedAt")

    corr=e["provenance"].get("correlationId")
    if h.get("correlationId") is not None:
        eq(errors, corr, h["correlationId"], "CC-13 correlationId")
    if l.get("trace",{}).get("correlationId") is not None:
        eq(errors, corr, l["trace"]["correlationId"], "CC-13 correlationId")

    # Operation semantics: exact equality except SNAPSHOT_RECORD may normalize to UPSERT.
    allowed = (h["operation"] == e["operation"]) or (e["operation"]=="SNAPSHOT_RECORD" and h["operation"]=="UPSERT")
    if not allowed:
        fail(errors, f"CC-14 operation semantics: envelope={e['operation']} handoff={h['operation']}")

    eq(errors, h["lineageId"], l["lineageId"], "CC-15 lineageId")
    eq(errors, h["handoffId"], l["handoffId"], "CC-16 handoffId")

    out_hash=l.get("data",{}).get("outputHash")
    if out_hash is not None:
        eq(errors, h["contentHash"], out_hash, "CC-17 contentHash/outputHash")

    return errors

if __name__=="__main__":
    p=Path(sys.argv[1])
    doc=json.loads(p.read_text(encoding="utf-8"))
    errs=check(doc)
    if errs:
        print("\n".join(errs))
        sys.exit(1)
    print("OUF core contract consistency OK.")
