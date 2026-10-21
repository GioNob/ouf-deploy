"""Rebind a sealed unapplied declaration to one verified durable package.

Pure transformation only. This grants no import, transition, peer, lease or
HUMAN authority; all prior inputs and retained native/host frames are preserved.
"""
import copy
import hashlib
import json
import re

OLD_IMAGE = "sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85"
IMAGE = "sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e"
SOURCE = "8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3"
ZIP_HASH = "b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def"

def require(ok, reason):
    if not ok: raise ValueError(reason)

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def environment(rows):
    require(type(rows) is list and len(rows)<=256,"BOUNDED_ENVIRONMENT_REQUIRED")
    out={}
    for row in rows:
        require(type(row) is str and len(row)<=65536 and "=" in row,"EXACT_ENVIRONMENT_ENTRY_REQUIRED")
        key,value=row.split("=",1)
        require(re.fullmatch("[A-Za-z_][A-Za-z0-9_]{0,127}",key) and key not in out,"UNIQUE_ENVIRONMENT_KEYS_REQUIRED")
        out[key]=value
    return out

def rebind(declaration, expected_hash, verified_config):
    require(digest(declaration)==expected_hash,"SEALED_PREDECESSOR_DECLARATION_REQUIRED")
    require(declaration.get("schema")=="ouf.discovery.private-file-secret-runtime-declaration.v1"
            and declaration.get("candidateImageId")==OLD_IMAGE
            and all(declaration.get(k) is False for k in
                    ("productionApplyReady","applicationCutoverAuthorized","completeReplacementOciProven")),
            "EXACT_UNAPPLIED_PREDECESSOR_REQUIRED")
    old=declaration["candidateConfig"]
    fields=("Entrypoint","Cmd","User","WorkingDir","ExposedPorts","Volumes","StopSignal","Healthcheck","Shell")
    require(verified_config.get("User")=="10001:10001"
            and all(verified_config.get(k)==old.get(k) for k in fields),
            "EXECUTION_DEFAULT_CHANGE_REQUIRES_REVIEW")
    old_labels=old.get("Labels") or {}
    new_labels=verified_config.get("Labels") or {}
    require(new_labels.get("org.opencontainers.image.revision")==SOURCE,
            "EXACT_NEW_SOURCE_LABEL_REQUIRED")
    require({k:v for k,v in old_labels.items() if k!="org.opencontainers.image.revision"}
            =={k:v for k,v in new_labels.items() if k!="org.opencontainers.image.revision"},
            "UNRELATED_IMAGE_LABEL_CHANGE_REQUIRES_REVIEW")
    before,new=environment(old["Env"]),environment(verified_config["Env"])
    application={k:v for k,v in before.items() if k.startswith(("OUF_","SPRING_","MANAGEMENT_"))
                 or k in ("PORT","JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS")}
    runtime={"PATH","JAVA_HOME","JAVA_VERSION","LANG","LANGUAGE","LC_ALL","TZ"}
    require(set(before)<=set(application)|runtime and set(new)<=runtime,
            "UNREVIEWED_IMAGE_ENVIRONMENT_REQUIRED")
    require(application and new.get("JAVA_HOME")=="/opt/java/openjdk",
            "EXACT_RETAINED_APPLICATION_ENV_REQUIRED")
    require("OUF_SEM_DB_PASSWORD" not in application and "SPRING_DATASOURCE_PASSWORD" not in application,
            "FILE_SECRET_ONLY_REQUIRED")
    require(application.get("SPRING_CONFIG_IMPORT")=="configtree:"+declaration["databaseSecretProjection"]["targetDirectory"]+"/",
            "MANDATORY_RETAINED_CONFIGTREE_REQUIRED")
    result=copy.deepcopy(declaration)
    # Retain every declared creation field other than the explicitly reviewed
    # image defaults below. No new mount, host/config privilege or role input.
    result["candidateImageId"]=IMAGE
    result["candidateConfig"]["Env"]=[k+"="+v for k,v in sorted({**new,**application}.items())]
    result["candidateConfig"]["Labels"]=copy.deepcopy(new_labels)
    result["qualifiedPackageBinding"]={"sourceCommit":SOURCE,"zipSha256":ZIP_HASH,"imageId":IMAGE,
                                       "predecessorDeclarationHash":expected_hash}
    result["freshRuntimeCustodyProven"]=False
    result["newTransportClosureProven"]=False
    require(result["proposedHostConfig"]==declaration["proposedHostConfig"]
            and result["retainedNativeCreationFrame"]==declaration["retainedNativeCreationFrame"]
            and result["roleOwnedReadOnlyMounts"]==declaration["roleOwnedReadOnlyMounts"]
            and result["databaseSecretProjection"]==declaration["databaseSecretProjection"],
            "PREDECESSOR_INPUT_FRAME_PRESERVATION_REQUIRED")
    return result
