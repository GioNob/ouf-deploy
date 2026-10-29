#!/usr/bin/env python3
"""Read installed deployment binding names and mounted file metadata; no key contents or mutations."""
import json, os, stat, subprocess
TARGETS=("ouf-semantic","ouf-apisix","ouf-mcp","ouf-semantic-provider","ouf-semantic-southbound","ouf-keycloak")
result={"schema":"ouf.discovery.installation-bindings.v1","secretValuesPrinted":False,"keyFilesRead":False,"configurationWrites":0,"containerLifecycleOperations":0,"releaseApplied":False,"components":[]}
for name in TARGETS:
    p=subprocess.run(["docker","inspect",name],capture_output=True,timeout=20)
    if p.returncode:
        result["components"].append({"name":name,"inspectAvailable":False})
        continue
    item=json.loads(p.stdout)[0]
    env=dict(x.split("=",1) for x in item["Config"].get("Env",[]) if "=" in x)
    row={"name":name,"running":bool(item["State"]["Running"]),"imageId":item["Image"],"user":item["Config"].get("User"),"bindingNames":sorted(k for k in env if k.startswith(("OUF_","KC_","KEYCLOAK_"))),"mounts":[]}
    for m in item.get("Mounts",[]):
        entry={"destination":m["Destination"],"readOnly":not m["RW"],"type":m["Type"]}
        if m["Type"]=="bind":
            try:
                s=os.lstat(m["Source"])
                entry.update(sourceAvailable=True,symlink=stat.S_ISLNK(s.st_mode),mode=oct(stat.S_IMODE(s.st_mode)),uid=s.st_uid,gid=s.st_gid,directory=stat.S_ISDIR(s.st_mode),regularFile=stat.S_ISREG(s.st_mode))
                if stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode):
                    entry["directEntryCount"]=len(os.listdir(m["Source"]))
            except OSError:
                entry["sourceAvailable"]=False
        row["mounts"].append(entry)
    if name=="ouf-semantic":
        keys=("OUF_SCHEMA_GOV_ENABLED","OUF_SCHEMA_GOV_GATEWAY_BASE_URL","OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED","OUF_SCHEMA_GOV_TOKEN_ENDPOINT","OUF_SCHEMA_GOV_CLIENT_ID","OUF_SCHEMA_GOV_CLIENT_SECRET_FILE","OUF_SCHEMA_GOV_WORKLOAD_SCOPE")
        row["explicitProviderBindingsPresent"]={k:bool(env.get(k)) for k in keys}
    if name=="ouf-keycloak":
        row["bootstrapCredentialBindingsPresent"]=any(bool(env.get(k)) for k in ("KC_BOOTSTRAP_ADMIN_PASSWORD","KEYCLOAK_ADMIN_PASSWORD"))
    result["components"].append(row)
print("OUF_DISCOVERY_INSTALLATION_BINDINGS="+json.dumps(result,sort_keys=True))
