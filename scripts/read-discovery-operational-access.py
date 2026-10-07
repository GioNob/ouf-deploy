#!/usr/bin/env python3
"""Probe the runner's existing privilege and IAM session; never read or print client secrets."""
import json, subprocess
r={"schema":"ouf.discovery.operational-access.v1","configurationWrites":0,"containerLifecycleOperations":0,"secretValuesPrinted":False,"clientSecretsRead":False}
def call(args):
    return subprocess.run(args,capture_output=True,text=True,timeout=30)
try:
    p=call(["sudo","-n","true"])
    r["existingNoninteractiveSudoAvailable"]=p.returncode==0
except (OSError,subprocess.TimeoutExpired):
    r["existingNoninteractiveSudoAvailable"]=False
base=["docker","exec","-i","ouf-keycloak","/opt/keycloak/bin/kcadm.sh","get"]
try:
    c=call(base+["clients","-r","ouf","--fields","id,clientId"])
    if c.returncode:
        r["iamReadStatus"]="EXISTING_SESSION_UNAVAILABLE"
    else:
        clients=json.loads(c.stdout)
        scopes=call(base+["client-scopes","-r","ouf","--fields","id,name"])
        if scopes.returncode:
            r["iamReadStatus"]="SCOPES_UNAVAILABLE"
        else:
            names={x["name"] for x in json.loads(scopes.stdout)}
            r["iamReadStatus"]="PASS"
            r["requiredScopeDefinitionsPresent"]={k:k in names for k in ("gateway.southbound.invoke","ouf.semantic.discovery")}
            r["matchingClients"]=[]
            for client in clients:
                name=client.get("clientId","")
                if name not in ("ouf-semantic-registry","ouf-semantic","ouf-human-admin","ouf-api-gateway","ouf-mcp-server"):
                    continue
                cid=client["id"]
                d=call(base+["clients/"+cid+"/default-client-scopes","-r","ouf","--fields","name"])
                o=call(base+["clients/"+cid+"/optional-client-scopes","-r","ouf","--fields","name"])
                defaults={x["name"] for x in json.loads(d.stdout)} if d.returncode==0 else set()
                optionals={x["name"] for x in json.loads(o.stdout)} if o.returncode==0 else set()
                r["matchingClients"].append({"clientId":name,"scopeAssignment":{k:"DEFAULT" if k in defaults else "OPTIONAL" if k in optionals else "NONE" for k in ("gateway.southbound.invoke","ouf.semantic.discovery")}})
except (OSError,ValueError,KeyError,subprocess.TimeoutExpired):
    r["iamReadStatus"]="READ_FAILED"
print("OUF_DISCOVERY_OPERATIONAL_ACCESS="+json.dumps(r,sort_keys=True))
