#!/usr/bin/env bash
set -euo pipefail
umask 077
oufStage=DOWNLOAD
trap 'oufCode=$?; printf "OUF_NETWORK_GUARD_BOOTSTRAP=BLOCKED STAGE=%s EXIT_CODE=%s NO_RAW_OUTPUT=true\n" "$oufStage" "$oufCode" >&2' ERR
test "$(id -un)" = oufadmin
oufGh=/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh
oufPackage="$(mktemp -d "$HOME/ouf-network-guard-source.XXXXXXXX")"
printf "OUF_NETWORK_GUARD_DOWNLOAD=%s\n" "$oufPackage"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_guard_extension/extend_empty_lease_guard.py?ref=f7740ce1cbe03c16f5069398985c8795ef1f68b9" --jq .content | base64 -d > "$oufPackage/extend_empty_lease_guard.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_guard_extension/build_guard_profiles.py?ref=f7740ce1cbe03c16f5069398985c8795ef1f68b9" --jq .content | base64 -d > "$oufPackage/build_guard_profiles.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_guard_extension/publish_guard_files.py?ref=f7740ce1cbe03c16f5069398985c8795ef1f68b9" --jq .content | base64 -d > "$oufPackage/publish_guard_files.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_guard_extension/install_provider_network_guard.py?ref=f7740ce1cbe03c16f5069398985c8795ef1f68b9" --jq .content | base64 -d > "$oufPackage/install_provider_network_guard.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_transaction_network/build_target_network_policy.py?ref=f7740ce1cbe03c16f5069398985c8795ef1f68b9" --jq .content | base64 -d > "$oufPackage/build_target_network_policy.py"
"$oufGh" api "repos/GioNob/ouf-deploy/contents/tools/semantic_transaction_network/read_gateway_peer_port.py?ref=f7740ce1cbe03c16f5069398985c8795ef1f68b9" --jq .content | base64 -d > "$oufPackage/read_gateway_peer_port.py"
cat > "$oufPackage/captured-network-inputs.json" <<'OUF_CAPTURED'
{
  "schema": "ouf.semantic-provider-transaction-network-inputs.v1",
  "status": "NETWORK_INPUTS_CAPTURED",
  "operatorReport": "/tmp/ouf-transaction-network-979dcbgd",
  "providerEndpoint": {
    "hostname": "schema.gov.it",
    "path": "/sparql",
    "port": 443
  },
  "oidcIssuerEndpoint": {
    "hostname": "auth.ouf-lab.it",
    "path": "/realms/ouf",
    "port": 443
  },
  "commonLockFile": "/run/ouf-semantic-boot-guard/guard.lock",
  "coordinationBinding": {
    "configurationHash": "f23515ca320983f380c2153e1ef8153be67b1343febd3d16d40bbcd9cbbe5c91",
    "leaseStructureHash": "26f6f80af9d1e4898c1a6fe6dc8721cd6f67f1ceed05c7eea35e3b9f4a040e54",
    "transactionId": "4c10ae427cc9e42a02b442df9ddad495191c3b3383f010d95483d494753b42e1"
  },
  "inputHashes": {
    "binding": "3f1872a332da691667a306db11d0749065ec2149080437853eada820ff7ec47a",
    "plan": "1e85ab77fdd8b1e439cf92542652d65b5ea044cfed50ef2214c89a16170645a2",
    "coordination": "be76f56598ef3d7e91e773351b6a04f8a4595c4fb6ef1d70986d47ddb350ad04"
  },
  "dns": {
    "resolvers": [
      "46.38.225.230",
      "46.38.252.230"
    ],
    "resolverPort": 53,
    "timeoutSeconds": 2,
    "maxLeaseSeconds": 30,
    "applyBudgetSeconds": 1
  },
  "kernel": {
    "tableName": "ouf_sem_provider",
    "guardedInterfaces": [
      "oufsp-int",
      "oufsp-egress"
    ],
    "existingInterfaces": [
      "br-113b5f0a3c53",
      "br-1209d6794475",
      "br-d60139f6aee7",
      "docker0"
    ],
    "staticFlows": [
      {
        "destination": "172.21.0.3",
        "port": 9443,
        "protocol": "tcp",
        "purpose": "GATEWAY_ADAPTER",
        "source": "172.21.0.2"
      },
      {
        "source": "172.22.0.2",
        "destination": "46.38.252.230",
        "protocol": "udp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.2",
        "destination": "46.38.252.230",
        "protocol": "tcp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.2",
        "destination": "46.38.225.230",
        "protocol": "udp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.2",
        "destination": "46.38.225.230",
        "protocol": "tcp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.3",
        "destination": "46.38.252.230",
        "protocol": "udp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.3",
        "destination": "46.38.252.230",
        "protocol": "tcp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.3",
        "destination": "46.38.225.230",
        "protocol": "udp",
        "port": 53,
        "purpose": "DNS"
      },
      {
        "source": "172.22.0.3",
        "destination": "46.38.225.230",
        "protocol": "tcp",
        "port": 53,
        "purpose": "DNS"
      }
    ],
    "providerFlows": [
      {
        "endpointRef": "schema-gov",
        "endpoint": {
          "hostname": "schema.gov.it",
          "path": "/sparql",
          "port": 443
        },
        "leaseSeconds": 30,
        "resolutionEvidenceRef": "fresh-lease-owner",
        "source": "172.22.0.3",
        "allowedPrivateAddresses": []
      }
    ]
  },
  "configurationWrites": 0,
  "containerLifecycleOperations": 0,
  "firewallWrites": 0,
  "providerCalls": 0,
  "startAuthorized": false,
  "acceptanceGranted": false
}
OUF_CAPTURED
printf '%s' '{"hashes":{"build_guard_profiles.py":"ace451e693102b1fe7e50dc954c71c6c93672ad06670f0ba20fd0ebd600f0774","build_target_network_policy.py":"4a284d7762b07b7ba0ec81f2b3d97d8364cbd750203062453ca2e71782bbe488","captured-network-inputs.json":"f9d2f800f1632c30d0f6502bf598431e4d55dc4ff651e2256afd1aed9e2fc756","extend_empty_lease_guard.py":"a2da96318982f48d7230c958841c83994bcfca172aeb8612343a3df57049855d","install_provider_network_guard.py":"9649f309249297d023338593c98e42f74b6aa33d88ebeb88b150308433518ab8","publish_guard_files.py":"3336bc05a9f2ae950af083fb350a693c558ebe48f804a606d56add1187ef402e","read_gateway_peer_port.py":"dd7aa7e671076e8bf2384660dc76d73568c435cb0f69049104929b2292e00a36"},"schema":"ouf.provider-network-guard-source.v1","sourceRef":"f7740ce1cbe03c16f5069398985c8795ef1f68b9"}' > "$oufPackage/sources.json"
oufStage=ROOT_INSTALLER_EXECUTION
sudo /usr/bin/python3 -I -B - "$oufPackage" cf219fd5b9c6d883a49ab690f3d59ecc9db7d9806fdc4c46ba0af19a6ba7dfca <<'OUF_ROOT'
import hashlib,json,os,pathlib,stat,sys,tempfile
stage='SOURCE_PROMOTION';destination=None
try:
 os.umask(0o077)
 source=pathlib.Path(sys.argv[1]);expected=sys.argv[2]
 def read(name):
  fd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   s=os.fstat(fd)
   if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>2000000:raise ValueError('SOURCE_FILE_TYPE_OR_SIZE')
   raw=os.read(fd,2000001)
   if len(raw)!=s.st_size:raise ValueError('SOURCE_CHANGED_DURING_READ')
   return raw
  finally:os.close(fd)
 manifest=read('sources.json')
 if hashlib.sha256(manifest).hexdigest()!=expected:raise ValueError('SOURCE_MANIFEST_HASH_CHANGED')
 data=json.loads(manifest)
 names={'extend_empty_lease_guard.py','build_guard_profiles.py','publish_guard_files.py','install_provider_network_guard.py','build_target_network_policy.py','read_gateway_peer_port.py','captured-network-inputs.json'}
 if set(data['hashes'])!=names:raise ValueError('SOURCE_CLOSURE_CHANGED')
 bodies={name:read(name) for name in names}
 for name,body in bodies.items():
  if hashlib.sha256(body).hexdigest()!=data['hashes'][name]:raise ValueError('SOURCE_HASH_CHANGED_'+name)
 parent=pathlib.Path('/etc/ouf/deploy-snapshots')
 for ancestor in (parent,*parent.parents):
  s=ancestor.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:raise ValueError('ROOT_SOURCE_PARENT_UNSAFE')
 destination=pathlib.Path(tempfile.mkdtemp(prefix='semantic-network-guard-source-',dir=parent))
 for name,body in {**bodies,'sources.json':manifest}.items():
  fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   os.fchown(fd,0,0)
   with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(body);stream.flush();os.fsync(fd)
  finally:os.close(fd)
 print('OUF_NETWORK_GUARD_SOURCE='+str(destination),flush=True)
 stage='INSTALLER_EXECUTION'
 os.execv(sys.executable,[sys.executable,'-I','-B',str(destination/'install_provider_network_guard.py'),'--source-directory',str(destination),'--manifest-sha256',expected])
except Exception as error:
 print('OUF_NETWORK_GUARD_PROMOTION_DIAGNOSIS='+json.dumps({'status':'BLOCKED','stage':stage,'reason':str(error) if isinstance(error,ValueError) else type(error).__name__,'snapshotDirectory':str(destination) if destination else None,'configurationWrites':0,'secretValuesPrinted':False},sort_keys=True))
 raise SystemExit(1)
OUF_ROOT
