"""Read the existing Semantic bridge peer needed by exact southbound admission."""
import json
import subprocess

SCRIPT = "for n in /sys/class/net/*; do printf '%s ' \"${n##*/}\"; cat \"$n/address\" | tr '\\n' ' '; cat \"$n/iflink\"; done"

def main():
 stage='SEMANTIC_NIC_METADATA'
 try:
  r=subprocess.run(['/usr/bin/docker','exec','ouf-semantic','sh','-c',SCRIPT],capture_output=True,text=True,timeout=15)
  if r.returncode or len(r.stdout)>4096:raise ValueError('SEMANTIC_NIC_READ_FAILED')
  selected=[]
  for line in r.stdout.splitlines():
   fields=line.split()
   if len(fields)!=3:raise ValueError('NIC_METADATA_FORMAT')
   if fields[1]=='b2:96:a1:e2:c1:8d':selected.append((fields[0],int(fields[2])))
  if len(selected)!=1:raise ValueError('SEMANTIC_BACKEND_MAC_DRIFT')
  interface,index=selected[0]
  stage='HOST_PEER_PORT'
  r=subprocess.run(['/usr/bin/ip','-j','link','show'],capture_output=True,text=True,timeout=15)
  if r.returncode or len(r.stdout)>131072:raise ValueError('HOST_PORT_READ_FAILED')
  rows=json.loads(r.stdout);matches=[v for v in rows if v.get('ifindex')==index]
  if len(matches)!=1 or matches[0].get('master')!='br-113b5f0a3c53':raise ValueError('SEMANTIC_PEER_BRIDGE_DRIFT')
  print('OUF_SEMANTIC_PEER_PORT='+json.dumps({'status':'EXISTING_PEER_PORT_CAPTURED','container':'ouf-semantic','address':'172.18.0.6','mac':'b2:96:a1:e2:c1:8d','childInterface':interface,'hostInterface':matches[0]['ifname'],'hostIfindex':index,'bridge':'br-113b5f0a3c53','configurationWrites':0,'containerLifecycleOperations':0,'privateFilesRead':0,'providerCalls':0},sort_keys=True))
 except Exception as e:
  print('OUF_SEMANTIC_PEER_PORT='+json.dumps({'status':'BLOCKED','stage':stage,'reason':str(e) if isinstance(e,ValueError) else 'BOUNDED_PEER_METADATA_FAILED','errorClass':type(e).__name__,'secretValuesPrinted':False},sort_keys=True));raise SystemExit(1)
if __name__=='__main__':main()
