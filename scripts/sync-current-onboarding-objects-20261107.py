#!/usr/bin/env python3
"""Copy missing current Onboarding objects to SeaweedFS; never overwrite or switch bindings."""
import datetime
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from urllib.parse import parse_qsl, quote
from xml.etree import ElementTree as ET

ROOT = Path('/var/lib/ouf-storage-migration')
PLAN = ROOT / 'cold-host-bound-20261107-v1/plan.private.json'
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
APP_IMAGE = 'sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51'
SEA_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
BUCKET = 'ouf-managed-files'
BINDINGS = ROOT / 'seaweedfs/staging-oci33-20261107-v1/application-s3-v1'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
METADATA = {'content-type', 'cache-control', 'content-disposition', 'content-encoding', 'content-language', 'expires'}
DEADLINE = 0


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


# Existing MinIO binding reader adapted from ouf-deploy@681935b6.
# InputBinding accepts existing file ownership/modes and never changes them.
require = need
Stop = RuntimeError


def attrs(s):
    return [getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                   'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

"""Bounded MinIO file/env precedence, without shells, defaults or secret exports."""
KEYS=('MINIO_ROOT_USER','MINIO_ROOT_PASSWORD','MINIO_ACCESS_KEY','MINIO_SECRET_KEY')
SPACE=' \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000'
def trim(value):return value.decode().strip(SPACE).encode()
class Binding:
 def __init__(self,pid,root=None,cwd=None):
  self.root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY) if root is None else os.dup(root)
  try:self.cwd=os.open('/proc/'+str(pid)+'/cwd',os.O_RDONLY|os.O_DIRECTORY) if cwd is None else os.dup(cwd)
  except BaseException:os.close(self.root);raise
  self.pid=pid if root is None else None;self.files={};self.probes={};self.opened=0;self.bytes=0;self.region=None;self.root_access=None
 def close(self):os.close(self.cwd);os.close(self.root)
 def path(self,raw):
  require(type(raw) is str and 0<len(raw.encode())<=4096 and '\x00' not in raw and '\n' not in raw and '\r' not in raw,'BOUNDED_DECLARED_CREDENTIAL_REFERENCE_REQUIRED')
  p=PurePosixPath(raw);require(not raw.startswith('//') and str(p)==raw and '..' not in p.parts and p.name not in ('','.','..'),'NO_TRAVERSAL_CREDENTIAL_REFERENCE_REQUIRED');return p
 def node(self,anchor,parts):
  fd=os.dup(anchor)
  try:
   for part in parts[:-1]:
    new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
   node=os.open(parts[-1],os.O_PATH|os.O_NOFOLLOW,dir_fd=fd)
   return fd,node
  except BaseException:os.close(fd);raise
 def read(self,raw,limit,config=False,verify=False):
  p=self.path(raw);anchor=self.root if p.is_absolute() else self.cwd;parts=p.parts[1:] if p.is_absolute() else p.parts;key=(p.is_absolute(),str(p),config)
  require(verify or key in self.probes or len(self.probes)<9,'CREDENTIAL_METADATA_CANDIDATE_LIMIT')
  if key in self.files and not verify:return self.files[key][0]
  try:parent,node=self.node(anchor,parts)
  except FileNotFoundError:
   observed=None;value=None
  else:
   try:
    info=os.fstat(node);require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o007 and info.st_nlink==1 and 0<=info.st_size<=limit,'PRIVATE_BOUNDED_REGULAR_CREDENTIAL_SOURCE_REQUIRED');observed=attrs(info)
    if verify:value=None
    else:
     require(self.opened<5,'CREDENTIAL_FILE_READ_LIMIT');self.opened+=1
     fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
     try:
      require(attrs(os.fstat(fd))==observed,'CREDENTIAL_SOURCE_REBOUND');value=os.read(fd,limit+1)
      require(len(value)==info.st_size and attrs(os.fstat(fd))==attrs(os.fstat(node))==observed,'CREDENTIAL_SOURCE_CHANGED');self.bytes+=len(value);require(self.bytes<=81920,'CREDENTIAL_BYTES_LIMIT')
     finally:os.close(fd)
   finally:os.close(node);os.close(parent)
  if verify:require(self.probes[key]==observed,'CREDENTIAL_SOURCE_METADATA_CHANGED');return None
  self.probes[key]=observed
  if value is not None:self.files[key]=(value,limit)
  return value
 def secret(self,raw):
  p=self.path(raw)
  # MinIO pathJoin preserves the /run/secrets prefix for absolute arguments too.
  candidate='/run/secrets/'+str(p).lstrip('/')
  value=self.read(candidate,4096)
  if value is None:value=self.read(str(p),4096)
  return trim(value) if value is not None else b''
 def stable(self):
  if self.pid is not None:
   require(attrs(os.stat('/proc/'+str(self.pid)+'/root'))[:5]==attrs(os.fstat(self.root))[:5] and attrs(os.stat('/proc/'+str(self.pid)+'/cwd'))[:5]==attrs(os.fstat(self.cwd))[:5],'CREDENTIAL_PROCESS_ROOT_OR_CWD_CHANGED')
  for absolute,path,config in list(self.probes):self.read(path,65536 if config else 4096,config=config,verify=True)
 def resolve(self,env):
  effective={k:env[k].encode() for k in KEYS if k in env};origins={k:'EXPLICIT_ENV' for k in effective};region={k:env[k] for k in ['MINIO_REGION_NAME','MINIO_REGION','MINIO_API_ROOT_ACCESS'] if k in env}
  for source,target in [('MINIO_ACCESS_KEY_FILE','MINIO_ROOT_USER'),('MINIO_SECRET_KEY_FILE','MINIO_ROOT_PASSWORD'),('MINIO_ROOT_USER_FILE','MINIO_ROOT_USER'),('MINIO_ROOT_PASSWORD_FILE','MINIO_ROOT_PASSWORD')]:
   if env.get(source):
    value=self.secret(env[source])
    if value:effective[target]=value;origins[target]='DECLARED_SECRET_FILE'
  if env.get('MINIO_CONFIG_ENV_FILE'):
   value=self.read(env['MINIO_CONFIG_ENV_FILE'],65536,config=True)
   if value is not None:
    for line in value.decode().split('\n'):
     line=line.strip(SPACE)
     if not line or line.startswith('#'):continue
     if line.startswith('export'):line=line[6:].strip(SPACE)
     require('=' in line,'MINIO_CONFIG_ENV_ENTRY_REQUIRED');key,value=line.split('=',1)
     if len(value)>=2 and value[0] in ('\"',"'") and value[-1]==value[0]:value=value[1:-1]
     if key in KEYS:effective[key]=value.encode();origins[key]='DECLARED_CONFIG_ENV'
     if key in ('MINIO_REGION_NAME','MINIO_REGION','MINIO_API_ROOT_ACCESS'):region[key]=value
  require(bool(effective.get(KEYS[0]))==bool(effective.get(KEYS[1])),'COMPLETE_ROOT_CREDENTIAL_PAIR_REQUIRED')
  pair=('MINIO_ROOT_USER','MINIO_ROOT_PASSWORD') if all(effective.get(k) for k in KEYS[:2]) else ('MINIO_ACCESS_KEY','MINIO_SECRET_KEY')
  require(all(effective.get(k) for k in pair),'EXPLICIT_EFFECTIVE_CREDENTIAL_PAIR_REQUIRED')
  values=[effective[k] for k in pair]
  require(all(0<len(v)<=4096 and v==trim(v) and b'\x00' not in v and b'\n' not in v and b'\r' not in v for v in values),'EXACT_SDK_CREDENTIAL_VALUE_REQUIRED')
  self.region=region.get('MINIO_REGION_NAME') or region.get('MINIO_REGION') or 'us-east-1'
  self.root_access=region.get('MINIO_API_ROOT_ACCESS');self.stable();return values,{'selectedSources':[origins[k] for k in pair],'secretFilesOpened':self.opened,'sourceBytesRead':self.bytes,'metadataCandidates':len(self.probes),'rawValuesSpooled':False}

class InputBinding(Binding):
 def __init__(self,pid,root=None,cwd=None):
  super().__init__(pid,root,cwd);self.observed={};self.reference_rows=[];self.preflight_done=False;self.policy_blocked=False
 def inspect(self,raw,config=False):
  try:p=self.path(raw)
  except Stop:return None,{'kind':'INVALID_REFERENCE'}
  key=(p.is_absolute(),str(p),config)
  if key in self.observed:return key,self.observed[key]
  require(len(self.observed)<9,'INPUT_METADATA_CANDIDATE_LIMIT');anchor=self.root if p.is_absolute() else self.cwd;parts=p.parts[1:] if p.is_absolute() else p.parts
  current=os.dup(anchor);node=None
  try:
   row=None
   for index,part in enumerate(parts):
    node=os.open(part,os.O_PATH|os.O_NOFOLLOW,dir_fd=current);info=os.fstat(node)
    if index<len(parts)-1:
     if not stat.S_ISDIR(info.st_mode):row={'kind':'ANCESTOR_SYMLINK' if stat.S_ISLNK(info.st_mode) else 'ANCESTOR_NOT_DIRECTORY','metadata':attrs(info)};break
     os.close(current);current=node;node=None
    else:
     mode=info.st_mode;kind='REGULAR' if stat.S_ISREG(mode) else 'SYMLINK' if stat.S_ISLNK(mode) else 'DIRECTORY' if stat.S_ISDIR(mode) else 'SPECIAL'
     limit=65536 if config else 4096
     row={'kind':kind,'metadata':attrs(info),'sizeWithinLimit':0<=info.st_size<=limit,'hasLink':info.st_nlink>=1,'readEligible':kind=='REGULAR' and info.st_nlink>=1 and 0<=info.st_size<=limit}
  except FileNotFoundError:row={'kind':'MISSING'}
  except OSError:row={'kind':'METADATA_UNAVAILABLE'}
  finally:
   if node is not None:os.close(node)
   os.close(current)
  self.observed[key]=row;self.probes[key]=row.get('metadata');return key,row
 def preflight(self,env):
  self.reference_rows=[];self.policy_blocked=False
  for role,name in [('LEGACY_USER','MINIO_ACCESS_KEY_FILE'),('LEGACY_PASSWORD','MINIO_SECRET_KEY_FILE'),('ROOT_USER','MINIO_ROOT_USER_FILE'),('ROOT_PASSWORD','MINIO_ROOT_PASSWORD_FILE'),('CONFIG_ENV','MINIO_CONFIG_ENV_FILE')]:
   if not env.get(name):continue
   config=role=='CONFIG_ENV';raw=env[name]
   try:p=self.path(raw)
   except Stop:self.reference_rows.append({'source':role,'location':'DECLARED','kind':'INVALID_REFERENCE','required':True});self.policy_blocked=True;continue
   candidates=[('DECLARED',str(p))] if config else [('SECRETS_PREFIX','/run/secrets/'+str(p).lstrip('/')),('DECLARED',str(p))]
   scanned=[(location,*self.inspect(path,config)) for location,path in candidates]
   first=scanned[0][2];selected=0 if config or first['kind'] not in ('MISSING','DIRECTORY') else 1
   for index,(location,key,row) in enumerate(scanned):
    required=index==selected;entry={'source':role,'location':location,'kind':row['kind'],'required':required}
    if 'metadata' in row:
     meta=row['metadata'];entry.update(mode=format(stat.S_IMODE(meta[2]),'04o'),rootOwned=meta[3]==0,singleLink=meta[5]==1,sizeWithinLimit=row.get('sizeWithinLimit',False))
     failures=[]
     if row['kind']!='REGULAR':failures.append('NOT_REGULAR')
     if meta[3]!=0:failures.append('NON_ROOT_OWNER')
     if meta[2]&0o007:failures.append('OTHER_PERMISSION_BITS')
     if meta[5]!=1:failures.append('LINK_COUNT_NOT_ONE')
     if not row.get('sizeWithinLimit',False):failures.append('SIZE_OUTSIDE_LIMIT')
     entry['previousGuardFailedPredicates']=failures
    if required and row['kind']!='MISSING' and not row.get('readEligible',False):self.policy_blocked=True
    self.reference_rows.append(entry)
  self.preflight_done=True;return self.public_metadata()
 def public_metadata(self):
  return {'metadataComplete':self.preflight_done,'readPolicy':'EXISTING_DECLARED_REGULAR_BOUNDED_STABLE_INPUTS_ONLY','sourceCustodyAdmitted':False,'policyBlocked':self.policy_blocked,'candidates':self.reference_rows,'filesOpened':self.opened,'sourceBytesRead':self.bytes,'rawValuesSpooled':False}
 def read(self,raw,limit,config=False,verify=False):
  require(self.preflight_done and not self.policy_blocked,'COMPLETE_INPUT_METADATA_PREFLIGHT_REQUIRED');p=self.path(raw);key=(p.is_absolute(),str(p),config);require(key in self.observed,'DECLARED_PREFLIGHTED_INPUT_ONLY')
  initial=self.observed[key];self.observed.pop(key);self.probes.pop(key,None);_,actual=self.inspect(raw,config)
  require(actual==initial,'DECLARED_INPUT_METADATA_CHANGED')
  if verify:return None
  if key in self.files:return self.files[key][0]
  if actual['kind']=='MISSING':return None
  require(actual.get('readEligible') is True,'DECLARED_REGULAR_BOUNDED_INPUT_REQUIRED')
  anchor=self.root if p.is_absolute() else self.cwd;parts=p.parts[1:] if p.is_absolute() else p.parts
  parent,node=self.node(anchor,parts)
  try:
   require(self.opened<5,'CREDENTIAL_FILE_READ_LIMIT');observed=actual['metadata'];require(attrs(os.fstat(node))==observed,'DECLARED_INPUT_REBOUND')
   fd=os.open(parts[-1],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=parent)
   self.opened+=1
   try:
    require(attrs(os.fstat(fd))==observed and observed[6]<=81920-self.bytes,'DECLARED_INPUT_REBOUND_OR_BYTE_LIMIT');value=os.read(fd,min(limit+1,81920-self.bytes));self.bytes+=len(value)
    require(len(value)==observed[6] and attrs(os.fstat(fd))==attrs(os.fstat(node))==observed,'DECLARED_INPUT_CHANGED')
   finally:os.close(fd)
  finally:os.close(node);os.close(parent)
  self.files[key]=(value,limit);return value
 def secret(self,raw):
  p=self.path(raw);candidate='/run/secrets/'+str(p).lstrip('/');key=(True,candidate,False)
  value=self.read(candidate,4096) if self.observed[key]['kind']=='REGULAR' else self.read(str(p),4096)
  return trim(value) if value is not None else b''



def source_credentials(container, report):
    env = dict(e.split("=", 1) for e in container["Config"]["Env"] if "=" in e)
    binding = InputBinding(container["State"]["Pid"])
    try:
        binding.preflight(env)
        values, meta = binding.resolve(env)
        report["sourceCredentialSource"] = "EXISTING_MINIO_SERVER_CONFIGURATION"
        report["sourceCredentialOrigins"] = meta["selectedSources"]
        report["sourceRootAccessDeclaration"] = binding.root_access or "NOT_DECLARED"
        need(not binding.root_access or binding.root_access.lower() in ("on", "true", "1"),
             "MINIO_ROOT_API_NOT_ENABLED_BY_DECLARATION")
        need(re.fullmatch("[a-z0-9-]{1,63}", binding.region), "SOURCE_REGION_INVALID")
        report["sourceRegion"] = binding.region
        return tuple(v.decode() for v in values), binding.region
    finally:
        binding.close()


def failure_reason(exc):
    return str(exc) if isinstance(exc, RuntimeError) and re.fullmatch("[A-Z0-9_]{1,120}", str(exc)) else type(exc).__name__


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path, maximum=1048576):
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    need(len(value) <= maximum, 'INPUT_TOO_LARGE')
    return value


def inspect(ref):
    p = subprocess.run((*DOCKER, 'container', 'inspect', ref), capture_output=True, timeout=15)
    need(p.returncode == 0 and len(p.stdout) <= 1048576, 'DOCKER_INSPECT_FAILED')
    rows = json.loads(p.stdout)
    need(len(rows) == 1, 'CONTAINER_NOT_UNIQUE')
    return rows[0]


def signed(method, path, host, auth, body, extra, stamp, region="us-east-1"):
    # Same SigV4 canonicalization used by the successful retained-data rehearsal.
    uri, _, query = path.partition('?')
    params = sorted((quote(k, safe='-_.~'), quote(v, safe='-_.~'))
                    for k, v in parse_qsl(query, keep_blank_values=True))
    query = '&'.join(f'{k}={v}' for k, v in params)
    payload = digest(body)
    headers = dict(extra, host=host)
    headers.update({'x-amz-content-sha256': payload, 'x-amz-date': stamp})
    names = sorted(headers)
    selected = ';'.join(names)
    lines = ''.join(f'{k}:{" ".join(headers[k].split())}\n' for k in names)
    canonical = '\n'.join((method, uri, query, lines, selected, payload))
    key, secret = auth
    day = stamp[:8]
    scope = f'{day}/{region}/s3/aws4_request'
    message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope, digest(canonical.encode())))
    signing = ('AWS4' + secret).encode()
    for component in (day, region, 's3', 'aws4_request'):
        signing = hmac.digest(signing, component.encode(), 'sha256')
    signature = hmac.digest(signing, message.encode(), 'sha256').hex()
    headers['authorization'] = f'AWS4-HMAC-SHA256 Credential={key}/{scope},SignedHeaders={selected},Signature={signature}'
    return uri + ('?' + query if query else ''), headers


class S3:
    def __init__(self, address, hostname, port, auth, ca=None, region="us-east-1", read_only=False):
        self.address, self.hostname, self.port, self.auth = address, hostname, port, auth
        self.context = ssl.create_default_context(cafile=str(ca)) if ca else None
        self.calls = 0
        self.region, self.read_only = region, read_only

    def request(self, method, path, body=b'', extra=None, maximum=10*1024*1024):
        need(time.monotonic() < DEADLINE, 'COPY_DEADLINE')
        need(not self.read_only or (method == 'GET' and path.startswith('/' + BUCKET)
             and path[len(BUCKET)+1:len(BUCKET)+2] in ('/', '?')), 'SOURCE_READ_ONLY_BUCKET_SCOPE')
        uri, headers = signed(method, path, f'{self.hostname}:{self.port}', self.auth, body, extra or {},
                              datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'), self.region)
        outer = self
        class Connection(http.client.HTTPConnection):
            def connect(self):
                raw = socket.create_connection((outer.address, outer.port), timeout=self.timeout)
                try:
                    self.sock = outer.context.wrap_socket(raw, server_hostname=outer.hostname) if outer.context else raw
                except BaseException:
                    raw.close()
                    raise
        connection = Connection(self.hostname, self.port, timeout=min(15, max(1, DEADLINE-time.monotonic())))
        self.calls += 1
        try:
            connection.request(method, uri, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(maximum + 1)
            need(len(data) <= maximum, 'S3_RESPONSE_TOO_LARGE')
            return response.status, data, response.getheaders()
        finally:
            connection.close()


def provider_code(body):
    match = re.search(rb'<Code>([A-Za-z][A-Za-z0-9_-]{0,79})</Code>', body[:65536])
    return match.group(1).decode() if match else None


def success(response, report):
    status, body, headers = response
    if status != 200:
        report.update(lastS3HttpStatus=status, lastS3Code=provider_code(body))
        raise RuntimeError('S3_REQUEST_NOT_SUCCESSFUL')
    return body, headers


def listing(client, report):
    raw, _ = success(client.request('GET', f'/{BUCKET}?list-type=2&max-keys=1000', maximum=1048576), report)
    root = ET.fromstring(raw)
    need(root.tag.rsplit('}', 1)[-1] == 'ListBucketResult' and root.findtext('{*}Name') == BUCKET,
         'SOURCE_LIST_SHAPE')
    need(root.findtext('{*}IsTruncated') == 'false', 'SOURCE_LIST_TRUNCATED')
    rows = []
    for item in root.findall('{*}Contents'):
        row = {name: item.findtext('{*}' + name) for name in ('Key', 'ETag', 'LastModified', 'Size')}
        row['Size'] = int(row['Size'])
        need(row['Key'] and row['Key'].startswith('managed-files/') and len(row['Key']) <= 1024
             and row['ETag'] and row['LastModified'] and 0 <= row['Size'] <= 10*1024*1024, 'SOURCE_OBJECT_SCOPE')
        rows.append(row)
    need(0 < len(rows) <= 512 and len({r['Key'] for r in rows}) == len(rows)
         and sum(r['Size'] for r in rows) <= 64*1024*1024, 'SOURCE_LIST_SIZE')
    return sorted(rows, key=lambda r: r['Key'])


def metadata(headers):
    selected = {}
    for k, value in headers:
        name = k.lower()
        need(not name.startswith(('x-amz-server-side-encryption', 'x-amz-object-lock'))
             and name != 'x-amz-website-redirect-location', 'SPECIAL_METADATA_REQUIRES_REVIEW')
        if name in METADATA or name.startswith('x-amz-meta-'):
            need(name not in selected and re.fullmatch('[a-z0-9_-]+', name)
                 and all(32 <= ord(c) < 127 for c in value), 'METADATA_REQUIRES_REVIEW')
            selected[name] = value
    return selected


def align(source, destination, rows, report, journal):
    manifest = []
    for ordinal, row in enumerate(rows, 1):
        report['currentObjectOrdinal'] = ordinal
        path = '/' + BUCKET + '/' + quote(row['Key'], safe='/-_.~')
        report['phase'] = 'READ_SOURCE_OBJECT'
        body, headers = success(source.request('GET', path, extra={'if-match': row['ETag']}), report)
        need(len(body) == row['Size'] and dict((k.lower(), v) for k, v in headers).get('etag') == row['ETag'],
             'SOURCE_OBJECT_CHANGED')
        source_meta = metadata(headers)
        body_hash = digest(body)
        report['phase'] = 'COMPARE_DESTINATION_OBJECT'
        target = destination.request('GET', path)
        if target[0] == 200:
            need(digest(target[1]) == body_hash and len(target[1]) == row['Size']
                 and metadata(target[2]) == source_meta, 'EXISTING_TARGET_OBJECT_DIFFERS')
            report['objectsAlreadyMatched'] += 1
        else:
            report.update(lastS3HttpStatus=target[0], lastS3Code=provider_code(target[1]))
            need(target[0] == 404 and provider_code(target[1]) == 'NoSuchKey', 'DESTINATION_READ_NOT_ABSENT')
            # The application target identity has no tag-administration privilege.
            # Existing historical objects are not rewritten; tagged new objects require a deliberate copy path.
            report['phase'] = 'CHECK_NEW_OBJECT_TAGS'
            tag_body, _ = success(source.request('GET', path + '?tagging', maximum=16384), report)
            tags = ET.fromstring(tag_body)
            need(tags.tag.rsplit('}', 1)[-1] == 'Tagging' and not tags.findall('{*}TagSet/{*}Tag'),
                 'NEW_TAGGED_OBJECT_REQUIRES_COPY_PATH')
            intent = {'key': row['Key'], 'sha256': body_hash, 'size': row['Size'], 'state': 'PUT_INTENT'}
            journal.write(json.dumps(intent, sort_keys=True) + '\n'); journal.flush(); os.fsync(journal.fileno())
            report['phase'] = 'PUT_MISSING_OBJECT'
            report['putAttempts'] += 1
            success(destination.request('PUT', path, body, dict(source_meta, **{'if-none-match': '*'})), report)
            actual, actual_headers = success(destination.request('GET', path), report)
            need(len(actual) == row['Size'] and digest(actual) == body_hash and metadata(actual_headers) == source_meta,
                 'COPIED_OBJECT_READBACK_DIFFERS')
            report['objectsCopiedAndVerified'] += 1
            journal.write(json.dumps(dict(intent, state='VERIFIED'), sort_keys=True) + '\n'); journal.flush()
            report.pop('lastS3HttpStatus', None)
            report.pop('lastS3Code', None)
        manifest.append({'key': row['Key'], 'size': row['Size'], 'sha256': body_hash, 'metadata': source_meta})
    return manifest


def generation(doc):
    return doc['Id'], doc['Image'], doc['State']['StartedAt'], doc['State']['Pid']


def run(report):
    global DEADLINE
    DEADLINE = time.monotonic() + 600
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    raw = read(PLAN)
    need(digest(raw) == PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    roles = json.loads(raw)['roles']
    app, minio, sea = inspect(roles['onboarding']['containerId']), inspect(roles['minio']['containerId']), inspect('ouf-seaweedfs-stage')
    need(app['State']['Running'] and app['Image'] == APP_IMAGE and minio['State']['Running']
         and minio['Image'] == roles['minio']['nativeImage']
         and sea['State']['Running'] and sea['Image'] == SEA_IMAGE, 'CURRENT_RUNTIME_CHANGED')
    before = [generation(d) for d in (app, minio, sea)]
    env = dict(e.split('=', 1) for e in app['Config']['Env'] if '=' in e)
    need(env['OUF_ONBOARDING_STAGING_ENDPOINT'] == 'http://ouf-minio:9000'
         and env['OUF_ONBOARDING_STAGING_BUCKET'] == BUCKET, 'CURRENT_SOURCE_BINDING_CHANGED')
    report['phase'] = 'RESOLVE_SOURCE_MAINTENANCE_IDENTITY'
    source_auth, source_region = source_credentials(minio, report)
    client = BINDINGS / 'clients/onboarding'
    target_env = json.loads(read(client / 'binding.private.json'))['environment']
    need(target_env['OUF_ONBOARDING_STAGING_ENDPOINT'] == 'https://ouf-seaweedfs-stage:9002'
         and target_env['OUF_ONBOARDING_STAGING_BUCKET'] == BUCKET, 'TARGET_BINDING_CHANGED')
    target_auth = tuple(read(client / name, 4096).decode().strip() for name in ('access-key', 'secret-key'))
    need(all(v and not any(c in v for c in '\r\n\x00') for v in (*source_auth, *target_auth)), 'CREDENTIAL_FILE_INVALID')
    source = S3(minio['NetworkSettings']['Networks']['ouf-backend']['IPAddress'], 'ouf-minio', 9000, source_auth,
                region=source_region, read_only=True)
    destination = S3(sea['NetworkSettings']['Networks']['ouf-seaweedfs-private']['IPAddress'], 'ouf-seaweedfs-stage', 9002,
                     target_auth, BINDINGS / 'config/tls/ca.pem')
    work = Path(tempfile.mkdtemp(prefix='onboarding-current-copy-', dir=ROOT))
    os.chmod(work, 0o700)
    report['privateEvidenceDirectory'] = str(work)
    try:
        report['phase'] = 'LIST_CURRENT_SOURCE'
        rows = listing(source, report)
        report.update(sourceObjects=len(rows), sourceBytes=sum(r['Size'] for r in rows))
        (work / 'source-before.json').write_text(json.dumps(rows, sort_keys=True) + '\n')
        with (work / 'copy-journal.jsonl').open('x') as journal:
            manifest = align(source, destination, rows, report, journal)
        report['phase'] = 'VERIFY_SOURCE_SNAPSHOT'
        need(listing(source, report) == rows, 'SOURCE_CHANGED_DURING_COPY')
        need([generation(inspect(d['Id'])) for d in (app, minio, sea)] == before, 'RUNTIME_CHANGED_DURING_COPY')
        payload = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
        (work / 'objects-verified.private.json').write_bytes(payload)
        report.update(status='CURRENT_ONBOARDING_OBJECTS_ALIGNED', phase='COMPLETE',
                      sourceSnapshotUnchanged=True, manifestSha256=digest(payload),
                      sourceStateMustBeRecheckedAtEndpointSwitch=True)
    finally:
        report.update(sourceS3Requests=source.calls, destinationS3Requests=destination.calls)


if __name__ == '__main__':
    os.umask(0o077)
    report = {'schema': 'ouf.current-onboarding-object-alignment.v1', 'status': 'INCOMPLETE',
              'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'objectsAlreadyMatched': 0, 'objectsCopiedAndVerified': 0, 'putAttempts': 0,
              'sourceObjectsModified': False, 'existingTargetObjectsOverwritten': False,
              'applicationBindingsChanged': False, 'databaseRequests': 0, 'serviceStops': 0,
              'credentialValuesEmitted': False, 'targetTagsFreshlyCompared': False,
              'sourceS3Requests': 0, 'destinationS3Requests': 0,
              'applicationPermissionsChanged': False, 'sourceRequestsReadOnly': True}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'INCOMPLETE'
        report['reason'] = failure_reason(exc)
    report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'privateEvidenceDirectory' in report:
        (Path(report['privateEvidenceDirectory']) / 'result.json').write_text(json.dumps(report, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'CURRENT_ONBOARDING_OBJECTS_ALIGNED' else 1)
