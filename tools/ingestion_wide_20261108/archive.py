"""Archive a newly built exact source; do not describe it as the old CI image."""
import hashlib,json,pathlib,subprocess,zipfile,zlib
SOURCE='c85d9fd3be215e518dc6e7d075797720b5afbd91'
tag='ouf-ingestion:'+SOURCE
def cmd(*a):return subprocess.check_output(a,text=True).strip()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
root=pathlib.Path('candidate');out=pathlib.Path('ingestion-wide-artifact');out.mkdir()
assert cmd('git','-C',str(root),'rev-parse','HEAD')==SOURCE
image=json.loads(cmd('docker','image','inspect',tag))[0]
assert image['Config']['User']=='10002:10002' and image['Config']['Entrypoint']==['java','-jar','/app/app.jar']
expected=json.loads(pathlib.Path('scripts/ingestion-wide-source-resources-20261108.json').read_text())
jar=root/'target/candidate.jar'
with zipfile.ZipFile(jar)as z:
 names=z.namelist();assert len(names)==len(set(names));migrations=[]
 for path in sorted(n for n in names if n.startswith('BOOT-INF/classes/db/migration/') and n.endswith('.sql')):
  raw=z.read(path);source=root/'src/main/resources'/path.removeprefix('BOOT-INF/classes/');assert source.read_bytes()==raw
  crc=0
  for line in raw.decode('utf-8-sig').splitlines():crc=zlib.crc32(line.encode(),crc)
  migrations.append({'name':source.name,'sha256':hashlib.sha256(raw).hexdigest(),'flywayStyleCrc32Utf8':crc if crc<2**31 else crc-2**32})
 assert migrations==[{k:x[k]for k in ('name','sha256','flywayStyleCrc32Utf8')}for x in expected['migrations']]
 yaml=z.read('BOOT-INF/classes/application.yml');assert yaml==(root/'src/main/resources/application.yml').read_bytes()
 classes={n:hashlib.sha256(z.read(n)).hexdigest()for n in names if n.startswith('BOOT-INF/classes/it/comune/trieste/ouf/ingestion/') and
          n.rsplit('/',1)[-1]in ('ManagedTabularAdapter.class','ManagedTabularAdapter$CsvCursor.class','ExecutionRuntimeConfiguration.class','ExecutionGatewayClient.class','IngestionReadinessHealthIndicator.class')}
 assert len(classes)==5 and len(migrations)==18
archive=out/'image.tar.gz'
with archive.open('wb')as dest:
 save=subprocess.Popen(['docker','save',tag],stdout=subprocess.PIPE)
 compress=subprocess.run(['gzip','-n'],stdin=save.stdout,stdout=dest,check=True);save.stdout.close();assert save.wait()==0
record={'schema':'ouf.ingestion-wide-archived-image.v1','sourceCommit':SOURCE,'sourceTree':cmd('git','-C',str(root),'rev-parse','HEAD^{tree}'),
 'newBuild':True,'historicalCiImageReused':False,'imageId':image['Id'],'imageConfig':image['Config'],
 'archiveSha256':sha(archive),'archiveBytes':archive.stat().st_size,'jarSha256':sha(jar),'jarBytes':jar.stat().st_size,
 'migrations':migrations,'applicationYamlSha256':hashlib.sha256(yaml).hexdigest(),'selectedClasses':classes,
 'sourceResourcesMatch':True,'targetChanged':False,'applicationStartupTested':False}
(out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'SHA256SUMS').write_text(''.join(sha(out/n)+'  '+n+'\n'for n in ('image.tar.gz','manifest.json')))
print(json.dumps({k:record[k]for k in ('sourceCommit','sourceTree','imageId','archiveSha256','archiveBytes','jarSha256','jarBytes','newBuild','applicationStartupTested')}))
