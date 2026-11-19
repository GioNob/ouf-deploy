import base64,hashlib,json,pathlib,shutil,subprocess,zipfile
root=pathlib.Path('native-package');root.mkdir();(root/'lib').mkdir();(root/'migrations').mkdir();(root/'classes').mkdir()
jars=list(pathlib.Path('semantic-source/target').glob('semantic-registry-*.jar'));assert len(jars)==1
shutil.copyfile(jars[0],root/'application.jar')
manifest=json.loads(pathlib.Path('releases/semantic-migration-source-20261108.json').read_text())
with zipfile.ZipFile(root/'application.jar') as z:
 for n in z.namelist():
  if n.startswith('BOOT-INF/lib/') and n.endswith('.jar'):(root/'lib'/pathlib.Path(n).name).write_bytes(z.read(n))
  if n.startswith('BOOT-INF/classes/db/migration/') and n.endswith('.sql'):
   leaf=pathlib.Path(n).name;assert hashlib.sha256(z.read(n)).hexdigest()==manifest['files'][leaf];(root/'migrations'/leaf).write_bytes(z.read(n))
source=pathlib.Path('tools/semantic_upgrade_20261108/SemanticMigration.java')
subprocess.run(['javac','--release','21','-cp',str(root/'lib/*'),'-d',str(root/'classes'),str(source),'tools/semantic_upgrade_20261108/NativeBaseline.java'],check=True)
raw=(root/'classes/SemanticMigration.class').read_bytes()
bundle={'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'javaRelease':21,'classSha256':hashlib.sha256(raw).hexdigest(),'classBase64':base64.b64encode(raw).decode()}
(root/'helper.json').write_text(json.dumps(bundle,sort_keys=True)+'\n')
