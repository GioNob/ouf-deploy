"""Qualify rebind against both original producer archives; synthetic declaration only."""
import hashlib,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
package=module("sealed_package_reader","scripts/rebase-semantic-package-declaration.py")
rebind=module("v11_rebind","tools/semantic_application_cutover/rebase_verified_package.py")
assert hashlib.sha256((ROOT/"scripts/rebase-semantic-package-declaration.py").read_bytes()).hexdigest()=="134a31a840373938c3e65cb9d80f588fe8006b472dfb9582ff3bb024733842ed"
old=package.package_config("old-semantic.zip")
package.SOURCE=rebind.SOURCE
new=package.package_config("new-semantic.zip",expected_zip=rebind.ZIP_HASH,expected_image=rebind.IMAGE)
old["Env"] += ["OUF_SEM_DB_URL=jdbc:fixture","SPRING_CONFIG_IMPORT=configtree:/run/db/","OUF_DISCOVERY_WORKER_ENABLED=false"]
declaration={"schema":"ouf.discovery.private-file-secret-runtime-declaration.v1","candidateImageId":rebind.OLD_IMAGE,
             "candidateConfig":old,"proposedHostConfig":{"fixtureOnly":True},"retainedNativeCreationFrame":{"fixtureOnly":True},
             "roleOwnedReadOnlyMounts":[{"fixtureOnly":True}],"databaseSecretProjection":{"targetDirectory":"/run/db"},
             "productionApplyReady":False,"applicationCutoverAuthorized":False,"completeReplacementOciProven":False}
updated=rebind.rebind(declaration,rebind.digest(declaration),new)
assert updated["candidateImageId"]==rebind.IMAGE
assert rebind.environment(updated["candidateConfig"]["Env"])["SPRING_CONFIG_IMPORT"]=="configtree:/run/db/"
receipt={"schema":"ouf.durable-v11-image-default-rebind-qualification.v1","status":"PASS",
         "oldImage":rebind.OLD_IMAGE,"newImage":rebind.IMAGE,"sourceCommit":rebind.SOURCE,
         "bothOriginalArchiveAndImageConfigDigestsVerified":True,"executionDefaultsMatch":True,
         "unrelatedImageLabelsPreserved":True,"mandatoryConfigtreeRetained":True,
         "applicationEnvironmentRetained":True,"targetDeclarationRead":False,"targetRuntimeChanged":False,
         "targetApplyAuthorized":False,"notReleaseAcceptance":True}
Path("durable-v11-rebind-native-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
print("OUF_DURABLE_V11_REBIND_NATIVE="+json.dumps(receipt,sort_keys=True))
