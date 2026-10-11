import copy,hashlib,importlib.util,json,types,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
r=module("verified_rebind","tools/semantic_application_cutover/rebase_verified_package.py")
entry=module("v11_entry","scripts/prepare-current-durable-v11-plan.py")

def fixture():
    config={"User":"10001:10001","Entrypoint":["java","-jar","/app/application.jar"],"Cmd":None,
            "WorkingDir":"/app","Env":["JAVA_HOME=/opt/java/openjdk","JAVA_VERSION=old","PATH=/bin"],
            "Labels":{"org.opencontainers.image.revision":"622614b0040cf11be2f6c7e3568733a488ca4ca8"}}
    old=copy.deepcopy(config);old["Env"] += ["OUF_SEM_DB_URL=jdbc:fixture","SPRING_CONFIG_IMPORT=configtree:/run/db/",
                                          "OUF_DISCOVERY_WORKER_ENABLED=false","PORT=8080"]
    declaration={"schema":"ouf.discovery.private-file-secret-runtime-declaration.v1",
                 "candidateImageId":r.OLD_IMAGE,"candidateConfig":old,"proposedHostConfig":{"Privileged":False},
                 "retainedNativeCreationFrame":{"opaque":"retained"},"roleOwnedReadOnlyMounts":[{"opaque":"retained"}],
                 "databaseSecretProjection":{"targetDirectory":"/run/db/","opaque":"retained"}}
    # Exact targetDirectory does not end with slash in real declaration.
    declaration["databaseSecretProjection"]["targetDirectory"]="/run/db"
    for key in ("productionApplyReady","applicationCutoverAuthorized","completeReplacementOciProven"):declaration[key]=False
    config["Labels"]["org.opencontainers.image.revision"]=r.SOURCE
    config["Env"][1]="JAVA_VERSION=new"
    return declaration,config

class RebindTests(unittest.TestCase):
    def test_new_runtime_preserves_application_host_inputs_and_old_document(self):
        d,c=fixture();before=copy.deepcopy(d)
        result=r.rebind(d,r.digest(d),c)
        self.assertEqual(d,before)
        self.assertEqual(result["candidateImageId"],r.IMAGE)
        env=r.environment(result["candidateConfig"]["Env"])
        self.assertEqual(env["JAVA_VERSION"],"new");self.assertEqual(env["OUF_SEM_DB_URL"],"jdbc:fixture")
        for key in ("proposedHostConfig","retainedNativeCreationFrame","roleOwnedReadOnlyMounts","databaseSecretProjection"):
            self.assertEqual(result[key],d[key])
        self.assertFalse(result["freshRuntimeCustodyProven"])
        self.assertFalse(result["newTransportClosureProven"])
        self.assertTrue(all(result[k] is False for k in ("productionApplyReady","applicationCutoverAuthorized","completeReplacementOciProven")))
    def test_stale_document_and_approved_or_wrong_image_denied(self):
        for change in ("hash","image","productionApplyReady","applicationCutoverAuthorized","completeReplacementOciProven"):
            with self.subTest(change=change):
                d,c=fixture();expected=r.digest(d)
                if change=="image":d["candidateImageId"]=r.IMAGE;expected=r.digest(d)
                elif change!="hash":d[change]=True;expected=r.digest(d)
                else:expected="0"*64
                with self.assertRaises(ValueError):r.rebind(d,expected,c)
    def test_all_execution_default_drifts_denied(self):
        for field in ("Entrypoint","Cmd","User","WorkingDir","ExposedPorts","Volumes","StopSignal","Healthcheck","Shell"):
            with self.subTest(field=field):
                d,c=fixture();c[field]="changed"
                with self.assertRaisesRegex(ValueError,"EXECUTION_DEFAULT"):r.rebind(d,r.digest(d),c)
    def test_source_label_and_unrelated_image_labels_denied(self):
        for field in ("org.opencontainers.image.revision","unreviewed.label"):
            d,c=fixture();c["Labels"][field]="changed"
            with self.assertRaises(ValueError):r.rebind(d,r.digest(d),c)
    def test_new_application_env_cannot_override_protected_input(self):
        d,c=fixture();c["Env"].append("OUF_SEM_DB_URL=other")
        with self.assertRaisesRegex(ValueError,"UNREVIEWED_IMAGE_ENVIRONMENT"):r.rebind(d,r.digest(d),c)
    def test_password_or_optional_missing_configtree_denied(self):
        for row in ("OUF_SEM_DB_PASSWORD=secret","SPRING_DATASOURCE_PASSWORD=secret"):
            d,c=fixture();d["candidateConfig"]["Env"].append(row)
            with self.assertRaisesRegex(ValueError,"FILE_SECRET_ONLY"):r.rebind(d,r.digest(d),c)
        d,c=fixture();d["candidateConfig"]["Env"]=[v for v in d["candidateConfig"]["Env"] if not v.startswith("SPRING_CONFIG_IMPORT=")]
        d["candidateConfig"]["Env"].append("SPRING_CONFIG_IMPORT=optional:configtree:/run/db/")
        with self.assertRaisesRegex(ValueError,"MANDATORY_RETAINED_CONFIGTREE"):r.rebind(d,r.digest(d),c)
    def test_duplicate_unknown_environment_and_wrong_java_home_denied(self):
        for row in ("PATH=duplicate","CUSTOM_UNREVIEWED=value","JAVA_HOME=/other"):
            d,c=fixture();c["Env"].append(row)
            with self.assertRaises(ValueError):r.rebind(d,r.digest(d),c)
    def test_complete_source_closure_checked_before_any_module_execution(self):
        # No source is executed if any one closure member mismatches, even if
        # another member contains an executable top-level effect.
        for target in entry.SOURCE_HASHES:
            sources={key:b"raise AssertionError('SOURCE_EXECUTED_BEFORE_COMPLETE_CLOSURE_CHECK')" for key in entry.SOURCE_HASHES}
            sources[target]=b"changed"
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError,"V11_PLAN_SOURCE_HASH_MISMATCH"):entry.modules(sources)
        with self.assertRaisesRegex(ValueError,"EXACT_V11_PLAN_SOURCE_CLOSURE"):entry.modules({})

if __name__=="__main__":unittest.main()
