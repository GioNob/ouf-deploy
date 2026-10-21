import copy,unittest
import read_candidate_trust_bytes as subject
class TrustComparison(unittest.TestCase):
    def receipt(self):
        return {"schema":"ouf.discovery.java-trust-preparation.v1","status":"CANDIDATE_PUBLIC_JAVA_TRUST_PREPARED_NOT_MOUNTED",
          "runtimeInputManifestHash":subject.MANIFEST,"baselineHash":subject.BASELINE,"providerCaHash":subject.CA,
          "truststoreHash":subject.STORE,"baselineCertificateCount":118,"mergedCertificateCount":119,
          "publicRootsPreserved":True,"containsPrivateKeys":False,"storeType":"PKCS12","mounted":False,
          "applicationCutoverAuthorized":False,"semanticUid":10001}
    def test_same_baseline_allows_byte_comparison_but_no_authority_inheritance(self):
        result=subject.qualify(self.receipt(),subject.BASELINE,subject.CA,subject.STORE)
        self.assertEqual(result["candidateImageId"],subject.IMAGE)
        self.assertFalse(result["priorInstallationAuthorityReused"])
        self.assertFalse(result["truststoreRegenerated"])
    def test_changed_baseline_provider_or_store_denied(self):
        values=[subject.BASELINE,subject.CA,subject.STORE]
        for index in range(3):
            changed=values.copy();changed[index]="0"*64
            with self.subTest(index=index),self.assertRaises(ValueError):subject.qualify(self.receipt(),*changed)
    def test_private_key_mounted_wrong_role_or_count_denied(self):
        for key,value in (("containsPrivateKeys",True),("mounted",True),("semanticUid",0),("mergedCertificateCount",118),("publicRootsPreserved",False),("applicationCutoverAuthorized",True)):
            row=self.receipt();row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):subject.qualify(row,subject.BASELINE,subject.CA,subject.STORE)
    def test_boolean_coercion_does_not_pass_scope_gate(self):
        row=self.receipt();row["semanticUid"]=True
        with self.assertRaises(ValueError):subject.qualify(row,subject.BASELINE,subject.CA,subject.STORE)
if __name__=="__main__":unittest.main()
