import hashlib, importlib.util, json, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('facts', ROOT/'scripts/read-semantic-token-static-facts.py')
facts = importlib.util.module_from_spec(spec); spec.loader.exec_module(facts)

class PublicFacts(unittest.TestCase):
    def test_embedded_observer_exact_qualified_bytes(self):
        self.assertEqual(hashlib.sha256(facts.OBSERVER_SOURCE).hexdigest(), facts.OBSERVER_HASH)
        self.assertEqual(facts.OBSERVER_SOURCE, (ROOT/'scripts/observe-semantic-token-source.py').read_bytes())

    def test_only_names_and_operational_literals_exposed_no_execution(self):
        raw = b'''password="DO_NOT_PRINT_SECRET"
endpoint="https://DO_NOT_PRINT_PRIVATE_HOST/token"
client=10001
key=required("OUF_TOKEN_ENDPOINT")
scope=os.environ.get("OUF_TOKEN_SCOPE", "DO_NOT_PRINT_SCOPE_VALUE")
directory.mkdir(mode=0o750, parents=False, exist_ok=True)
os.fchmod(stream.fileno(),0o440)
os.fchown(stream.fileno(),0,gid)
response.read(65537)
opener.open(request,timeout=15)
if len(token)>65536: raise ValueError("DO_NOT_PRINT")
if expires<60: raise ValueError("DO_NOT_PRINT")
raise RuntimeError("DO_NOT_EXECUTE")
'''
        result = facts.public_facts(raw); text = json.dumps(result)
        self.assertEqual(result['environmentKeyNames'], ['OUF_TOKEN_ENDPOINT','OUF_TOKEN_SCOPE'])
        self.assertIn('0440', text); self.assertIn('0750', text)
        self.assertIn('timeoutSeconds', text); self.assertIn('65537', text)
        for private in ('DO_NOT_PRINT','10001','https://','DO_NOT_EXECUTE'):
            self.assertNotIn(private, text)

    def test_nonliteral_or_out_of_profile_values_not_disclosed(self):
        result = facts.public_facts(b'os.fchmod(fd, secret_mode)\nopener.open(r,timeout=99999)\nresponse.read(-1)\npassword=12345\nrequired("private-value")\n')
        self.assertEqual(result['environmentKeyNames'], [])
        self.assertEqual(result['operationalLiteralSettings'], [])
        self.assertEqual(result['validationLiteralComparisons'], [])

if __name__ == '__main__': unittest.main()
