"""Import-order and unchanged business-authorization boundaries before login."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_chatbot_cohort_containers as bootstrap
from tools.chatbot_file_cohort import postgrant_preparation as prep
from tools.chatbot_file_cohort.plan import PlanDenied


class PostGrantPreparation(unittest.TestCase):
    def test_import_does_not_load_consumers_before_authenticated_owner_helpers(self):
        paths=list(sys.path)
        source="""import sys,json
sys.path[:0]=json.loads(sys.argv[1])
for name in list(sys.modules):
    if name.startswith(('tools.chatbot_file_cohort','qualified_owner_')):sys.modules.pop(name,None)
import tools.chatbot_file_cohort.postgrant_preparation
assert 'tools.chatbot_file_cohort.assemble' not in sys.modules
assert 'tools.chatbot_file_cohort.delivery' not in sys.modules
assert 'qualified_owner_authorization_lifecycle' not in sys.modules
"""
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',source,json.dumps(paths)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_unqualified_helper_is_rejected_before_staging_or_execution(self):
        bundle={'sources':{'qualified_owner_authorization_lifecycle':base64.b64encode(b'raise Exception("unqualified")').decode()}}
        with (patch.object(prep,'protected_directory',side_effect=AssertionError('MUST_NOT_STAGE')),
             patch.object(prep,'qualified_module',side_effect=AssertionError('MUST_NOT_EXECUTE')),
             self.assertRaisesRegex(PlanDenied,'HELPER_DRIFT')):
            prep.qualified_helpers(Path('/unused'),bundle)

    def test_only_fresh_human_session_binding_may_change(self):
        original={'sessionBinding':{'old':'expired'},'addedDescriptors':[],'roleProposal':None,
            'scopeBindings':[],'targetRoles':{'roles':['retained']},'scopeCreations':[]}
        current=copy.deepcopy(original);current['sessionBinding']={'new':'current'}
        prep.validate_authorization_rebind(original,current)
        for field,value in (('targetRoles',{'roles':['changed']}),('addedDescriptors',[{}]),
                ('roleProposal',{'new':'proposal'}),('scopeBindings',[{}]),('scopeCreations',[{}])):
            changed=copy.deepcopy(current);changed[field]=value
            with self.subTest(field=field),self.assertRaises(PlanDenied):prep.validate_authorization_rebind(original,changed)


if __name__=='__main__':unittest.main()
