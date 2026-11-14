import importlib.util,json,pathlib,tempfile,unittest
s=importlib.util.spec_from_file_location('reader',pathlib.Path(__file__).resolve().parents[2]/'scripts/read-semantic-discovery-key-binding-20261108.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class H:
 @staticmethod
 def environment(doc):return dict(x.split('=',1) for x in doc['Config']['Env'])
 @staticmethod
 def digest(value):return 'fixture-digest'

class KeyBindingTests(unittest.TestCase):
 def test_declarations_preserve_conflicts_without_secret_values(self):
  d={'Config':{'Env':['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE=/run/discovery.key','UNRELATED_SECRET=hidden-secret',
   'SPRING_APPLICATION_JSON={"ouf":{"semantic":{"discovery-delegation":{"key-file":"/other/key"}}}}'],
   'Cmd':['java','-Douf.semantic.discovery-delegation.workload=sample-workload']},'Mounts':[]}
  values=r.selected(d,H);out=r.project(d,values,['/run/discovery.key'])
  key='ouf.semantic.discovery-delegation.key-file'
  self.assertEqual(len(out[key]),2);self.assertTrue(out[key][0]['matchesFailedLogPath'])
  self.assertEqual(out[key][0]['mount']['status'],'NO_DECLARED_MOUNT')
  self.assertNotIn('hidden-secret',json.dumps(out));self.assertNotIn('sample-workload',json.dumps(out))
 def test_host_metadata_no_content_or_symlink_traversal(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);(root/'key').write_text('hidden-secret');(root/'link').symlink_to(root/'key')
   d={'Mounts':[{'Destination':'/run/keys','Source':t,'Type':'bind','RW':False}]}
   a=r.mount_summary(d,'/run/keys/key');b=r.mount_summary(d,'/run/keys/absent');c=r.mount_summary(d,'/run/keys/link')
   self.assertTrue(a['hostSource']['regular']);self.assertTrue(a['readOnly'])
   self.assertEqual(b['hostSource']['status'],'HOST_PATH_MISSING');self.assertTrue(c['hostSource']['symlink'])
   self.assertNotIn(t,json.dumps(a));self.assertNotIn('hidden-secret',json.dumps(a))
   self.assertEqual(r.mount_summary(d,'/run/keys/../key')['status'],'NO_NORMALIZED_ABSOLUTE_PATH')
 def test_current_route_signer_is_named_without_key_bytes(self):
  source='return function(conf, ctx)\n'+ '\n'.join('local '+k+' = '+json.dumps(v) for k,v in {
   'DELEGATION_KEY_ENV':'MCP_KEY','ISSUER':'fixture-issuer','AUDIENCE':'fixture-audience',
   'MCP_WORKLOAD':'fixture-workload','OWNER_KEY_ENV':'SEMANTIC_KEY'}.items())+'\nend'
  rows=[{'uri':p,'plugins':{'serverless-post-function':{'functions':[source]}}} for p in r.PATHS]
  values={k:[] for k in r.FIELDS};values['ouf.iam.issuer']=[{'value':'fixture-issuer'}]
  secret='a'*64
  out=r.gateway_summary(rows,{'SEMANTIC_KEY':secret,'SOME_DISCOVERY_KEY':'b'*64},values,H)
  self.assertTrue(out['allSelectedRoutesUseSameOwnerKeyEnvironment'])
  entry=out['routes'][r.PATHS[1]];self.assertTrue(entry['ownerKeyFormatValid'])
  self.assertEqual(entry['declaredSemanticMatches']['ouf.iam.issuer'],[True])
  self.assertNotIn(secret,json.dumps(out));self.assertNotIn('b'*64,json.dumps(out))
  self.assertEqual(out['otherDiscoveryKeyEnvironmentNames'],['SOME_DISCOVERY_KEY'])
if __name__=='__main__':unittest.main()
