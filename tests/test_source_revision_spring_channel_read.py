import importlib.util,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('channel_read',ROOT/'scripts/read-source-revision-spring-channels.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

class Redaction(unittest.TestCase):
 def test_no_values_or_credentials_in_output(self):
  result=reader.channels(['PASSWORD=PRIVATE_CANARY','SPRING_APPLICATION_JSON={"password":"PRIVATE_CANARY"}',
   'JAVA_TOOL_OPTIONS=-Dpassword=PRIVATE_CANARY','SPRING_FLYWAY_ENABLED=true'])
  self.assertNotIn('PRIVATE_CANARY',json.dumps(result))
  self.assertEqual(result[-1],{'name':'SPRING_FLYWAY_ENABLED','classification':'EXPLICIT_TRUE'})
 def test_empty_java_is_distinguished_from_empty_spring(self):
  self.assertEqual(reader.classify('JAVA_TOOL_OPTIONS',''),'EMPTY_JVM_NO_OPTIONS')
  self.assertEqual(reader.classify('SPRING_FLYWAY_ENABLED',''),'EMPTY_SPRING_CHANNEL_REQUIRES_REVIEW')
 def test_closed_memory_option_grammar(self):
  self.assertEqual(reader.jvm('-Xms256m -Xmx1G -XX:MaxRAMPercentage=75.0'),'MEMORY_ONLY_JVM')
  for value in ('-Dspring.flyway.enabled=false','@private-options','-Xmx1G -javaagent:agent.jar','"bad'):
   self.assertEqual(reader.jvm(value),'UNCLASSIFIED')
 def test_duplicate_and_malformed_entries_are_rejected(self):
  for value in (['A=1','A=2'],['missing-equals'],['SPRING_SECRET\nCANARY=value']):
   with self.assertRaises(AssertionError):reader.channels(value)
 def test_json_property_shapes_do_not_include_values(self):
  rows=reader.json_properties('{"ouf":{"onboarding":{"udp-identity":{"gateway-url":"PRIVATE_CANARY"}}}}')
  self.assertEqual(rows,[{'property':'oufonboardingudpidentitygatewayurl','type':'str'}])
  self.assertNotIn('PRIVATE_CANARY',json.dumps(rows))
 def test_json_duplicates_and_relaxed_aliases_are_rejected(self):
  for raw in ('{"ouf.a":1,"ouf.a":2}','{"ouf.a":1,"ouf-a":2}'):
   with self.assertRaises(AssertionError):reader.json_properties(raw)

if __name__=='__main__':unittest.main()
