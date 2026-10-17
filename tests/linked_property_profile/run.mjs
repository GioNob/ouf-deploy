import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {verify} from './linked-property-profile.test.mjs';
import {POLICY} from '../../tools/linked_property_profile/linked-property-profile.mjs';
const result=verify();
const proposal=JSON.parse(await readFile(new URL('../../releases/linked-property-profile-proposal-20261017.json',import.meta.url)));
assert.equal(proposal.properties.length,20);
assert.equal(new Set(proposal.properties.map(p=>p.propertyIri)).size,20);
for(const p of proposal.properties){
  assert.equal(p.reconciliation.policyRef,POLICY);assert.equal(p.reconciliation.cardinality,'SINGLE');
  assert.equal(p.reconciliation.normalizerRef,'EXACT_TYPED');assert.equal(p.reconciliation.validity,'SOURCE_INTERVAL');
  assert.equal(p.expectedCurrent.datatype,'http://www.w3.org/2001/XMLSchema#string');
  assert.equal(p.expectedCurrent.accessLabel,'RESTRICTED');assert.equal(p.reconciliation.deletionField,undefined);
  assert.equal(p.reconciliation.revisionField,undefined);
}
console.log(JSON.stringify({...result,fixturePropertyCount:20,nativeProfilePublished:false,readyForActivation:false}));
