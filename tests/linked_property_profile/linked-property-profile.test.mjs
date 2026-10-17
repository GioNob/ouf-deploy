function clone(v) { return JSON.parse(JSON.stringify(v)); }
import assert from 'node:assert/strict';
import {prepare,POLICY} from '../../tools/linked_property_profile/linked-property-profile.mjs';

function fixture(mode='MANAGED', kind='INTERNAL_MANAGED') {
  const property={propertyIri:'urn:asset:name',sourceField:'urn:asset:name',datatype:'http://www.w3.org/2001/XMLSchema#string',accessLabel:'RESTRICTED',authorityOrder:['registry']};
  const snapshot={sourceId:'registry',onboardingVersionId:'version-1',configurationHash:'sha256:'+'a'.repeat(64),configuration:{
    bundle:{source:{sourceId:'registry',sourceKind:kind,acquisitionMode:mode},bundleVersion:'1'},
    semanticMapping:{mappingId:'mapping-1',propertyMappings:[{targetPropertyIri:'urn:asset:name'}]},
    syncProfile:{bootstrap:'FULL_SNAPSHOT',incremental:'NONE'},sourceObjectIdentityPolicy:{sourceFields:['id']},
    changeRepresentationProfile:{mode:'FULL_SNAPSHOT'},dataAccessPolicies:[{target:'urn:asset:name',label:'RESTRICTED'}],
    temporalMapping:{mode:'OBSERVATION_ONLY'},unrelated:{futureOption:['unchanged']},
    extractionProfile:{runtime:{execution:{adapterId:'fixture'},udp:{resolution:{policyRef:'identity-1'},
      materialization:{policyRef:'authority-1',checkpointInterval:7,bitemporalProperties:[],properties:[property]}}}}}};
  const proposal={schema:'ouf.linked-property-profile-proposal.v1',expected:{sourceId:snapshot.sourceId,onboardingVersionId:snapshot.onboardingVersionId,configurationHash:snapshot.configurationHash},properties:[{
    propertyIri:property.propertyIri,expectedCurrent:clone(property),
    reconciliation:{policyRef:POLICY,cardinality:'SINGLE',normalizerRef:'EXACT_TYPED',normalizerVersion:1,validity:'SOURCE_INTERVAL'},
    basis:{cardinality:'approved conservative policy',normalization:'exact typed',validity:'existing source intervals only',sourceAuthority:'retain explicit order',deletion:'no deletion'}}]};
  return {snapshot,proposal};
}
export function verify() {
  let passed=0;const names=[];const check=(name,fn)=>{fn();passed++;names.push(name);};
  check('configuration preserved; no implicit defaults, mutation or publication',()=>{
    const {snapshot,proposal}=fixture();const before=clone(snapshot);const out=prepare(snapshot,proposal);
    assert.deepEqual(snapshot,before);assert.equal(out.changes.length,1);assert.equal(out.readyForActivation,false);
    assert.equal(out.configuration.extractionProfile.runtime.udp.materialization.policyRef,'authority-1');
    assert.equal(out.configuration.extractionProfile.runtime.udp.materialization.checkpointInterval,7);
    assert.deepEqual(out.configuration.unrelated,before.configuration.unrelated);
    assert.deepEqual(out.configuration.temporalMapping,before.configuration.temporalMapping);
    assert.equal(out.scheduling.oneShotDerivedFromManaged,true);assert.equal(out.scheduling.newPublicationCanScheduleAcquisition,true);
  });
  check('files, GeoPackage, API, delta and dynamic layers share one preparer',()=>{
    for(const [mode,kind,change] of [['MANAGED','INTERNAL_MANAGED','FULL_SNAPSHOT'],['MANAGED','INTERNAL_MANAGED','DELTA_PATCH'],['PULL','EXTERNAL_API','DELTA_PATCH'],['PULL','OGC_SERVICE','PROPERTY_EVENTS']]){
      const {snapshot,proposal}=fixture(mode,kind);snapshot.configuration.changeRepresentationProfile.mode=change;
      if(kind==='OGC_SERVICE') snapshot.configuration.extractionProfile.runtime.udp.spatial={policyRef:'crs-1',geometry:{sourceField:'urn:geometry'}};
      const out=prepare(snapshot,proposal);assert.equal(out.changes.length,1);assert.equal(out.scheduling.oneShotDerivedFromManaged,mode==='MANAGED');
      assert.deepEqual(out.configuration.extractionProfile.runtime.udp.spatial,snapshot.configuration.extractionProfile.runtime.udp.spatial);
    }
  });
  check('null or absent reconciliation both retained in the baseline proof',()=>{
    const {snapshot,proposal}=fixture();snapshot.configuration.extractionProfile.runtime.udp.materialization.properties[0].reconciliation=null;
    proposal.properties[0].expectedCurrent.reconciliation=null;assert.equal(prepare(snapshot,proposal).changes.length,1);
  });
  check('stale owner hash blocked',()=>{const {snapshot,proposal}=fixture();snapshot.configurationHash='sha256:'+'b'.repeat(64);assert.throws(()=>prepare(snapshot,proposal),/BASELINE_IDENTITY_DRIFT/);});
  check('source authority drift blocked',()=>{const {snapshot,proposal}=fixture();snapshot.configuration.extractionProfile.runtime.udp.materialization.properties[0].authorityOrder=['other'];assert.throws(()=>prepare(snapshot,proposal),/PROPERTY_CONFIGURATION_DRIFT/);});
  check('access label drift blocked',()=>{const {snapshot,proposal}=fixture();snapshot.configuration.extractionProfile.runtime.udp.materialization.properties[0].accessLabel='OPEN';assert.throws(()=>prepare(snapshot,proposal),/PROPERTY_CONFIGURATION_DRIFT/);});
  check('missing explicit cardinality blocked',()=>{const {snapshot,proposal}=fixture();delete proposal.properties[0].reconciliation.cardinality;assert.throws(()=>prepare(snapshot,proposal),/UNSUPPORTED_RECONCILIATION_RULE/);});
  check('unsupported normalizer blocked',()=>{const {snapshot,proposal}=fixture();proposal.properties[0].reconciliation.normalizerRef='FUZZY';assert.throws(()=>prepare(snapshot,proposal),/UNSUPPORTED_RECONCILIATION_RULE/);});
  check('deletion without source revision blocked',()=>{const {snapshot,proposal}=fixture();proposal.properties[0].reconciliation.deletionField='remove';assert.throws(()=>prepare(snapshot,proposal),/EXPLICIT_DELETION_CONTRACT_REQUIRED/);});
  check('geometry cannot be converted into scalar reconciliation',()=>{const {snapshot,proposal}=fixture();snapshot.configuration.extractionProfile.runtime.udp.spatial={geometry:{sourceField:'urn:asset:name'}};assert.throws(()=>prepare(snapshot,proposal),/GEOMETRY_REQUIRES_SPATIAL_PROFILE/);});
  check('multivalue temporal combination blocked',()=>{const {snapshot,proposal}=fixture();proposal.properties[0].reconciliation.cardinality='MULTI';snapshot.configuration.extractionProfile.runtime.udp.materialization.bitemporalProperties=['urn:asset:name'];assert.throws(()=>prepare(snapshot,proposal),/UNSUPPORTED_BITEMPORAL_COMBINATION/);});
  check('existing active reconciliation cannot be overwritten',()=>{const {snapshot,proposal}=fixture();const p=snapshot.configuration.extractionProfile.runtime.udp.materialization.properties[0];p.reconciliation=clone(proposal.properties[0].reconciliation);proposal.properties[0].expectedCurrent=clone(p);assert.throws(()=>prepare(snapshot,proposal),/EXISTING_RULE_REQUIRES_SEPARATE_REVIEW/);});
  check('duplicate proposed property blocked',()=>{const {snapshot,proposal}=fixture();proposal.properties.push(clone(proposal.properties[0]));assert.throws(()=>prepare(snapshot,proposal),/DUPLICATE_PROPOSED_PROPERTY/);});
  check('metadata projection is insufficient for a publication payload',()=>{const {snapshot,proposal}=fixture();delete snapshot.configuration.semanticMapping;assert.throws(()=>prepare(snapshot,proposal),/COMPLETE_CONFIGURATION_REQUIRED/);});
  check('empty configuration basis cannot authorize inferred semantics',()=>{const {snapshot,proposal}=fixture();delete proposal.properties[0].basis.validity;assert.throws(()=>prepare(snapshot,proposal),/EXPLICIT_CONFIGURATION_BASIS_REQUIRED/);});
  check('unsupported datatype aliases rejected',()=>{const {snapshot,proposal}=fixture();snapshot.configuration.extractionProfile.runtime.udp.materialization.properties[0].datatype='xsd:string';proposal.properties[0].expectedCurrent.datatype='xsd:string';assert.throws(()=>prepare(snapshot,proposal),/UNSUPPORTED_DATATYPE/);});
  check('bundle-level delta contract remains in its native location',()=>{
    const {snapshot,proposal}=fixture('PULL','EXTERNAL_API');
    snapshot.configuration.bundle.changeRepresentationProfile={mode:'DELTA_PATCH'};
    snapshot.configuration.bundle.deltaPatchContract={contractId:'reviewed-delta'};
    delete snapshot.configuration.changeRepresentationProfile;
    const result=prepare(snapshot,proposal);
    assert.deepEqual(result.configuration.bundle,snapshot.configuration.bundle);
    assert.equal(Object.hasOwn(result.configuration,'changeRepresentationProfile'),false);
  });
  check('optional identity and access fields are never fabricated',()=>{
    const {snapshot,proposal}=fixture('PULL','EXTERNAL_API');
    delete snapshot.configuration.sourceObjectIdentityPolicy;delete snapshot.configuration.dataAccessPolicies;
    const result=prepare(snapshot,proposal);
    assert.equal(Object.hasOwn(result.configuration,'sourceObjectIdentityPolicy'),false);
    assert.equal(Object.hasOwn(result.configuration,'dataAccessPolicies'),false);
    assert.equal(result.readyForActivation,false);
    assert.ok(result.requiredGates.includes('OWNER_NATIVE_VALIDATION'));
  });
  return {passed,names};
}
