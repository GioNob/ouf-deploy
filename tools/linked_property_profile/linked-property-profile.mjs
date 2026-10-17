function clone(v) { return JSON.parse(JSON.stringify(v)); }
/** Offline native-profile preparation. No network, database, credentials or publication. */
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

export const POLICY = 'urn:ouf:policy:linked-object-property-reconciliation:v1';
const TYPES = new Set(['string','number','integer','boolean','object','http://www.w3.org/2001/XMLSchema#string']);
const FIELDS = new Set(['policyRef','cardinality','normalizerRef','normalizerVersion','validity','revisionField','deletionField']);
function requireThat(ok, code) { if (!ok) throw new Error(code); }
function plain(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function text(v) { return typeof v === 'string' && v.trim().length > 0; }
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (plain(v)) return Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])]));
  return v;
}
export function digest(v) { return createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex'); }
function validate(property, rule, profile, geometry) {
  requireThat(plain(rule) && Object.keys(rule).every(k=>FIELDS.has(k)), 'UNSUPPORTED_RECONCILIATION_FIELD');
  requireThat(rule.policyRef===POLICY && ['SINGLE','MULTI'].includes(rule.cardinality)
    && ['EXACT_TYPED','NFC_TRIM'].includes(rule.normalizerRef) && rule.normalizerVersion===1
    && ['SOURCE_INTERVAL','UNBOUNDED'].includes(rule.validity), 'UNSUPPORTED_RECONCILIATION_RULE');
  requireThat(TYPES.has(property.datatype), 'UNSUPPORTED_DATATYPE');
  const stringType = ['string','http://www.w3.org/2001/XMLSchema#string'].includes(property.datatype);
  requireThat(rule.normalizerRef!=='NFC_TRIM' || stringType, 'STRING_NORMALIZER_REQUIRES_STRING');
  requireThat(['propertyIri','sourceField','datatype','accessLabel'].every(k=>text(property[k])), 'PROPERTY_BINDING_REQUIRED');
  requireThat(Array.isArray(property.authorityOrder) && property.authorityOrder.every(text)
    && new Set(property.authorityOrder).size===property.authorityOrder.length, 'INVALID_EXISTING_AUTHORITY');
  for (const key of ['revisionField','deletionField'])
    requireThat(rule[key]===undefined || rule[key]===null || text(rule[key]), 'INVALID_SOURCE_CONTRACT_FIELD');
  requireThat(!rule.deletionField || rule.cardinality==='SINGLE' && text(rule.revisionField)
    && property.authorityOrder.length>0, 'EXPLICIT_DELETION_CONTRACT_REQUIRED');
  requireThat(!geometry || property.sourceField!==geometry.sourceField, 'GEOMETRY_REQUIRES_SPATIAL_PROFILE');
  requireThat(!profile.bitemporalProperties?.includes(property.propertyIri)
    || rule.cardinality==='SINGLE' && !rule.deletionField, 'UNSUPPORTED_BITEMPORAL_COMBINATION');
}

/** The caller supplies a fresh complete owner configuration, never just the projected property list. */
export function prepare(snapshot, proposal) {
  requireThat(plain(snapshot) && plain(proposal), 'INPUT_OBJECT_REQUIRED');
  requireThat(proposal.schema==='ouf.linked-property-profile-proposal.v1', 'PROPOSAL_SCHEMA_REQUIRED');
  for(const key of ['sourceId','onboardingVersionId','configurationHash']) {
    requireThat(text(snapshot[key]) && snapshot[key]===proposal.expected[key], 'BASELINE_IDENTITY_DRIFT');
  }
  requireThat(/^sha256:[a-f0-9]{64}$/.test(snapshot.configurationHash), 'OWNER_CONFIGURATION_HASH_REQUIRED');
  const configuration=snapshot.configuration;
  requireThat(plain(configuration) && plain(configuration.bundle) && plain(configuration.semanticMapping)
    && plain(configuration.syncProfile) && plain(configuration.sourceObjectIdentityPolicy)
    && plain(configuration.changeRepresentationProfile) && Array.isArray(configuration.dataAccessPolicies), 'COMPLETE_CONFIGURATION_REQUIRED');
  requireThat(configuration.bundle.source?.sourceId===snapshot.sourceId, 'SOURCE_BINDING_DRIFT');
  const udp=configuration.extractionProfile?.runtime?.udp;
  const profile=udp?.materialization;
  requireThat(plain(profile) && plain(udp.resolution) && text(profile.policyRef)
    && Array.isArray(profile.properties) && profile.properties.length>0 && profile.properties.length<=256, 'NATIVE_PROFILE_REQUIRED');
  requireThat(Array.isArray(proposal.properties) && proposal.properties.length>0
    && proposal.properties.length<=256, 'EXPLICIT_PROPERTY_RULES_REQUIRED');
  const byIri=new Map(profile.properties.map((p,i)=>[p.propertyIri,{p,i}]));
  requireThat(byIri.size===profile.properties.length, 'DUPLICATE_EXISTING_PROPERTY');
  const selected=new Set(); const candidate=clone(configuration); const changes=[];
  for(const decision of proposal.properties) {
    requireThat(!selected.has(decision.propertyIri), 'DUPLICATE_PROPOSED_PROPERTY'); selected.add(decision.propertyIri);
    const found=byIri.get(decision.propertyIri);requireThat(found, 'MAPPED_PROPERTY_REQUIRED');
    requireThat(plain(decision.expectedCurrent) && isDeepStrictEqual(found.p,decision.expectedCurrent), 'PROPERTY_CONFIGURATION_DRIFT');
    requireThat(found.p.reconciliation===undefined || found.p.reconciliation===null, 'EXISTING_RULE_REQUIRES_SEPARATE_REVIEW');
    requireThat(plain(decision.basis) && ['cardinality','normalization','validity','sourceAuthority','deletion']
      .every(k=>text(decision.basis[k])), 'EXPLICIT_CONFIGURATION_BASIS_REQUIRED');
    validate(found.p, decision.reconciliation, profile, udp.spatial?.geometry);
    candidate.extractionProfile.runtime.udp.materialization.properties[found.i].reconciliation=clone(decision.reconciliation);
    changes.push({propertyIri:decision.propertyIri,path:`/extractionProfile/runtime/udp/materialization/properties/${found.i}/reconciliation`,before:found.p.reconciliation??null,after:clone(decision.reconciliation)});
  }
  const restored=clone(candidate);
  for(const {p,i} of byIri.values()) {
    if(!selected.has(p.propertyIri))continue;
    const changed=restored.extractionProfile.runtime.udp.materialization.properties[i];
    if(Object.hasOwn(p,'reconciliation'))changed.reconciliation=p.reconciliation;else delete changed.reconciliation;
  }
  requireThat(isDeepStrictEqual(restored,configuration), 'UNRELATED_CONFIGURATION_CHANGED');
  const acquisition=configuration.bundle.source.acquisitionMode;
  requireThat(['MANAGED','PULL'].includes(acquisition), 'UNKNOWN_ACQUISITION_MODE');
  return {
    schema:'ouf.linked-property-profile-preparation.v1', sourceId:snapshot.sourceId,
    baselineVersionId:snapshot.onboardingVersionId, baselineConfigurationHash:snapshot.configurationHash,
    // Digests bind this local artifact; the native owner computes the authoritative candidate hash.
    inputDigest:digest(configuration),candidateDigest:digest(candidate),configuration:candidate,changes,
    preserved:{identity:true,sourceAuthority:true,datatype:true,access:true,geometry:true,temporalMapping:true,syncProfile:true,otherConfiguration:true},
    scheduling:{acquisitionMode:acquisition,oneShotDerivedFromManaged:acquisition==='MANAGED',
      newPublicationCanScheduleAcquisition:true,topLevelTriggerOnceIsNotTheGate:true,
      existingRunsKeepPinnedBundle:true,requiresFreshScheduleAndInflightRead:true},
    nativeProfilePublished:false,readyForActivation:false,runtimeAuthorityIssued:false,
    requiredGates:['SEMANTIC_AND_SOURCE_CONTRACT_REVIEW','BOTH_XSD_STRING_CAPABLE_APPLICATIONS_IF_USED',
      'OWNER_NATIVE_VALIDATION','FRESH_ACTIVE_PUBLICATION_AND_SCHEDULE_READ',
      'EXPLICIT_ACQUISITION_EFFECT_OR_PROVEN_SOURCE_HOLD','HUMAN_THS_APPROVAL'],
    jobsRetried:0,identityDecisionsPerformed:false,historicalReprocessing:false
  };
}
