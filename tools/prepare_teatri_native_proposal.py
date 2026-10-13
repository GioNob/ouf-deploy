"""Private review preparation only: no network, owner writes or approval.

Build owner-compatible native DRAFT commands from the retained authorized
profile. No imported ontology, external alignment, publication/revision pins,
credential material, raw CSV values or runtime claims are fabricated.
"""
import hashlib
import json
from pathlib import Path
import re

ASSET='6609b245-86ed-4315-8ce0-73f2a8555bf3'
PROFILE='7984c39c-7396-4248-ab0a-f2efc390b49c'
PROFILE_HASH='cfa36cff7ad5034c743e23dec79cc3c989431a9222b1058393b4a67ac078fd29'
NS='https://api.ouf-lab.it/semantic/teatri#'
CLASS=NS+'Teatro'
XSD='http://www.w3.org/2001/XMLSchema#'
TYPES={'STRING':'string','LONG':'integer','DECIMAL':'decimal','DATE':'date'}

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')

def prepare(profile,owner_ref,authority_ref):
    if hashlib.sha256(canonical(profile)).hexdigest()!=PROFILE_HASH:
        raise ValueError('RETAINED_PROFILE_OBSERVATION_DRIFT')
    if not (profile.get('assetId')==ASSET and profile.get('profileId')==PROFILE
            and profile.get('profileVersion')==1 and profile.get('format')=='CSV'
            and profile.get('metadata')=={'rows':13,'columns':20,'encoding':'UTF-8','delimiter':';','headerRow':1}):
        raise ValueError('EXACT_RETAINED_TEATRI_PROFILE_REQUIRED')
    columns=profile.get('columns')
    if not (type(columns) is list and len(columns)==20
            and len({c.get('name') for c in columns})==20
            and all(re.fullmatch('[a-z][a-z_]{0,63}',c.get('name',''))
                    and c.get('dataType') in TYPES and type(c.get('nullable')) is bool for c in columns)
            and profile.get('identityProposal',{}).get('sourceFields')==['nome_teatro']
            and any(c['name']=='nome_teatro' and not c['nullable'] and c.get('distinctValues')==13 for c in columns)):
        raise ValueError('BOUNDED_PROFILE_IDENTITY_AND_TYPES_REQUIRED')
    if not all(type(v) is str and 0<len(v)<=200 and not any(x in v for x in '\r\n') for v in (owner_ref,authority_ref)):
        raise ValueError('EXPLICIT_PROPOSED_OWNER_AND_AUTHORITY_REQUIRED')
    common={'namespace':NS,'ownerRef':owner_ref,'authorityRef':authority_ref,'semanticVersion':'1.0.0'}
    commands=[{**common,'semanticId':CLASS,'artifactType':'CLASS','localName':'Teatro',
        'labels':{'it':'Teatro'},'definition':{'description':{'it':'Luogo teatrale censito dalla sorgente Teatri. Classe OUF nativa proposta; nessuna equivalenza con Cinema o allineamento esterno.'}}}]
    fields=[]
    for column in columns:
        name=column['name'];iri=NS+name
        definition={'domainRefs':[CLASS],'datatype':XSD+TYPES[column['dataType']],
                    'minCardinality':0 if column['nullable'] else 1,'maxCardinality':1,
                    'description':{'it':'Valore della colonna '+name+' della sorgente Teatri, senza normalizzazione o interpretazioni aggiuntive.'}}
        commands.append({**common,'semanticId':iri,'artifactType':'PROPERTY','localName':name,
                         'labels':{'it':name.replace('_',' ')},'definition':definition})
        fields.append({'fieldName':name,'extractionDecision':'INCLUDE','dataAccessLabel':'RESTRICTED',
                       'targetPropertyIri':iri})
    content={'schema':'ouf.teatri-native-semantic-review.v1','status':'PREPARED_FOR_OWNER_REVIEW_NOT_REGISTERED',
        'profileBinding':{'assetId':ASSET,'profileId':PROFILE,'profileVersion':1,'profileObservationHash':hashlib.sha256(canonical(profile)).hexdigest(),
                          'rowsHistorical':13,'columnsHistorical':20,'rawCsvValuesRead':False},
        'proposedOwnership':{'ownerRef':owner_ref,'authorityRef':authority_ref,'authorityInheritedFromOtherArtifacts':False},
        'nativeDraftCommands':commands,
        'mappingBlueprint':{'targetClassIri':CLASS,'sourceObjectKeyFields':['nome_teatro'],'fields':fields,
                            'semanticReferencesResolved':False,'notExecutableOnboardingRequest':True},
        'reviewRequirements':[
            'Owner confirms native semantic need, namespace, ownership and authority; proposal is no approval.',
            'Owner validates the 21 DRAFT revisions; HUMAN reviews and publishes exact content through THS.',
            'Bind all class/property revisions to an exact final published set; no latest or fabricated pins.',
            'Confirm all 20 extraction/access decisions. RESTRICTED is a conservative proposal, not source classification evidence.',
            'CAP remains the profiled integer source value; no leading-zero recovery or postal-code normalization is claimed.',
            'Coordinates are decimal source values; no CRS, axis-order or geometry conversion is inferred.',
            'nome_teatro is proposed as source-local native key. Renames change identity absent a governed policy; no cross-source merge.',
            'Verify retention, source configuration, finite run, durable ACK/lineage and complete search for all 13 rows.'
        ],
        'effects':{'artifactCreated':False,'approvalIssued':False,'published':False,'sourceActivated':False,
                   'newRunIssued':False,'durableAckObserved':False,'csvEndToEndProven':False,
                   'vpsChanged':False,'r12Touched':False,'budgetReset':False},
        'nativePathDeploymentCompatibilityProven':False,'v11CutoverWaived':False,
        'humanAuthorityRequired':True,'notReleaseAcceptance':True}
    return {**content,'proposalHash':hashlib.sha256(canonical(content)).hexdigest()}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=Path,required=True)
    parser.add_argument('--owner-ref',required=True)
    parser.add_argument('--authority-ref',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=prepare(json.loads(args.profile.read_text()),args.owner_ref,args.authority_ref)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print('TEATRI_NATIVE_REVIEW_PREPARED_NOT_REGISTERED '+result['proposalHash'])
