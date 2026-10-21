"""Prepare one reviewable RDF proposal; never adopt, publish or execute it.

The original 20261013 proposal remains historical evidence. This replacement
uses established Schema.org class/name/type terms and retains source-scoped
facts whose meaning cannot be collapsed into a broader standard property.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = 'https://api.ouf-lab.it/semantic/teatri#'
ONTOLOGY = NS + 'TeatriOntology'
SCHEMA = 'https://schema.org/'
XSD = 'http://www.w3.org/2001/XMLSchema#'

COMMENTS = {
    'toponimo': 'Tipo di elemento stradale riportato dalla fonte, distinto dal nome e dal numero civico; non e un indirizzo completo.',
    'nome_indirizzo': 'Componente nominale dell indirizzo riportata dalla fonte; non include implicitamente toponimo e civico.',
    'civico': 'Numero civico lessicale riportato dalla fonte, compresi eventuali suffissi; nessuna risoluzione di indirizzi discordanti.',
    'cap': 'Codice postale lessicale del luogo riportato dalla fonte. Conservare gli zeri iniziali dai byte CSV; il tipo LONG del profiler non autorizza conversioni numeriche.',
    'citta': 'Localita dell indirizzo riportata dalla fonte; questa proprieta piatta non asserisce una risorsa PostalAddress.',
    'provincia': 'Provincia dell indirizzo riportata dalla fonte; il testo non e risolto in una entita amministrativa.',
    'latitudine': 'Valore di latitudine riportato dalla fonte, da interpretare insieme a sistema_riferimento e precisione_coordinate; non equivale a una trasformazione WGS84 verificata.',
    'longitudine': 'Valore di longitudine riportato dalla fonte, da interpretare insieme a sistema_riferimento e precisione_coordinate; non equivale a una trasformazione WGS84 verificata.',
    'sistema_riferimento': 'Sistema di riferimento dichiarato dalla fonte per le coordinate; nessuna trasformazione o completamento implicito.',
    'precisione_coordinate': 'Descrizione della precisione e del riferimento geometrico riportata dalla fonte; non convertita in una tolleranza numerica.',
    'capienza_posti': 'Posti riportati dalla fonte. Il valore puo riferirsi a una singola sala secondo note; non asserisce la capienza totale del luogo.',
    'spettacoli_stagione': 'Numero di spettacoli riportato dalla fonte per stagione_riferimento; non un totale senza periodo e non un elenco di eventi.',
    'stagione_riferimento': 'Etichetta della stagione cui si riferisce la misura spettacoli_stagione; nessuna data di inizio o fine inferita.',
    'note': 'Annotazioni della fonte che qualificano i valori riportati, compresi ambito della capienza e discrepanze dell indirizzo.',
    'fonte_indirizzo': 'Riferimento di provenienza riportato per i dati di indirizzo; non il sito ufficiale del teatro e non un ordine di accesso alla URL.',
    'fonte_coordinate': 'Riferimento di provenienza riportato per le coordinate; non una verifica geografica e non un ordine di accesso alla URL.',
    'fonte_altri_dati': 'Riferimento di provenienza riportato per altri dati; non una equivalenza di identita e non un ordine di accesso alla URL.',
    'data_verifica': 'Data di verifica dichiarata dalla fonte per il record; non data di modifica dell oggetto urbano o prova indipendente della verifica.',
}

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()

def prepare(previous):
    commands = previous['nativeDraftCommands']
    fields = commands[1:]
    if len(fields) != 20 or {c['localName'] for c in fields} != set(COMMENTS) | {'nome_teatro', 'tipologia'}:
        raise ValueError('EXACT_TWENTY_RETAINED_FIELDS_REQUIRED')
    prefix = ('@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n'
              '@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n'
              '@prefix owl: <http://www.w3.org/2002/07/owl#> .\n'
              '@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n'
              '@prefix schema: <https://schema.org/> .\n'
              '@prefix dct: <http://purl.org/dc/terms/> .\n'
              '@prefix teatri: <' + NS + '> .\n\n')
    blocks = [
        'teatri:TeatriOntology a owl:Ontology ; rdfs:label "Profilo semantico dei luoghi teatrali"@it ;\n'
        '  dct:source <https://schema.org/PerformingArtsTheater>, <https://schema.org/name>, <https://schema.org/additionalType> ;\n'
        '  rdfs:comment "Proposta da approvare: riuso di termini standard e proprieta qualificate della fonte. Nessuna equivalenza con Cinema, approvazione o classificazione dei dati e implicita."@it .',
        'schema:PerformingArtsTheater a owl:Class ; rdfs:label "Luogo per le arti performative"@it ; rdfs:isDefinedBy <https://schema.org/PerformingArtsTheater> .',
        'schema:name a rdf:Property ; rdfs:label "Nome"@it ; rdfs:isDefinedBy <https://schema.org/name> .',
        'schema:additionalType a rdf:Property ; rdfs:label "Tipologia aggiuntiva dichiarata"@it ; rdfs:isDefinedBy <https://schema.org/additionalType> .',
    ]
    mappings = []
    for field in fields:
        name = field['localName']
        # The actual CSV adapter + IDENTITY pipeline retain lexical cells.
        # Profiler inference is not a conversion contract. Do not advertise
        # numeric/date JSON materialization which that pipeline never performs.
        datatype = XSD + 'string'
        target = SCHEMA + {'nome_teatro': 'name', 'tipologia': 'additionalType'}[name] if name in ('nome_teatro', 'tipologia') else NS + name
        if name in COMMENTS:
            blocks.append('teatri:' + name + ' a owl:DatatypeProperty ;\n'
                          '  rdfs:domain schema:PerformingArtsTheater ; rdfs:range <' + datatype + '> ;\n'
                          '  rdfs:label ' + json.dumps(name.replace('_', ' '), ensure_ascii=False) + '@it ;\n'
                          '  rdfs:comment ' + json.dumps(COMMENTS[name], ensure_ascii=False) + '@it .')
        mappings.append({'fieldName': name, 'targetPropertyIri': target,
                         'dataType': 'STRING', 'profileInferredDatatype': field['definition']['datatype'],
                         'extractionDecision': 'INCLUDE', 'dataAccessLabel': 'RESTRICTED'})
    turtle = prefix + '\n\n'.join(blocks) + '\n'
    base = commands[0]
    command = {k: base[k] for k in ('ownerRef', 'authorityRef', 'semanticVersion')}
    command.update(semanticId=ONTOLOGY, artifactType='ONTOLOGY', namespace=NS,
                   localName='TeatriOntology', labels={'it':'Profilo semantico dei luoghi teatrali'},
                   definition={}, mediaType='text/turtle', rdfTurtle=turtle)
    if len(canonical(command)) > 65536:
        raise ValueError('OWNER_COMMAND_BOUND_EXCEEDED')
    review = {
        'schema': 'ouf.teatri-reuse-semantic-review.v2',
        'status': 'PREPARED_FOR_OWNER_REVIEW_NOT_REGISTERED',
        'supersedesUnregisteredProposalHash': previous['proposalHash'],
        'profileBinding': previous['profileBinding'],
        'importCommand': command,
        'rdfSha256': hashlib.sha256(turtle.encode()).hexdigest(),
        'mappingBlueprint': {'targetClassIri':SCHEMA+'PerformingArtsTheater', 'sourceObjectKeyFields':['nome_teatro'],
                             'fields':mappings, 'semanticReferencesResolved':False, 'notExecutableOnboardingRequest':True},
        'constraints': [
            'All twenty property IRIs and the class must be proven in the exact approved containing RDF revision and publication set.',
            'Standard IRIs are proposed for adoption, not already ACTIVE references.',
            'CAP must be parsed from original CSV text as STRING before numeric conversion; never restore guessed leading zeros.',
            'This CSV execution uses IDENTITY and materializes lexical string values. Profiler numeric/date inference remains metadata, not an implemented conversion or range-search guarantee.',
            'HUMAN must review extraction/access labels, source-local key and type classification; RESTRICTED is a proposal.',
            'Coordinate values remain source assertions; missing coordinates and qualifiers must survive ingestion.',
            'Seat capacity remains qualified by notes; never project it as whole-venue maximum capacity.',
            'The unchanged file does not prove a cross-source merge. Verify actual UDP resolution/commit results and separately qualify positive matching.',
        ],
        'effects': {'artifactCreated':False, 'approvalIssued':False, 'published':False, 'sourceActivated':False,
                    'tokenGrantRequests':0, 'vpsChanged':False, 'csvEndToEndProven':False},
        'humanAuthorityRequired': True,
        'notReleaseAcceptance': True,
    }
    review['proposalHash'] = hashlib.sha256(canonical(review)).hexdigest()
    return review, turtle

if __name__ == '__main__':
    previous=json.loads((ROOT/'releases/teatri-native-semantic-proposal-20261013.json').read_text())
    review,turtle=prepare(previous)
    (ROOT/'releases/teatri-reuse-semantic-proposal-20261014.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n')
    (ROOT/'releases/teatri-reuse-20261014.ttl').write_text(turtle)
    print(review['proposalHash'])
