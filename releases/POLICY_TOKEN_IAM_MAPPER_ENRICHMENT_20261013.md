# Recupero dei mapper completi e compilazione del candidato in un solo passaggio

Il VPS ha bloccato la compilazione prima di qualunque scrittura con MAPPER_SCHEMA_UNPROVEN; [receipt](../evidence/policy-token-iam-binding-mapper-schema-block-target-20261013.json). La prova esatta kcadm monouso in [CI38370345359](https://github.com/GioNob/ouf-deploy/actions/runs/38370345359) riproduce la proiezione: sei mapper privi di protocol/type/config dopo --fields, mentre le rappresentazioni REST complete sono interpretabili. Questo identifica un difetto dell'acquisizione qualificata; il vecchio receipt generico non dimostra da solo che ogni anomalia target abbia questa causa.

Il comando seguente conserva il file originale e usa i suoi ID selezionati come anchor. Legge core client/service-account/scope flat, rifiuta qualsiasi differenza dagli anchor, poi legge solo i mapper del client, dei default scope e degli optional richiesti attraverso protocol-mappers/models SENZA --fields. Una seconda lettura conferma mapper e core; Il protocol delle assegnazioni scope, talvolta omesso dal server, rimane opzionale e non viene inventato; id/name e ogni campo presente restano confrontati, mentre il protocol dei mapper è verificato dalle rappresentazioni complete. Nessun endpoint client-secret, grant SERVICE, modifica IAM, arresto unit o reset budget. Gli optional non richiesti non sono interrogati. La sessione amministrativa esistente è riusata; il comando non fa login.

Il nuovo file di metadati root0600 e il candidato root0600 sono gli unici output sul VPS. Il precedente file e il suo hash restano immutati. Fonte/parent/hash e fase restano nel receipt anche se la compilazione finale fallisce. Non è un aggiornamento della baseline runtime congelata né un rinnovo dell'autorità.

Il candidato v2 espone categorie/conteggi dei mapper opachi senza nomi, chiavi o valori. Opaque schema, mapper sconosciuti, conflitti o flag mancanti restano motivi di review, con vincoli non provati; nessuna accettazione viene concessa per far proseguire il codice. Anche un insieme statico completo non prova bearer/secret, peer HTTPS, accounting o authority/HUMAN corrente. Il compilatore è una proposta, non un'applicazione del rollout V11.

Profilo single-attempt v1: massimo180secondi totali,48GET,15secondi per GET e19scope effective oltre al client; niente retry interno e niente lock/TX condivisi durante I/O. Il limite dei GET include doppia acquisizione e core4+4. Schema/integrità/drift/sessione non dimostrabile bloccano prima della pubblicazione; pubblicazione parziale resta conservata per riconciliazione. Accounting e budget runtime non sono toccati.

## Comando per il VPS

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-iam-mapper-enrichment.json
import base64,hashlib,pathlib,shutil,subprocess,os
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='d3b3b06657d756af297078fc9029f77f0524ba18'
sources=[('binding','iam_binding_candidate.py','a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d'),('enrichment','iam_mapper_enrichment.py','6b6cbfdfd2a4b628c35d8a7eeb087339e15e0ae49aff8be1f359f74de7e0699e')]
records=[]
for name,file,expected in sources:
    endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/'+file+'?ref='+ref
    try:
        reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        if len(reply.stdout)>65536:raise ValueError()
        raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
    except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE module='+name+'; no sudo executed')
    if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH module='+name+'; no sudo executed')
    records.append((name,base64.b64encode(raw).decode('ascii'),expected))
args=['qualified-mapper-enrichment','--snapshot','/etc/ouf/deploy-snapshots/policy-token-iam-metadata-74e3f02522a741b3919dfe3f06a2cccc.private.json','--snapshot-sha256','6e37df961443b0c3f95f097865c53af5f8b3b777e626d59c5faaa44973942227','--issuer','https://auth.ouf-lab.it/realms/ouf','--tenant','ouf-lab','--audience','ouf-api-gateway']
bootstrap='import base64,hashlib,sys,types\nrecords='+repr(records)+'\nverified={}\nfor name,payload,expected in records:\n raw=base64.b64decode(payload,validate=True)\n if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\n verified[name]=raw\nmodule=types.ModuleType("iam_binding_candidate")\nsys.modules[module.__name__]=module\nexec(compile(verified["binding"],"qualified-binding","exec"),module.__dict__)\nsys.argv='+repr(args)+'\nexec(compile(verified["enrichment"],"qualified-mapper-enrichment","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=195)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Incollare soltanto il JSON pubblico. I due file privati restano sul VPS. Se EXISTING_IAM_GET_UNAVAILABLE compare prima delle scritture, preservare fase/esito e usare il login interattivo già documentato se la sessione non è più utilizzabile; non dedurre automaticamente scadenza/permessi dal solo codice generico. Non ruotare secret, correggere scope/mapper o fermare il timer dal solo receipt. Dopo i vincoli: preparare owner credential/peer/accounting/installer e review concreta, fino a card THS e CSV13 ACK/lineage/search.
