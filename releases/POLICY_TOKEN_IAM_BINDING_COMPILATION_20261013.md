# Binding IAM dai metadati già acquisiti — nessun nuovo login o GET

Il [receipt operatore](../evidence/policy-token-existing-iam-metadata-target-20261013.json) riporta service-account abilitato, scope richiesti assegnati,9default/5optional e un solo file privato di metadati. Non prova token/secret/accounting o autorità runtime. Il file viene riusato esattamente tramite il suo hash: non ripetere login e acquisizione IAM.

Il compilatore `iam_binding_candidate.py` seleziona mapper client + default scope + soli optional effettivamente richiesti. Produce un candidato privato con issuer/client/subject candidato, riferimento tenant/actor/audience, envelope conservativo dei possibili scope e fatti/limiti dei mapper. L'envelope non è una lettura del bearer né una nuova assegnazione IAM. Mapper sconosciuti, override del subject, conflitti, audience assente e flag introspection non espliciti diventano motivi di review; non viene automaticamente corretto alcun mapper. Persino con tutti i fatti statici positivi, peer HTTPS, credenziale, accounting, fresh introspection e autorità corrente restano non provati.

I riferimenti da confrontare, già usati nell'ambiente OUF, sono issuer `https://auth.ouf-lab.it/realms/ouf`, tenant `ouf-lab`, audience `ouf-api-gateway`, actor `SERVICE`. Sono vincoli di confronto della proposta, non permessi creati dal compilatore. La differenza dai metadati è esposta con codici, senza pubblicare valori del client/subject/mapper. Non estendere automaticamente il confronto per farlo passare.

La CLI legge solo il file root0600 selezionato, con no-follow/ancestry/hash/identità e schema esatto, massimo512KiB. Non apre configurazioni, client-secret, token, chiavi, journal o altre evidenze. Pubblica esclusivamente un candidato root0600 nel parent evidence esistente. Nome basato sui byte del candidato e O_EXCL: ripetizione identica riconcilia senza riscrivere; file parziale/estraneo blocca, non viene cancellato o sostituito con un nuovo job. Non crea radici runtime, budget o unit. Il profilo diagnostico ha30secondi complessivi, zero richieste esterne e nessun retry interno.

## Comando per il terminale VPS

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-iam-binding-compilation.json
import base64,hashlib,pathlib,shutil,subprocess,os
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='18d65dcbeea0c563e750b61d0f7887d60c5d3c5e'
endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_binding_candidate.py?ref='+ref
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>65536:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE; no sudo executed')
expected='b394254b874f86342ca6c110226ceb968941affc3c9daa760e00cb978edb776e'
if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
args=['qualified-iam-binding','--snapshot','/etc/ouf/deploy-snapshots/policy-token-iam-metadata-74e3f02522a741b3919dfe3f06a2cccc.private.json','--snapshot-sha256','6e37df961443b0c3f95f097865c53af5f8b3b777e626d59c5faaa44973942227','--issuer','https://auth.ouf-lab.it/realms/ouf','--tenant','ouf-lab','--audience','ouf-api-gateway']
payload=base64.b64encode(raw).decode('ascii')
bootstrap='import base64,hashlib,sys\nraw=base64.b64decode('+repr(payload)+',validate=True)\nif hashlib.sha256(raw).hexdigest()!='+repr(expected)+':raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\nsys.argv='+repr(args)+'\nexec(compile(raw,"qualified-iam-binding","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=45)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Incollare solo il JSON pubblico. Candidato e metadati privati rimangono sul VPS. Un risultato COMPILED_REVIEW_ONLY non approva il runtime; usare motivi e fatti statici per comporre la successiva re-establishment/accettazione IAM, la riconciliazione accounting e l'installer con mandato/firme correnti. Il timer legacy e R12 restano invariati. Card THS e CSV13 ACK/lineage/search sono ancora il traguardo successivo al rollout.
