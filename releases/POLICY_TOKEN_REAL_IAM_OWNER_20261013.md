# Policy token: IAM reale, owner e worker — candidato qualificato

Il candidato risolve il seam DomainOwner e compone il worker periodico finito usato per il nuovo contratto del token policy-read. Consente di proseguire verso le card Teatri senza approvare implicitamente token, pubblicazione semantica o attivazione della sorgente. Non è ancora un installer qualificato sul VPS.

## Modifiche e prova

`iam_admission.py` usa TLS con CA/hostname e peer espliciti, discovery e introspection del Keycloak esistente, senza DNS/proxy/redirect/fallback o retry interno. Verifica issuer, client, service-account subject, tenant, actor SERVICE, audience, scope e validità residua. Le radici TLS effettive, la policy del journal e l'intervallo del worker fanno parte del binding approvato. Nessun JWT viene approvato decodificandone semplicemente il payload.

`installed_owner.py` collega il binding alla custodia delle sorgenti, al mandato HUMAN corrente e alle due firme di ruolo già previste. Richiede uno scope esplicito `tokenOwnerRuntime`, il journal e il marker di admission preesistenti e i due vecchi writer unit inattivi e masked. Una risposta tardiva non può ripristinare un marker revocato. Le firme infrastrutturali non creano permessi IAM.

`worker_entry.py` costruisce gli adapter reali e il ciclo di esecuzione. Resta vivo e fermo quando journal o osservabilità non sono dimostrabili; non riparte automaticamente da quello stato. `reporter.py` conserva un solo stato pubblico limitato, senza token, principal, path privati o hash del token. Readiness applicativa resta separata dalla liveness.

La source-stage v2 include dieci sorgenti reali e il binding dell'owner; la v1 storica mantiene il proprio contratto. Ogni grant, inclusi i rinnovi riusciti, consuma lo stesso budget finito. Nessun journal, marker, scope, sessione o budget viene inizializzato dal worker. Il profilo conservativo non implementa un rinnovo HUMAN del budget né un servizio illimitato.

Qualificazione finale dell'intera composizione su commit `25e75789e6d9ba95a783d50956b6c5e9031f2d37`: [CI 38354374394](https://github.com/GioNob/ouf-deploy/actions/runs/38354374394), **78 prove, zero esclusioni**, con custodia root/gid10001, firme Ed25519, TLS vero, writer systemd realmente masked sul runner monouso, riavvio ambiguo, cancellazione, log sink guasto e comando operativo. Quando il log fallisce e il journal resta disponibile, anche l'osservazione persistente passa a BLOCKED. La prova con un container Keycloak reale passa per discovery, grant, introspection, audience errata, token alterato e client disabilitato. Immagine test `quay.io/keycloak/keycloak:26.0.8`, ID `sha256:e447933b6a5015646c24a1b927a40202ce07adbadac839e7a1f99c463d68a224`. Questo è un issuer monouso CI, non l'IAM di produzione. Evidenza conservata: [qualification JSON](../evidence/policy-token-real-iam-owner-source-qualification-20261013.json).

## Dipendenza reale sul VPS

Il vecchio writer osservato risiede sotto `/opt/ouf`, con ancestor uid/gid1000 e custodia non dimostrata. La sola presenza di HTTPS, client e scope nella configurazione storica non prova l'autorità IAM. Non si può copiare il vecchio segreto, inventare accounting zero o riutilizzare i claim consumati R8–R12.

Il runner VPS disponibile non offre il canale root interattivo necessario per osservare e poi stabilire le nuove radici protette. I tre percorsi seguenti sono una proposta già documentata, non directory la cui presenza/custodia sul VPS sia stata accettata:

| Ruolo | Percorso proposto |
| --- | --- |
| Codice approvato | `/usr/local/libexec/ouf-policy-token` |
| Credenziale ristabilita dall'IAM owner | `/etc/ouf/policy-token/credentials/semantic` |
| Stato persistente | `/var/lib/ouf/policy-token/semantic` |

Occorre prima la sola osservazione root riportata sotto. Successivamente il pacchetto d'installazione deve includere il binding reale IAM e la provenienza della credenziale, l'accounting storico riconciliato, il layout eseguibile e loader root con tutte le dipendenze di authority, il contratto completo dei sei mount e il mandato/firme aggiornati sul nuovo source closure. Il controllo dei dieci file staged non prova da solo che il processo stia eseguendo esattamente quei byte. Nessuna di queste evidenze viene sostituita dalla CI.

Il canale DRAFT → validazione → review rimane nelle PR [Registry35](https://github.com/GioNob/ouf-semantic-registry/pull/35), [Gateway70](https://github.com/GioNob/ouf-api-gateway/pull/70) e [MCP64](https://github.com/GioNob/ouf-mcp-server/pull/64). Dopo il rollout qualificato: creare i21 draft Teatri, ottenere revisioni/hash/card reali, review HUMAN in THS, poi attivazione source/config approvata e ingestione dei13 record con ACK, lineage, dedup/merge e ricerca. Non sono state create card o ingestion di produzione in questa qualificazione.

## Unico comando richiesto ora all'operatore sul VPS

Eseguire nel terminale VPS già usato come `oufadmin`. Riutilizza il `gh` esistente fuori dal PATH, scarica una sola sorgente privata da un commit fisso e ne verifica SHA256; il processo root esegue gli stessi byte già verificati dalla memoria, senza una copia modificabile tra verifica ed esecuzione. `sudo` può richiedere la normale password sul terminale.

Lo script legge solo ownership/mode/identità delle tre radici e gli stati delle due unit già identificate. Non legge token, chiavi, secret, contenuti del journal, environment, argomenti del writer o nomi dei membri delle directory. Non crea cartelle, non cambia permessi, non ferma servizi e non effettua grant.

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-protected-scope-observation.json
import base64,hashlib,pathlib,shutil,subprocess,sys
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
import os
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='5cffef27d03374ccfc20e34f7cf3812187428054'
endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/protected_scope_probe.py?ref='+ref
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>32768:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE; no sudo executed')
expected='0974406a9400e4ff42acf766f2734ee8a29e45319fa23677b3fe887a0443511e'
if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
payload=base64.b64encode(raw).decode('ascii')
bootstrap='import base64,hashlib\nraw=base64.b64decode('+repr(payload)+',validate=True)\nif hashlib.sha256(raw).hexdigest()!='+repr(expected)+':raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\nexec(compile(raw,"qualified-protected-scope-probe","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=60)
except Exception:raise SystemExit('phase=ROOT_METADATA reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Restituire il JSON prodotto. È una richiesta di esecuzione materiale root read-only, non una nuova richiesta di autorizzazione a sviluppare. Un eventuale errore resta distinto per fase DELIVERY/ROOT_METADATA; le osservazioni UNPROVEN conservano ruolo, fase e motivo. L'esito non dà approvazione all'installer o all'IAM.

Regola di authority applicabile: [AGENTS.md](https://github.com/GioNob/ouf-deploy/blob/main/AGENTS.md), «Development delegation is not runtime HUMAN authority». Il collo di bottiglia corrente è l'assenza della superficie root e dei binding protetti reali, non una revoca dell'autorizzazione GitHub data dall'utente.
