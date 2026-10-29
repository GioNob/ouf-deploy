# Metadati IAM del client policy-read esistente — lettura completata

Aggiornamento: la lettura IAM è stata completata dall'operatore. Il [receipt](../evidence/policy-token-existing-iam-metadata-target-20261013.json) conferma client/service-account/scope e il file privato conservato. Non ripetere questo comando né il login. Il passo corrente è [compilare il binding dal file già acquisito](POLICY_TOKEN_IAM_BINDING_COMPILATION_20261013.md).

La [lettura operatore](../evidence/policy-token-protected-scope-target-20261013.json) del 13 ottobre alle08:25:47 Europe/Rome mostra le tre radici proposte assenti, il service legacy inattivo/static e il timer attivo/enabled. Questo non equivale a writer fenced: non arrestare/maskare il timer prima della transizione qualificata. Il receipt è operator-reported, non un readback indipendente.

## Chiusura eseguibile qualificata

`sealed_runtime.py` verifica tutti i21 moduli effettivamente importati da worker/authority, oltre ai byte del loader. La directory root0700 contiene solo i membri root0600, regolari/single-link e senza symlink. Tutto viene letto e compilato prima di qualsiasi import. Il loader esegue quei byte dalla memoria, con process `-I -B`, namespace tools privato e nessun fallback per moduli locali mancanti. Moduli tools pre-caricati sono rifiutati. La source-stage v2 storica resta invariata: il separato mount observer e il suo binding non sono qualificati da questo caricamento.

[CI 38357362520](https://github.com/GioNob/ouf-deploy/actions/runs/38357362520), commit `f87312d950eae36aa529c9b01727434b6a222831`:87 prove top-level, zero skips. Le9 nuove prove includono il worker/authority effettivo importato senza sorgenti locali, sostituzione di tutti i file dopo la lettura, dipendenze assenti/tamper/extra/link, namespace pre-caricato e quattro scenari nativi annidati di grant/TLS/firme/pause/revoca. Il Keycloak monouso resta verde. Non è un installer completo: bootstrap/interprete/stdlib, configurazione e binding indipendenti, mandate che comprende la nuova closure, accounting storico, six-mount e transizione legacy restano gate distinti.

## Osservazione IAM selezionata

Correzione del selettore dopo il [blocco operatore](../evidence/policy-token-iam-probe-path-selection-block-target-20261013.json): il precedente reader imponeva un filename assunto, senza evidenza target. Non era deriva del VPS. Il reader corretto seleziona l'unica EnvironmentFile dichiarata dalla unit, sotto `/etc`, con percorso canonico, root0600, ancestor root senza scritture di gruppo/altri e nessun override. Non cerca varianti o file credenziali; custodia, schema e stabilità del file/unit restano obbligatori. La configurazione è solo il selettore del client esistente: non prova authority, contenuto del secret o validità del bearer.

Usa soltanto `kcadm get` nel container `ouf-keycloak`, server amministrativo locale `http://localhost:8080`, realm `ouf`, e la sessione già presente. Legge il client selezionato, il service-account e le assegnazioni/default/optional con i metadati dei mapper. Nessuna lettura del client-secret endpoint, login automatico, grant del client SERVICE, modifica IAM, journal o unit. Configurazione e metadati vengono riletti per negare drift durante l'osservazione. Non si assume che la lettura amministrativa interna dimostri il binding HTTPS/peer del token runtime.

Il risultato completo, senza la configurazione originale o i suoi percorsi credenziali, viene scritto esclusivamente in un nuovo file root0600 sotto l'esistente `/etc/ouf/deploy-snapshots`. Principal/client/mapper non sono stampati. L'output pubblico include solo stato, fase, motivo, conteggi e riferimento/hash del nuovo evidence file. Non incollare il file privato in chat. La creazione del solo file evidence è l'unica modifica prevista sul VPS.

Profilo `ouf.policy-token-admin-observation.single-attempt.v1`: deadline totale120secondi e massimo15secondi per GET, nessun retry interno o moltiplicazione tra layer; errore di sessione richiede login interattivo, drift/schema ignoto bloccano, pubblicazione parziale mantiene evidenza/path e richiede riconciliazione. Il profilo diagnostico non crea o sostituisce incidenti/budget runtime.

## Comando storico già eseguito — non ripetere

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-iam-observation.json
import base64,hashlib,pathlib,shutil,subprocess,os
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='2ec928aebdec423ce85c1b5bf65c8b25487d7662'
endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_target_probe.py?ref='+ref
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>65536:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE; no sudo executed')
expected='e0cf80a9df839932c4278605738a226dd11639f7560c686d32e4241621ef2c87'
if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
payload=base64.b64encode(raw).decode('ascii')
bootstrap='import base64,hashlib\nraw=base64.b64decode('+repr(payload)+',validate=True)\nif hashlib.sha256(raw).hexdigest()!='+repr(expected)+':raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\nexec(compile(raw,"qualified-existing-iam-probe","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=135)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Incollare solo il JSON pubblico. `EXISTING_IAM_GET_UNAVAILABLE` non prova da solo una sessione scaduta: include container/CLI/server/sessione indisponibili e non deve essere trasformato in una conclusione IAM. Se il canale è disponibile e occorre rinnovare la sessione, il percorso già documentato è `sudo docker exec -it ouf-keycloak /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user oufadmin`; password solo nel terminale. Nessun login viene eseguito dal reader.

La lettura non ristabilisce ancora il secret, non approva issuer/grant runtime e non riconcilia l'accounting del writer precedente. Dopo il receipt: comporre il binding dai metadati conservati, preparare la re-establishment IAM e la migrazione accounting governata, poi completare installer/current HUMAN/role signatures e six-mount. Card THS Teatri e CSV/ACK/lineage/search dei13 record restano dipendenti dal rollout.
