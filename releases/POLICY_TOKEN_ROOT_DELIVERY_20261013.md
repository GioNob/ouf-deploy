# Creazione governata delle radici: comando completo qualificato

Il passaggio operativo ora disponibile crea le tre radici già proposte: codice, credenziale e stato persistente. Le identità device/inode realmente ottenute sono conservate nel ledger privato e serviranno ai binding successivi. Non è l'installer completo, non ruota la credenziale e non completa l'end-to-end Teatri.

Sorgente eseguibile: commit `698427d6a26b8714e33611eb7ad225f72100dbc3`, `scripts/establish-policy-token-migration-roots.py`, SHA256 `e5ea803a5f2eb2dc297bd70fbc77ff9c5675c92225fc67afdec1b7ff8a6bc51d`. Riusa il capsule di 29 moduli, SHA256 `6f97e4b49a9d47b5d277b49be7d3037326fcb40045b664c5e4a17af8e31bbac7`, e l'osservazione host `93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4`. Non ripetere le osservazioni IAM o consumer già completate.

La [CI 38456173237](https://github.com/GioNob/ouf-deploy/actions/runs/38456173237), job `115499355740`, ha superato **27 prove, zero escluse**: 8 retirement, 12 root custody e 7 consegna. Le nuove prove eseguono le funzioni operative effettive con directory e firme Ed25519 reali in fixture; host, decisione HUMAN e input amministrativi sono sintetici. È stata inoltre verificata l'importazione delle funzioni effettive dal capsule reale in processo `-I -B -S`. Nessuna di queste prove equivale a un'esecuzione sul VPS.

## Effetti e decisione richiesta

Il comando verifica il codice, legge le evidenze trattenute e i binding correnti, pubblica la review privata completa e mostra nel terminale la lista esatta delle directory. Solo dopo la frase `APPROVO RADICI <hash mostrato>` riserva durevolmente l'emissione, usa la chiave installer già prevista per due firme di ruolo e crea le directory mancanti come root:root/0700 entro 300 secondi. La finestra del prompt è 120 secondi.

Radici: `/usr/local/libexec/ouf-policy-token`, `/etc/ouf/policy-token/credentials/semantic`, `/var/lib/ouf/policy-token/semantic`; i soli parent mancanti sono determinati dall'evidenza host già acquisita. Non modifica IAM, timer, servizi o permessi esistenti; non legge credenziali client o token e non richiede grant. Non riavvia R12, non azzera lo storico UNKNOWN e non emette autorità runtime. Il nuovo comando non chiama il vecchio apply IAM già consumato.

L'approvazione nel terminale è necessaria per la regola di `AGENTS.md` «Development delegation is not runtime HUMAN authority» e il mandato HUMAN del percorso di cutover esistente. La delega a completare lo sviluppo consente di preparare questo risultato; non viene convertita in una decisione runtime precompilata. Nessuna nuova chiave o autorità è introdotta.

La prenotazione di emissione ha un'identità stabile per l'operazione. Un errore dopo prenotazione o un risultato non ricevuto non autorizzano una seconda emissione: conservare il JSON e le evidenze, riconciliare prima. Un inode presente ma non registrato non viene adottato, cancellato o sostituito. Un errore prima di qualsiasi effetto rimane distinto per fase/motivo. Il comando non cerca una sessione amministrativa IAM, quindi non serve rifare login Keycloak per questa operazione.

## Comando per il VPS

Eseguire come `oufadmin` nel terminale abituale. Il comando usa il `gh` portatile esistente e verifica i byte prima di `sudo`. La review e l'eventuale conferma sono nello stesso flusso; restituire soltanto il JSON finale, non file privati o chiavi.

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-root-delivery.json
import base64,hashlib,os,pathlib,shutil,subprocess
p=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(p) if p.is_file() and os.access(p,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='698427d6a26b8714e33611eb7ad225f72100dbc3'
endpoint='repos/GioNob/ouf-deploy/contents/scripts/establish-policy-token-migration-roots.py?ref='+ref
try:
    r=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(r.stdout)>65536:raise ValueError()
    raw=base64.b64decode(b''.join(r.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='e5ea803a5f2eb2dc297bd70fbc77ff9c5675c92225fc67afdec1b7ff8a6bc51d':
    raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
exec(compile(raw,'qualified-root-delivery','exec'),{'__name__':'__main__'})
PY
```

## Posizione nel percorso reale Teatri

Riletture MCP del 13 ottobre 2026, account `ouf-admin`: `ouf.system.status` restituisce il riepilogo PUBLIC_OPERATIONAL MCP HEALTHY; `semantic.search(q=teatro,type=CLASS,limit=5)` restituisce zero risultati per quella ricerca; `source.file.preview` conferma lo stesso asset `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profilo `7984c39c-7396-4248-ab0a-f2efc390b49c`, versione 1, 13 righe/20 colonne, `PENDING_HUMAN_REVIEW`. Nessun sample o dato grezzo è copiato in questa documentazione. HEALTHY riguarda il riepilogo MCP e non certifica tutti gli owner o il deployment.

Restano da chiudere, con prove target: integrazione completa credenziale/token e worker finito; cutover applicativo/six-mount e readiness; registrazione delle 21 proposte semantiche e review/pubblicazione THS; configurazione sorgente approvata; esecuzione ingestion sui 13 record; ACK e lineage UDP, dedup/merge secondo esiti owner; lettura MCP degli oggetti risultanti. Identificativi di revisioni/pubblicazioni/job/oggetti devono provenire dagli owner, non dalle fixture. Nessun replay della precedente Cinema e nessuna equivalenza tra 13 righe e necessariamente 13 nuovi oggetti canonici.

Il prossimo intervento materiale è l'esecuzione di questo comando sul VPS, perché questa sessione non dispone di accesso amministrativo remoto. La ricevuta con le directory realmente create consente di procedere ai binding di migrazione; non dichiarare l'end-to-end dimostrato da questa milestone.
