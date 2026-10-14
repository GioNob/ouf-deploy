# Nuovi pacchetti: raccolta unica degli input d'installazione — 14 ottobre2026

Lo staging è completato in /home/oufadmin/ouf-semantic-candidates-20261014.fADvCV9u, [ricevuta operatore](../evidence/semantic-proposal-candidate-stage-target-20261014.json). Non scaricare nuovamente gli ZIP. Le radici policy-token create il13 ottobre sono custodite e la claim è consumata: [ricevuta e divieto di replay](POLICY_TOKEN_ROOT_DELIVERY_20261013.md). PR5 è integrata e le quattro CI successive al merge134bcc45 passano.

Questo nuovo programma compone la raccolta necessaria a riferire i nuovi byte a quella custodia, alla policy dell'installer e alla generazione attuale del Registry. Serve l'operatore per le letture dei ledger protetti e della metadata Docker: questa sessione non ha un canale SSH/root. Non è una richiesta di approvazione del cutover e non effettua il cutover.

## Perimetro completo di questo comando

- Legge i tre ZIP già consegnati da descriptor no-follow, li lega agli hash Actions e ai manifest qualificati. Questo controllo serve a usare dati della home nel processo root; non li promuove a sorgenti custoditi root.
- Riusa il capsule verificato dei29 moduli e il ledger completato tramite rootEvidenceHash8b769879…/source closure9b78689d…; mantiene aperti i descriptor delle tre radici e ne controlla l'identità. Non ricrea directory né rinnova la vecchia finestra HUMAN.
- Legge il precedente intake governato, piano/snapshot IAM, profile e trust policy pubblici già selezionati; verifica le identità degli eseguibili e della libreria Python effettiva. Non legge i file delle chiavi o della credenziale.
- Riusa l'evidenza consumer603a7e11… senza ripetere l'inventario; la conserva come osservazione storica. Legge soltanto gli stati delle due unit semantic già note.
- Legge la generazione, immagine, restart policy e mount del Registry selezionato7ae83be8…, omettendo Config.Env e i comandi. Confronta di nuovo generazione/unità prima della pubblicazione; eventuali differenze sono descritte tramite nomi dei campi, senza valori privati.
- Pubblica un solo review JSON root-protetto tramite il publisher esistente, senza sovrascrivere evidenze. Timeout root240 secondi, nessun retry automatico. Un esito ambiguo della pubblicazione indica il percorso da riconciliare.

Zero creazioni di radici, firme, accessi a chiavi/credenziali, grant, chiamate IAM/database o modifiche a unità/container/R12. Il report non stampa i mount o il contenuto dei ledger. Una generazione o una custodia diversa blocca la raccolta: non aggiorna automaticamente il baseline.

## Qualificazione

[CI38510781497](https://github.com/GioNob/ouf-deploy/actions/runs/38510781497), job115678542290:6 test, zero esclusi, SUCCESS. Filesystem e proprietà root/utente sono reali sul runner; il test Docker usa una risposta sintetica e verifica l'omissione dell'environment. Il vero programma root carica il capsule byte-esatto in -I -B -S e viene provato anche nel caso in cui i pacchetti target manchino: si ferma prima delle letture private e delle scritture. Non è una prova positiva della raccolta sul VPS.

Il filesystem scratch non supporta il chown usato dalle prove native; non si è indebolito il controllo per farle passare localmente. Le due CI finali hanno invece eseguito tutti i sei casi sul runner Linux con sudo.

Programma: scripts/prepare-semantic-candidate-installation-review.py, commit7f3e08060836ec963013f418f1b2cd96f8d0420a, SHA25654d9c1fbfd6f678f65f8039a42147381f2bd2723476e57376cd9a3e38b68aaca. Le modifiche successive a documentazione non cambiano questi pin.

## Comando da eseguire una volta sul VPS

Riusa gh portable; verifica i byte prima di sudo. Restituire solo il JSON finale, senza ledger, credenziali o output dei comandi amministrativi.

```bash
set -o pipefail
python3 - <<'PY'
import base64,hashlib,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
endpoint='repos/GioNob/ouf-deploy/contents/scripts/prepare-semantic-candidate-installation-review.py?ref=7f3e08060836ec963013f418f1b2cd96f8d0420a'
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>65536:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='54d9c1fbfd6f678f65f8039a42147381f2bd2723476e57376cd9a3e38b68aaca':
    raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
exec(compile(raw,'qualified-installation-input-review','exec'),{'__name__':'__main__'})
PY
```

Risultato atteso: CURRENT_INSTALLATION_INPUTS_RECORDED_NOT_APPLY_READY, con hash e percorso della review privata. Un errore contiene phase/reason/evidenceLocation e conserva i ledger esistenti; non autorizza il replay della creazione o una mutazione alternativa.

## Limiti e seguito

Questa è preparazione di input, non l'installer completo. Non prova OCI completo, schema DB corrente/ammissione V10, runtime MCP/Gateway, nuova chiave receipt o integrazione periodica/renewal HUMAN. I dati privati raccolti dovranno essere usati sul target dal compilatore del nuovo piano, senza copiarli in chat. I nuovi pacchetti non ereditano l'accettazione V11 e le firme della creazione non autorizzano retirement, rotazione o grant.

Restano il collegamento operativo completo con scope correnti e decisione HUMAN, consegna custodita/installer/attestazione, verifica applicativa, registrazione delle21 DRAFT e review/pubblicazione THS, attivazione source e il vero ciclo CSV. Nessun nuovo run, ACK o oggetto UDP è stato prodotto. Non descrivere13 righe come necessariamente13 nuovi oggetti canonici: dedup/merge e lineage dipendono dagli esiti owner.
