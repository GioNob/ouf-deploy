> **COMANDO MUTANTE SOSPESO: tentativo VPS consumato con HELD/SLICE_NAME_REQUIRED. Non eseguire nuovamente il blocco sotto.** Correzione qualificata run42308152680; prossima azione soltanto scripts/read-storage-host-slice-held-20261106.py sui3file conservati. Nessun nuovo stop/installer/apply autorizzato da questa diagnosi. Il testo sotto conserva la proposta originale e la decisione già acquisita.

> Decisione acquisita: Giovanni ha autorizzato questa singola operazione in chat. Riferimento GIOVANNI-NONPROD-HOST-CONTAIN-20261106-01; [ricevuta](../evidence/storage-host-containment-operator-decision-20261106.json). Esecuzione VPS ancora pendente. Le diciture di proposta/decisione pendente sotto conservano il pacchetto esatto approvato.

# Contenimento host per backup di test — operazione proposta 2026-11-06

Stato: **QUALIFICATO SU RUNNER, DECISIONE HOST PENDENTE**. Questa proposta non è un'autorizzazione.
OUF non è in produzione e può restare indisponibile; dati applicativi di test. Conservare le configurazioni private e gli originali.
Scopo: fermare le riscritture delle cinque fonti runtime che impedivano il backup, quindi rendere possibile una nuova operazione stop/capture collegata alle prove conservate.

## Binding e prove

- Bozza privata: /var/lib/ouf-storage-host-containment-preparation-20261106-v1/draft.private.json.
- SHA256 bozza: c4d59b3894f59d6679f11d48dbec2a3d7f5cbba6c8aa89bbee78b63e86475d0a.
- [Ricevuta operatore](../evidence/storage-host-containment-prepared-operator-20261106.json). Non rieseguire il preparatore.
- Codice: c742943800252099c56ac60ef448b712d9d007f3,20994byte,SHA256 6d5e41d71150c8e59394002473e6eee728981f540bad94a09fd633f493004004.
- [Qualifica](../evidence/storage-host-containment-qualified-20261106.json): [run42306614307](https://github.com/GioNob/ouf-deploy/actions/runs/42306614307),job128197445773 SUCCESS.3unit test e processi systemd reali;5completamenti naturali,TERM registry,6override,13comandi mutanti,replay respinto.
- Primo fallimento42306145691 conservato; nuova prova giustificata dalla sostituzione del controllo processi con cgroup v2 legato alla unità, inclusi servizi inizialmente inattivi. Non inferisce assenza processi da un errore generico.
- Originale scadenza1794081219 invariata: avvio richiede almeno5400s residui. Nessun rinnovo automatico.
- Installazione e applicazione VPS non ancora eseguite; qualifica Ubuntu24 non è prova del target Debian13.

## Perimetro esatto

| Timer da disabilitare e fermare | Servizio da lasciare completare naturalmente |
| --- | --- |
| ouf-gateway-policy-token.timer | ouf-gateway-policy-token.service |
| ouf-ingestion-policy-token.timer | ouf-ingestion-policy-token.service |
| ouf-onboarding-identity-token.timer | ouf-onboarding-identity-token.service |
| ouf-policy-token@onboarding.timer | ouf-policy-token@onboarding.service |
| ouf-policy-token@udp.timer | ouf-policy-token@udp.service |

In aggiunta disabilitare e fermare con SIGTERM **ouf-registry-token-7cb59501000058b5dc5030ad.service**.
La coppia semantic già masked deve restare invariata.

Su questi sei servizi creare un nuovo file root0600 in /etc/systemd/system/UNIT.service.d/zzzz-ouf-storage-offline-20261106.conf:
```ini
[Service]
Restart=no
SendSIGKILL=no
RuntimeDirectoryPreserve=yes
TimeoutStopSec=120s
```
Eventuali sei directory mancanti vengono create root0755; nessun overwrite/chmod dei file esistenti.
Le modifiche e le disabilitazioni sono persistenti: il programma non le annulla e non riavvia servizi.

Totale massimo previsto:6dropin,6disable,1daemon-reload,5stop timer,1stop registry=13comandi mutanti.
I cinque oneshot non ricevono stop o segnali; attesa naturale massima120s. Registry attesa120s,senza SIGKILL.
Budget complessivo600s,256CLI,32MiB stdout/stderr privati,15s e1MiB percomando.
Il timeout del client può terminare soltanto il proprio processo CLI,non il servizio.
Nuova area esclusiva /var/lib/ouf-storage-host-containment-20261106-v1:claim permanente prima delle query,nessun retry/reset/cancellazione. Qualsiasi HOLD conserva modifiche e journal.

Prima di mutare: verifica10file configurazione,quattro ricevute precedenti,unità e dipendenze correnti,assenza stop hooks tramite12array D-Bus tipizzati vuoti,percorsi e custodia dei dropin.
Dopo: unità inattive,PID0,job vuoto,cgroup esatto vuoto/assente,disablement e override effettivi; due scansioni delle cinque fonti devono coincidere.
Corpi token/config possono essere letti localmente dallo scanner privato delimitato; mai stampati o inviati inGit.

## Decisione richiesta

Riferimento proposto: **GIOVANNI-NONPROD-HOST-CONTAIN-20261106-01**.
Approvare il perimetro sopra, una sola esecuzione con manutenzione esclusiva, lasciando i servizi disabilitati fino a successiva decisione.
È un'estensione ai servizi host: il consenso precedente GIOVANNI-NONPROD-COLD-20261106-01 riguardava35policy Docker/14container e il tentativo è consumato.
Il riferimento registra provenienza operatore,non autentica HUMAN/THS e non concede authority runtime.

## Comando VPS Bash — soltanto dopo la decisione sopra

Installa due file pinned; poi avvia soltanto il contenimento host. Nessun Docker/IAM/PG/S3,capture,merge,deploy o riapertura.
Non eseguire una seconda volta in caso di HOLD.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, subprocess, sys, urllib.request
url = ("https://raw.githubusercontent.com/GioNob/ouf-deploy/"
       "08ff35a29200aa9797e17871c7d96e376baae36e/"
       "scripts/install-storage-host-containment-20261106.py")
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(3463)
if len(raw) != 3462 or hashlib.sha256(raw).hexdigest() != "d2f776ae4fe51993cc694efee9bafc7554f43386a80451423a1701a3fbc28a8a":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
print("Download e SHA256: OK — installazione strumenti", flush=True)
exec(compile(raw, "verified-installer", "exec"), {"__name__": "__main__"})
result = subprocess.run([
    sys.executable, "-I", "-B", "-S",
    "/var/lib/ouf-storage-host-containment-20261106.py",
    "--decision-reference", "GIOVANNI-NONPROD-HOST-CONTAIN-20261106-01",
    "--exclusive-operator-maintenance", "--nonproduction-test-state"])
if result.returncode:
    raise SystemExit("HELD: operazione conservata; non rilanciare.")
PY
```

Installer3462byte/SHA256d2f776ae4fe51993cc694efee9bafc7554f43386a80451423a1701a3fbc28a8a: sintassi e due payload confrontati localmente,nessuna installazione target dichiarata. Tutti i payload vengono verificati prima di scrivere,root0600/O_EXCL/fsync,riuso soltanto se byte e metadati esatti. Reader18228byte/SHAcaac2981e43b96150bc0875405facfc4cb34ad8b188adc210e4ed214bb5bf5b1 e driver dal commit c7429438. Dipendenze precedenti pinned già installate restano invariate.

## Esito e prossimo passo

Atteso HOST_WRITERS_CONTAINED_NEW_STOP_PLAN_REQUIRED. Restituire soltanto JSON redatto stdout.
Questa operazione non prova censimento completo writer,drain,common-cut,revoca globale o accettazione storage.
Successivamente costruire la nuova composizione stop/capture legata a ricevuta host e tentativo Docker conservato: **non rilanciare il vecchio stop**.
Poi archivio cifrato reale → PC Windows → restore isolato → migrazione SeaweedFS e criteri originali.
MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati;120corpi verificati separatamente. Nessun credito aggiunto.
