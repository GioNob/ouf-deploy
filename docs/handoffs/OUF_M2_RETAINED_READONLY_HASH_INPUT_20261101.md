# M2 — nuovo input privato: hash dei file regolari montati readonly

1 novembre2026, Europe/Rome. La cattura dei metadati sul VPS è riuscita:
candidato `46f6e6355a1bb133c4f72537f09d7b60250fd4c47265cde24fc1ea792cb366a7`,
risultato pubblico canonico `59935457cad39f7ffe245c8e76a71216b73ebf49bc27c7a20e5bf4e1c7612c0f`.
Entrambe le vecchie directory sono consumate e restano conservate. Non eseguire
nuovamente i vecchi launcher e non cancellare le prove.

Il nuovo input serve per completare le dichiarazioni della custodia privata:
gli hash dei file readonly non erano stati acquisiti. Questo comando **legge
solo i file regolari nell'elenco readonly già fissato**, inclusi eventuali file
di credenziali/chiavi, per calcolarne gli hash in memoria. I valori non vengono
stampati o salvati; gli hash dei singoli file e i percorsi rimangono soltanto nel
nuovo JSON root privato. Non inviare file privati o credenziali alla conversazione.

La sessione non dispone di shell/filesystem del VPS: questa nuova preparazione
richiede l'operatore. Non è un replay del precedente input né un'autorizzazione
all'installazione. Il lavoro sorgente necessario è stato preparato e qualificato
prima di richiedere questo intervento.

## Unico comando necessario sul VPS

```bash
(
  set -e
  sudo -v
  ouf_hash_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_hash_tmp"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/8a302bab5567105f056f617dfb18070907391e43/scripts/launch-m2-retained-readonly-hashes-20261101.sh \
    -o "$ouf_hash_tmp/run.sh"
  printf '%s  %s\n' 52da256f65c610006e055c952806a19bfd8b442fec597589758590413db5ccf5 "$ouf_hash_tmp/run.sh" | sha256sum --check --strict
  bash "$ouf_hash_tmp/run.sh"
)
```

Restituire soltanto il JSON pubblico finale. In caso di `STOP_RECONCILE`,
conservare tutte le directory e non ripetere, cancellare o modificare gli input.
`sudo -v` autentica prima il bootstrap non interattivo. La directory temporanea
contiene soltanto codice pubblico; il launcher verifica in memoria l'hash della
capsula prima di eseguirla con Python isolato.

Nuova directory, creata una sola volta:
`/etc/ouf/deploy-snapshots/m2-retained-readonly-hashes-46f6e635-20261101-v1`.
Risultato atteso: `PRIVATE_READONLY_HASH_CANDIDATES_PREPARED_NOT_ADMITTED`.
Il risultato pubblico contiene contatori e hash aggregati, nessun valore o
hash individuale di credenziali/chiavi. Non dichiara zero letture di credenziali:
eventuali file di quel tipo possono essere letti esclusivamente per hashing.

## Contratto del nuovo passaggio

- Verifica i due scope precedenti, i loro file root:root0600/directory0700,
  l'esatto precedente fallito0922ad73 e il candidato/risultato/seed fissati.
  Anche i frame dei file storici sono verificati alla fine; nessun vecchio
  scope viene riaperto, modificato o usato come nuova autorità.
- Il roster originale di tredici peer mantiene gli alias come etichette.
  Dieci ID mantenuti, intere configurazioni/process pin, boot e peer Engine
  devono ancora corrispondere. Due GET per ID, nessun altro endpoint Engine.
- La verifica dei metadati precede ogni lettura di contenuti. L'elenco è chiuso
  sui file regolari degli alberi readonly già acquisiti; symlink/hardlink,
  cambiamenti di inode/permessi/size/tempi, configurazioni o processi fanno
  fermare la preparazione. O_PATH mantiene l'inode originale e il file viene
  aperto rispetto al descrittore del parent, con nofollow e frame ricontrollato.
- Alias readonly sovrapposti a una sorgente RW dichiarata sono respinti prima
  del primo hash; si confrontano nomi canonici e inode dei parent per rilevare
  anche alias bind. Contenuti mutabili/effimeri, FIFO/socket/dispositivi non
  vengono aperti. Diritti di protocollo readonly restano non dimostrati.
- File condivisi deduplicati per percorso esatto; file vuoti hanno hash esplicito.
  Limiti2048file,8MiB perfile/64MiB complessivi,90s; timeout100s+kill5s.
  Un solo tentativo nuovo, nessun retry. Dimensione e budget residuo verificati
  prima di aprire ogni file per contenuti.
- La storia degli input conserva2controlli/20GET precedenti; questo nuovo input
  aggiunge1tentativo/20GET: massimo3controlli/40GET in questa catena di input,
  non un contatore globale di tutte le osservazioni del progetto. I vecchi clock
  non vengono ripresi/reset e nessun budget/grant runtime viene emesso.
- Nessuna copia/installazione di credenziali, nuova chiave, firma, sessione SQL,
  OAuth, lifecycle, attivazione sorgente, pubblicazione o accettazione. Hash e
  metadati restano candidati; la politica attesa e l'ammissione non si deducono
  dall'osservazione e richiedono la futura review privata completa.

## Sorgenti e qualifica

[Sorgente a3694974](https://github.com/GioNob/ouf-deploy/commit/a369497438c9a13dcb501efb790d84e4af50e43b).
[Capsula 8e08b7d4](https://github.com/GioNob/ouf-deploy/blob/8e08b7d4f0a38e43154608c54da64f8d4b4d5a8f/scripts/prepare-m2-retained-readonly-hashes-20261101.py),87816byte,
SHA256 `35fff36ff18e149e0ae537f0bbf4eeae28b596d358cc046b49f99782e3c2d446`.
[Launcher 8a302bab](https://github.com/GioNob/ouf-deploy/blob/8a302bab5567105f056f617dfb18070907391e43/scripts/launch-m2-retained-readonly-hashes-20261101.sh),
SHA256 `52da256f65c610006e055c952806a19bfd8b442fec597589758590413db5ccf5`.
Cinque sorgenti chiuse; helper e lettori precedenti byte identici. Manifesto della
capsula dichiara esplicitamente letture di contenuti readonly per hashing.
`--inspect-source` verifica/compila soltanto il codice e non legge il target.

CI sorgente [41287945761](https://github.com/GioNob/ouf-deploy/actions/runs/41287945761):
19test/3suite PASS, log finali124792998260 e124792998163 letti; unit10/capsula5/
native4, zero failure/error/skip/ResourceWarning. Docker29.8.1 reale/dieci scratch
processes, root:10001/0440, processo riavviato respinto prima di Engine/hash,
race di contenuti respinta; tre peer/parent e comuni hash di review sono fixture.

CI launcher [41288195129](https://github.com/GioNob/ouf-deploy/actions/runs/41288195129):
23test/4suite PASS (unit19/native4), log finali124793729401 e124793729539
letti, zero failure/error/skip/ResourceWarning. Include byte alterati/vuoti/eccessivi
e argomenti estranei rifiutati prima di eseguire la capsula.

Publisher push [41287940897](https://github.com/GioNob/ouf-deploy/actions/runs/41287940897),
job124792984364/artifact13075393575, ZIP SHA256
`2e776fb002f07db9738e19b48c9276ff2b23e7a575a03862c2f14f67c298ad37`.
Runner gh2.97.0 verifica bundle offline con source/ref/workflow/repo fissati;
log finale letto. Certificato/subject/source/ref/repoID1409074354/owner96419716
scaricati e riletti; byte scaricati identici alla capsula commessa. Nessuna
verifica crittografica locale aggiuntiva dichiarata.

L'intake precedente04920448 e controller v4 (13owner/24letture) sono qualificati:
194test/27suite PASS in41286820490, tutti5log finali letti;28test/3suite PASS in
41286820335, due log finali letti. Runtime binding conserva l'ordine Docker dei
mount, distinto dal vecchio digest storico ordinato per destinazione. I235hash
congelati e le vecchie consegne restano invariati. Non è OUF E2E né ammissione target.

[Dossier hash](../../evidence/m2-retained-readonly-hashes-qualified-20261101.json),
[dossier intake/controller](../../evidence/m2-retained-mount-intake-qualified-20261101.json),
[ricevuta VPS](../../evidence/m2-retained-mount-role-correction-target-20261101.json).
Restano custodia privata completa/artefatti runtime terzi, bearer target,
controller/checkpoint completo e pacchetto/review/autorità correnti, E2E/due client.
M1/Teatri e stessa Farmacie61/10/10OPEN/ministeriale STRING preservati. Nessun
replay upload/profiling/acquisizioni. UDP con tutti61esiti conclude il caricamento,
poi ricerca nel grafo, poi verticali/API e scheduler delta.
