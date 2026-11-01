# M2 — tredici immagini correnti: consegna qualificata, input VPS necessario

1 novembre 2026, Europe/Rome. M1/Teatri resta acquisito: tecnico 8/8,
funzionale 6/6. M2/G5/G6/G7 restano aperti. Farmacie conserva lo stesso
asset/job/profilo SUCCEEDED, 61 righe, 10 colonne, codice ministeriale STRING
e tutti i 10 campi OPEN già confermati. Il caricamento termina in UDP con
gli esiti di ogni riga; seguono grafo/search e verticali/API con scheduler/delta.

## Stato verificato e scopo

Il precedente input dei mount effettivi è riuscito e consumato:
candidate `9f1d571b1f38ace9ec5b5f52b157ed0c4de20c2e1a4553ccc6ae19f9ae04344a`,
receipt `ac206493fa3e9e4d7af098fe8d3a8aec9325162c3167858cff37a0dd57cc6a7b`.
I sei scope precedenti e 22 GET Engine restano conservati. L'agente dispone
della ricevuta pubblica, non dei record privati o di una shell sul VPS.

Manca l'input privato dei byte esatti di Gateway, vendor e sidecar per
completare la composizione della coorte. Questa singola lettura esporta
le 13 immagini native originali selezionate dal roster CID già conservato.
Usa solo `GET /v1.44/images/sha256:…/get` sul socket Engine root autenticato;
verifica boot/processi root, storico e ricevute correnti, senza lookup per tag.
Non riosserva la configurazione o la vitalità dei processi applicativi.

Gli archivi possono includere configurazione dell'immagine e valori di build:
restano sul VPS, directory root 0700, archivi 0400, indice e risultato privati
0600. Non inviare archivi, indice, Engine Env o credenziali in chat.
Nessun contenuto dei mount host viene aperto. Nessuna estrazione/import,
modifica container, SQL, IAM/OAuth, grant, acquisizione, pubblicazione o nuova
autorità runtime. I candidati di riparazione OS già qualificati restano
separati e non selezionati; non sostituiscono le immagini originali.

Nuovo scope fisso:
`/etc/ouf/deploy-snapshots/m2-native-image-archives-9f1d571b-20261101-v1`.
Un tentativo, 1.800 secondi, massimo 13 GET, 2 GiB per immagine e 8 GiB totali.
Servono 9 GiB liberi prima del consumo dello scope; riserva minima 1 GiB.
Timeout esterno 1.835 secondi più kill dopo 5 secondi. Nessun retry automatico:
STOP/interruzione conserva l'input parziale e richiede riconciliazione.
Non cancellare, ripetere o riarmare questo scope o quelli precedenti.
Solo al successo i contatori diventano 7 controlli / 35 GET; sul target
restano per ora 6 / 22. Questi contatori non sono budget runtime.

## Prove e pin immutabili

- Sorgenti originali: `4a1e7e23dd1b09ca4e3752dd148146275f24e415`, 13 moduli;
  [qualifica sorgente](../../evidence/m2-native-image-archives-source-qualified-20261101.json).
- Capsula consegnata nel commit `a7cb69d8bab9bbefc3202f8008e2e744df85a5d5`,
  189.219 byte, SHA256
  `3e281be893cf7c5dc36d6169b8a48a14d979f6a9c32bd523071d8ea4fa6f148f`.
  Byte e fonte firmata già qualificati e conservati; non sostituire la
  capsula con una rigenerazione che dichiari un'altra revisione.
- Launcher qualificato: `1a519f533318d9274950b017b1fa2c4c928c70d1`, SHA256
  `ad50569c294bc39a541f0fdeefea4eac27331c03ebe9ab133dca3ac2adc1dd16`.
  HTTPS con redirect solo HTTPS, dimensione/tempo limitati, nessun retry;
  verifica FD stabile, file regolare senza link e hash prima di eseguire
  la capsula in memoria con Python isolato. L'ispezione non richiede root.
- [Push 41323332553](https://github.com/GioNob/ouf-deploy/actions/runs/41323332553)
  e [PR 41323339276](https://github.com/GioNob/ouf-deploy/actions/runs/41323339276):
  ciascuno 20 test / 5 suite, zero failure/error/skip/ResourceWarning.
  I sei log finali sono stati letti: 4 test socket Unix/peer/archivi privati,
  5 capsula, 7 launcher, 3 Docker 29.8.1 reali, 1 consegna HTTPS reale.
  La fixture nativa usa sei producer e tredici immagini distinte; scope
  precedenti preservati, receipt alterata e generazione root errata negate.
  La consegna reale confronta i byte pubblicati col checkout e ispeziona
  soltanto la capsula; non esegue l'input VPS.
- La nuova attestazione emessa in queste CI riguarda la rigenerazione
  della capsula con la revisione CI, non cambia i byte della consegna
  originale fissata sopra. Nessuna firma publisher concede autorità runtime.

Baseline consultata per questa consegna: miniPET M2 1.3 §§2–4, WP2/WP6 e
§10; policy resilienza v3 §§3–9, 14–18; Gateway PET 1.5 T11/T11.3 e
Authorization PET 1.5 §§1.3–3 (actor separation, HUMAN-only, audit).
È manutenzione installativa circoscritta, non un passaggio ordinario del
caricamento CSV. Nessuna conformità complessiva o accettazione E2E dedotta.

## Unica azione operatore necessaria

Come `oufadmin`, in SSH interattivo sul VPS, eseguire **una sola volta** il
[comando fissato](../../releases/OUF_M2_NATIVE_IMAGE_ARCHIVES_COMMAND_20261101.sh).
Il plugin OUF non espone questa lettura amministrativa dell'Engine Docker;
il canale di esecuzione VPS qualificato richiede l'operatore. `sudo -v`
può chiedere la password locale sudo, da inserire solo nel terminale.
Non serve un login IAM o una nuova decisione THS per questa lettura.

Atteso al successo: `NATIVE_IMAGE_ARCHIVE_CANDIDATES_CAPTURED_NOT_ADMITTED`
e footer `ImageArchiveInputExit=0`. Restituire soltanto JSON pubblico e footer.
In caso di STOP, interruzione o errore: conservare tutto, inviare l'esito
pubblico disponibile e non rilanciare.

## Dopo il risultato

Legare il nuovo indice privato ai typed owner e verificare l'identità nativa,
la provenienza e l'appartenenza di tutti gli artefatti alla coorte effettiva.
Poi completare Gateway private proposal, policy attesa e owner live, custody
e workload bearer, nuovo pacchetto completo di esecuzione/review privata e
authority HUMAN/dual-role correnti. Le authority vecchie restano consumate.
Nessun vecchio controller o compilatore file-first/four-mount sostituisce
questa composizione M2. Tutti questi residui, Farmacie→UDP, gli scenari di
resilienza/ripetibilità e i due client restano aperti. Non ripetere upload,
profiling o acquisizioni Teatri/Farmacie per aggirare i residui installativi.
