# M2 — verifica privata degli archivi acquisiti, consegna qualificata

1 novembre 2026, Europe/Rome. Proseguire dalla cattura riuscita e consumata
`fa95a7196e67dee8b0f94f5df223bb51bcf17feeb31bf2022626d0a7be81008e`,
ricevuta canonica `9733fa7c6168a5073f06ea02b89cd015da505ce8bc0bbbbe4f95e614b2b5a4de`.
[JSON dell'operatore e footer](../../evidence/m2-native-image-archives-target-20261101.json):
13 archivi, 2.774.726.144 byte, tutti i sei scope precedenti preservati,
7 controlli/35 GET complessivi, zero contenuti mount/credenziali, Exit0.
L'agente ha letto questa ricevuta pubblica; non ha i file privati o una shell VPS.
**Non eseguire nuovamente la cattura, il suo launcher o i comandi precedenti.**

## Passo pronto

Il nuovo verificatore rilegge sul VPS gli stessi archivi. Verifica indice,
ricevuta, seed originale e sette scope conservati, file regolari root 0400,
hash/dimensioni/metadata stabili, boot e generazioni root/Engine. Non verifica
la liveness o la configurazione applicativa corrente e non invoca l'Engine.

Per ogni archivio verifica il digest richiesto come configurazione classica,
manifesto OCI o indice OCI con selezione univoca linux/amd64; quindi configurazione, layer compressi e diff ID espansi. Controlla anche i blob delle
attestazioni BuildKit e il loro collegamento all'immagine. Questi metadati
ausiliari non diventano immagini eseguibili, firme di un publisher autorizzato,
scan PASS o authority runtime. Niente estrazione su filesystem, import, tag,
container exec, directory dei mount, file di credenziali, SQL, IAM/OAuth o lifecycle.

I riferimenti normativi del formato sono la
[specifica OCI manifest/empty descriptor](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
e il [contratto di storage delle attestazioni BuildKit](https://github.com/moby/buildkit/blob/master/docs/attestations/attestation-storage.md).
Si controllano digest e soggetti, senza dedurre fiducia nel contenuto delle
attestazioni. Formati sconosciuti o ambiguità restano bloccanti.

La verifica conserva il proprio claim, la prova completa e il risultato in
un **nuovo** scope fisso:
`/etc/ouf/deploy-snapshots/m2-image-byte-verification-fa95a719-20261101-v1`.
Directory root 0700 e file 0600, scritture create-only e fsync. Gli archivi
originali e tutti i sette input restano intatti. I contenuti/configurazioni e
gli hash individuali degli archivi non sono esportati in chat.

Profilo finito: un tentativo, 600 secondi, zero nuovi GET Engine; timeout esterno
635s più kill dopo 5s. Limiti: 2 GiB per archivio, 8 GiB input totali, 8 GiB
espansi per immagine/32 GiB complessivi, 256 MiB ausiliari per immagine,
2048 membri tar e header di estensione limitati prima dell'allocazione.
Questo passaggio non duplica gli archivi e non richiede altri 9 GiB liberi.
I contatori diventano 8 controlli/35 GET soltanto dopo la nuova verifica;
nessun budget runtime o contatore precedente viene azzerato/rinnovato.

Al primo STOP, errore o interruzione preservare scope, report e claim. Nessun
retry automatico o replay: risposta persa e risultati parziali si riconciliano.
La scadenza di dieci minuti è un limite operativo, non uno SLA prestazionale
provato su questo VPS.

## Qualifica acquisita

- Sorgente `01f503393443627d49b716dc5eb55e3da2d060cc`, 17 moduli chiusi;
  [qualifica e provenienza della capsula](../../evidence/m2-image-byte-verification-source-qualified-20261101.json).
  Tutti i 235 sorgenti del compilatore congelato restano esatti; questa nuova
  capsula non si presenta come suo sostituto o pacchetto completo di esecuzione.
- Capsula consegnata in `88c1df7311701e5414dc1d79ee108fe991c46f0c`,
  237.245 byte, SHA256
  `70ab863a3bdb9855672acd5bf9af33d1678ad29ba35c0259ce0bf38e6b64337f`.
  Lo ZIP originale 13091359357, 91.026 byte, hash
  `255e8c648e941ebbc97e30845cef0af73d02657d4dddbaa1d98c9be59d372416`
  è stato scaricato e confrontato byte per byte con il builder locale.
  Il risultato della verifica crittografica gh2.97 sul runner e la subject/source/
  repo/workflow/ref/runner identity firmata sono conservati e riletti.
  Nessuna riverifica crittografica locale della trust chain è dichiarata.
- Launcher `bdb49b4f018871930147c7a30d3734724f95a2ac`, SHA256
  `575818ebf7d3607c6ffe2613aa4ed3c536f0fa6f96a1e19154f8370bda82c212`.
  Download HTTPS immutabile e bounded, zero retry; file/FD/hash prima di
  eseguire i byte verificati in Python isolato. Nessun parametro per cambiare
  path, Engine, risultati, authority o budget.
- [Push 41327850081](https://github.com/GioNob/ouf-deploy/actions/runs/41327850081)
  e [PR 41327857484](https://github.com/GioNob/ouf-deploy/actions/runs/41327857484):
  ciascuno **38 test/7 suite**, zero failure/error/skip/ResourceWarning;
  tutti i sei log finali letti. Dodici test formato/limiti/tamper/BuildKit,
  quattro intake, sei reader/controllo durevole, cinque capsula, sette launcher,
  tre Docker29.8.1 reali, una consegna HTTPS reale. I tredici export nativi
  della fixture richiedono tredici indici OCI e includono tredici attestazioni.
  La verifica dei byte non effettua altre chiamate Engine e non modifica gli
  input. I negativi coprono generazioni, scope, link, hash, espansione e header.
- Le prime qualifiche native fallite sono conservate nell'evidenza sorgente:
  indice OCI inizialmente trattato come manifesto e configurazione empty di
  un'attestazione inizialmente trattata come immagine eseguibile. Entrambi
  corretti con regressioni esplicite; nessun effetto o difetto sul VPS dedotto.
  La precedente ispezione HTTPS locale ha avuto timeout di proxy prima di
  qualunque input target; le due consegne HTTPS effettive hosted sono PASS.
- Le capsule rigenerate dalle CI del launcher dichiarano revisioni CI diverse:
  non sostituirle alla capsula originale 70ab… consegnata e qualificata sopra.

Baseline consultata: miniPET M2 1.3 WP2/WP6 e §10; policy resilienza v3
regole3–9/14–18; Gateway PET1.5 T11/T11.3; Authorization PET1.5 §3
(separazione degli actor, default-deny e authority non dichiarata dal client).
Questa è manutenzione circoscritta, distinta dal percorso ordinario CSV.

## Unica azione operatore necessaria ora

Eseguire come `oufadmin`, in SSH interattivo sul VPS, **una sola volta** il
[comando fissato](../../releases/OUF_M2_IMAGE_BYTE_VERIFICATION_COMMAND_20261101.sh).
Il plugin OUF non espone la lettura di questi archivi amministrativi privati;
il canale VPS qualificato richiede l'operatore. Eventuale password sudo solo
nel terminale locale; non serve aprire un login IAM o una nuova review THS.

Atteso: `PRIVATE_IMAGE_BYTES_VERIFIED_SOURCE_AND_RUNTIME_NOT_ADMITTED` e
`ImageByteVerificationExit=0`. Restituire soltanto JSON pubblico e footer.
In caso di STOP/interruzione conservare tutto e non rilanciare. Non inviare
archivi, prova privata, configurazioni, attestazioni incorporate o credenziali.

## Residuo dopo la verifica

Usare le prove private per chiudere l'appartenenza delle immagini alla coorte
effettiva, con i publisher/source lock qualificati e i rispettivi owner.
I candidati OS di riparazione restano separati, non selezionati e non installati.
Gateway private proposal, owner/policy attesi, full custody/workload bearer,
pacchetto completo e review privata correnti, authority HUMAN/dual-role e prova
target rimangono aperti. Nessun PASS di questi gate deriva dal solo hash.

M1/Teatri resta tecnico8/8 e funzionale6/6; stessa Farmacie SUCCEEDED61righe,
10colonne/10OPEN e ministeriale STRING, senza nuovo upload/profiling o replay
di acquisizioni/attivazioni. M2/G5/G6/G7, ripetibilità/fault e due client reali
restano aperti. Il caricamento termina in UDP con ogni riga rendicontata;
seguono grafo/search e verticali/API con scheduler/delta. Nessun merge o release
acceptance è stato eseguito o autorizzato da questa consegna.
