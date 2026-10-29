# Caricamento CSV → UDP e capabilities sugli oggetti caricati

## Obiettivo confermato dall’owner

Il percorso ordinario deve essere integralmente governato da chatbot tramite le
capability OUF: upload CSV, profiling, proposta semantica e mapping, review HUMAN,
onboarding, Ingestion e materializzazione UDP con esiti verificabili per ogni riga.
Le capabilities UDP devono essere utilizzabili via chatbot sugli oggetti caricati.
Search non è una fase del caricamento: è una capability UDP da qualificare nel
suo perimetro, separatamente dalla sequenza di ingestion. Il completamento del
caricamento non dipende dall’invocazione di search; un diniego o guasto della
consultazione non annulla gli oggetti persistiti e non riavvia l’acquisizione.
Deve essere ripetibile, resiliente e fluido. Installazione/manutenzione sono un
percorso operatore distinto, da non ripetere a ogni caricamento.

Riferimenti: mini-PET CSV E2E1.1 (24 requisiti/24 test), mini-PET M2v1.3
(8 criteri UX) e gli 8 criteri M2-DISC-STABLE. Tutti rimangono nel denominatore.
Una ricerca semantica riuscita o un import singolo non chiudono M2.

## Stato verificato

- Tecniche8/8 e funzionali6/6 del caso conservato: M1/G4 acquisiti; nessuna terza
  acquisizione Teatri. M2/G5–G7 e accettazione finale restano OPEN.
- Farmacie conserva lo stesso asset/job/profilo: SUCCEEDED,61righe/10colonne;
  codice ministeriale STRING e10campi OPEN già confermati. Nessun nuovo upload,
  profiling o conferma di quelle scelte.
- Nuove sole letture live ouf-admin: `ouf.system.status` HEALTHY/actionRequiredfalse;
  `semantic.search(q=Farmacia,type=CLASS,limit=5)` restituisce `[]`, senza errore.
  Questo non prova assenza di ogni semantica equivalente, disponibilità discovery,
  readiness applicativa o E2E. Non crea/adotta un’ontologia sostitutiva.
- Discovery deve seguire chatbot→MCP→Gateway→Registry→OntoPiA. Le tre capability
  candidate MCP81 sono ancora non pubblicate al checkpoint; il provider target
  resta fermo nell’ultima ricevuta conservata, non riosservato da questa ripresa.

## Incremento implementato

[Deploy54/cb6f2da6](https://github.com/GioNob/ouf-deploy/commit/cb6f2da62f5974ca1a9eaee0352f21e4a7cfaccb)
introduce il compilatore e la transazione create-only dei file del worker:

1. Template/capsule/configurazione/ricetta/unità e ledger iniziali esatti;
   policy, clock iniziali e hash sono coperti da un seal da attestare.
2. Tre attestazioni CREATION_ATTESTATION già emesse e correnti: seal,
   installazione e ammissione della generazione. Il componente non firma,
   non trasforma un’osservazione in ammissione e non contiene CLI di consegna.
3. Stesso parent/child/fase e lock logico; claim durevole esclusivo prima delle
   scritture. File e directory nuovi, nessuna sovrascrittura o adozione di ledger.
4. `installed.json` come ultimo marker visibile al runtime. Reconciliation
   iniziale prima dello start: solo lettura, inode posseduti/custody/hash/byte;
   risposta finale persa riconciliabile, partial write conservata senza replay.
5. Scope parent unico per pubblicazione e start distinto. Vecchio scope start-only
   conservato per file già installati e firmati; capsule37moduli invariata.

Prove locali complete:13nuovi+59regressioni=72PASS/0skip, eseguite per suite in
processi distinti. File, Ed25519,fsync/flock e guard runtime sono reali; ammissioni
applicative, probe delle due generazioni e boot del fixture sono sintetici.
Il primo avvio multi-suite non ha prodotto un riepilogo completo: non è contato;
si usano soltanto i report completi delle otto suite separate e della nuova.
CI del commit:248test selezionati per push/PR, zero skip; entrambi job SUCCESS.
Anche frame OCI e sandbox Docker29.8.1/systemd/DNS/nft passano per push/PR;
sei log letti direttamente. Il fixture sandbox nativo continua a creare i file
manuali: non è ancora la prova nativa del nuovo publisher composto con il
controller completo. [Evidenza e job esatti](../../evidence/m2-discovery-worker-file-publication-qualified-20261029.json).
Nessuna nuova prova target è inferita.

Baseline originale effettivamente consultata: Matrix1.7 DOCX §§1,7 e Registry1.3
DOCX §26/26.3, oltre alle repliche testuali; mini-PET CSV1.1 §§1–6 e mini-PET M2
con criteri di stabilità. Non è una dichiarazione di conformità completa.

## Continuazione: issuer finito e ammissione conservata del provider

[Deploy54/f2dfa9c2](https://github.com/GioNob/ouf-deploy/commit/f2dfa9c2be348cfdfdeb4581228b3d1b1612d763)
collega il reader di ammissione provider al signer esistente e al publisher:

- Il reader riusa il protocollo deployment firmato, la creazione v2 con frame
  autenticato, il mandato firmato di accettazione/rootfs e il registro di consumo
  STARTED. Confronta ricetta indipendente, immagine, artifact, trasporto, runtime,
  OCI applicativo, PID/startTicks/namespace con il peer del worker. Non crea o
  ammette un provider e non ne prova la readiness.
- Lo scope parent separato lega chiave esistente isolata e tre payload esatti.
  Registry owner e probe nativo delle due generazioni sono ricontrollati prima
  della firma; uno snapshot non firmato non raggiunge da solo il signer.
- Claim esclusivo e dispatch per payload precedono ogni uso della chiave. Esiti
  persi/parziali restano consumati; la reconciliation legge soltanto prove attuali,
  firme e inode posseduti. Directory/chiave/scope cambiati bloccano la firma.
- La prova composta arriva da contratti provider firmati a tre attestazioni reali
  e pubblicazione tramite il componente precedente, senza un secondo signer.
  Capsule37moduli invariata; nessun nuovo engine di ammissione o lifecycle.

15nuovi test e72regressioni locali PASS/0skip, report completi. CI263test per
push/PR PASS/0skip; sandbox/frame nativi passati, sei log letti. Ed25519, protocollo,
file/fsync/flock e publisher sono reali; le prove della creazione applicativa e
le osservazioni native/boot del fixture sono sintetiche. Il reader richiede i
contratti di ammissione esistenti: averlo implementato non dimostra che un nuovo
provider li abbia prodotti sul target. La qualifica CI corrente e i suoi limiti
sono nel [record di evidenza](../../evidence/m2-discovery-worker-attestation-qualified-20261029.json).

Lo slot provider del parent copre ora la lettura dell’ammissione conservata.
Il futuro controller deve comporre esplicitamente anche lo scope della propria
installazione: create/start non possono essere nascosti dentro questo reader.
L’issuer è finito e iniziale; boot, rotazione e rinnovo ordinario restano separati.

## Continuazione: un’unica fase iniziale del worker

La fase ATTEST → FILES → REGISTER → START ha ora scope parent unico, claim e
dispatch persistenti per ogni sottopasso. Registrazione manager create-only e un
solo daemon-reload; avvio singolo separato. Una risposta persa viene riconciliata
senza rieseguire il comando. La continuazione esplicita può invocare solo un
sottopasso mai tentato; un effetto parziale/ambiguo blocca il resto. Ogni commit
richiede rilettura esatta, ogni dispatch ricontrolla il proprio record e la stessa
invocazione rifiuta una regressione rispetto al suo ultimo stato conservato.

Lo start richiede le tre prove iniziali; il suo hash coincide con quello
conservato nel NativeEvidenceStore. Dopo l’avvio, l’osservazione mantiene la prova
iniziale e legge il worker corrente senza pretendere il ledger iniziale o
ripristinarlo. Gli osservatori read-only verificano l’inode del lock senza
acquisirne il flock di durata del worker; le mutazioni conservano il fence esclusivo.

CI del sorgente finale:287 test/33 suite per push e PR, zero skip; entrambi
SUCCESS, log completi letti. La prova nativa esercita davvero issuer/Ed25519,
publisher, registrazione, systemd,
Docker29.8.1, DNS/nft, risposta start persa, SIGKILL/rientro e revoca della trust.
Il seed manuale inutilizzato è conservato prima dell’installazione in destinazioni
nuove. I contratti di ammissione applicativa Registry/provider del fixture restano
sintetici: non equivale a provider ammesso sul target, installer completo o E2E.
[Qualifica e limiti](../../evidence/m2-discovery-worker-sequence-qualified-20261029.json).

Il contratto runtime effettivo del provider non è negli input storici e non è
accessibile via MCP. È pronta la [sola lettura target qualificata](OUF_M2_PROVIDER_RUNTIME_CONTRACT_20261029.md),
con quattro GET Engine e metadata selezionati, senza chiavi/credenziali/lifecycle.
Il comando monouso è il solo intervento indispensabile all’owner; dopo l’esito si
prosegue sul provider child. Non è un nuovo passo del caricamento CSV.

## Residuo, in ordine di dipendenza

- Comporre e qualificare nativamente il nuovo provider nella finestra gate-only,
  il suo percorso reale di ammissione/consumo e la ripausa prima di Registry ATTEST.
  Collegare quelle prove reali al nuovo issuer; nessun vecchio provider o mandato
  scaduto può sostituirle.
- Completare il coordinatore/installazione attorno alla fase worker ora qualificata:
  13peer/TLS/IAM/DB/fencing/trust, boot/rotazione con continuità di budget e storia.
  Il solo comando corrente è la lettura metadata del provider nel handoff dedicato.
- Installazione governata e pubblicazione coordinata delle capability, grant
  di uso ordinario e rinnovi persistenti; verificare tutti8 M2-DISC-STABLE.
- Eseguire la vera discovery OntoPiA, confronto/adozione/pubblicazione approvati,
  mapping pinned del CSV, Ingestion/UDP con contabilizzazione di ogni riga,
  provenienza ed esiti per riga. Qualificare separatamente le capabilities UDP
  sugli oggetti caricati, compresa la ricerca tipizzata prevista dai contratti.
- Completare vocaboli/relazioni managed, reimport invariato senza duplicati,
  fault/ripresa/cambio chat, due client reali e dossier HUMAN M2.

Input1868b57c e predecessori rimangono consumati. Nessun replay/reset, nuovo
budget/grant/upload/job/acquisizione, authority runtime, target apply, merge,
subagente o automazione. Repository aggiornati nell’autorizzazione esistente.
