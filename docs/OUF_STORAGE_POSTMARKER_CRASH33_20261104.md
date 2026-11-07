# Crash dopo marker di compattazione33 — 2026-11-04

## Esito qualificato

**POSTMARKER_PROCESS_CRASH_RECOVERY PASS.** Producer
`18b93a7f6f704a6b9f7c959c9f6c088eb5b1cb31`,
[run41864590947](https://github.com/GioNob/ouf-deploy/actions/runs/41864590947),
job126695427394, attempt1:157 test/12 scenari PASS. Nessun secondo laboratorio
nativo; tutti gli undici scenari precedenti conservati e rieseguiti nella suite.
Binario `c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc`
e OCI33 invariati; binding di tutte33patch e dei cinque sorgenti esaminati PASS.

### Fase realmente osservata e recupero

- Volume4, PID28516/startTicks72537, container
  `d17b1316cc5f2409f24f80bcfe1638c03f83f1bfd6083dc249e8bae32adb9171`.
  Nove thread in ptrace-stop `t`; TID28820 fermo all'ingresso `renameat`264,
  `/data/ouf-identity-fixture_4.cpd` verso `.dat`, syscall mai ripresa.
  Fsync marker e directory ritornati0, in quest'ordine, sullo stesso TID.
- `.cpc` vuoto/inode9700681 presente; `.cpd`1048688byte/inode9700679 e
  `.cpx`16byte/inode9700680 conservati. Coppia precedente DAT5243072byte/inode9700548,
  IDX48byte/inode9700555, hash/blocchi immutati prima del crash. Tutti i temporanei
  originali e gli stati frozen/stopped/gated verificati identici.
- Quattro SIGKILL137/non-OOM; tutti i nove thread tracciati morti senza riprendere
  la rinomina. Nuovi container/namespace e regole prima di exec, stesse radici.
  Ripresa nativa: esattamente gli inode `.cpd/.cpx` diventano DAT/IDX, con gli stessi
  bytes/hash/allocazione; marker e temporanei rimossi. Stato identico dopo le probe.
- Recuperati4194384byte DAT e4194304byte allocati. Tutti i needle validi e i volumi
  non selezionati conservati; payload e tombstone dell'orfano rimossi fisicamente.
  Witness `4,0100000000002133aabbcc`,1048593byte,
  SHA256`88750de893a15f19daabf07592666678d399ed4c10feba3bf1d93c2a1d10cd6c`:
  offset4194392→8, identita/cookie/body e GET integri.
- Baseline S38388865byte e metadati completi integri al tentativo1; topology attempt1,
  filer response0→1953byte, volume response0→8397746byte. Orfano404/S3assente;
  11link/36dinieghi ripetuti. Nessun secondo vacuum, PUT di recupero o retry mutativo.
- Suite:60 stati finali effettivi verificati con exit0/non-OOM,111container distinti
  e51morti intenzionali dai receipt,12reti rimosse. Clone tracking esercitato nel
  test Linux sintetico; nella finestra candidata osservata `cloneEvents=[]`.

### Readback, custodia e stato GitHub

Due verifiche indipendenti dell'originale hanno prodotto lo **stesso risultato**:
[readback41865783844](https://github.com/GioNob/ouf-deploy/actions/runs/41865783844),
source9493fb95/job126699497368, e
[verifica41867565360](https://github.com/GioNob/ouf-deploy/actions/runs/41867565360),
source5436f3fe/job126705653060. Entrambe PASS:1364membri,1363checksum esaustivi,
36binding sorgenti sul checkout producer esatto,157test senza skip/12scenari,
ricostruzione sia del rollback precommit sia del rollforward post-marker.

| Archivio | Artifact | Byte | SHA256 |
| --- | --- | ---: | --- |
| Originale | [13343120116](https://github.com/GioNob/ouf-deploy/actions/runs/41864590947/artifacts/13343120116) | 3447908 | `be6f6164165c07bf1e8982cc0a14b8371c46177ba109135cea26134a48e7a4e0` |
| Readback originale annidato | [13342372982](https://github.com/GioNob/ouf-deploy/actions/runs/41865783844/artifacts/13342372982) | 3112583 | `475aa28a5a7f07646b5802ccd3fd07c2ddfd26a55eea65d2a785756dd731e696` |
| Seconda verifica originale annidato | [13343535815](https://github.com/GioNob/ouf-deploy/actions/runs/41867565360/artifacts/13343535815) | 3114469 | `f1bec6c542e499e9a70aa9877addf05630d8329d9831df4b10546020758d5276` |

Receipt completo: [storage-postmarker33-hosted-readback-20261104.json](../evidence/storage-postmarker33-hosted-readback-20261104.json).
Originale e due copie esatte annidate negli artifact fino2027-02-02 (prima scadenza
16:09:39Z). Nessuna custodia durevole Git dei nuovi ZIP dichiarata e nessun readback
ZIP locale; receipt/provenienza persistono in Git, tutti i vecchi archivi preservati.

Osservata discordanza temporanea: API e UI indicavano queued/senza runner mentre
log conclusi e artifact esistevano. GitHub segnalava un
[incidente Actions/Pages](https://www.githubstatus.com/incidents/xr3myzj7ms51),
Actions partial outage dalle16:17Z; compatibile, non prova causale del singolo run.
La seconda verifica acquisisce prima l'originale e registra separatamente lo stato
terminale, senza modificare il readback rigoroso o rilanciare il nativo. Entrambe le
verifiche hanno infine confermato il run nativo completed/success; discordanza risolta
al checkpoint, `nativeTerminalSuccessConfirmed=true`. Nessun criterio allentato.

### Limiti e prossimo singolo passo

Scheduling strumentato esternamente, binario candidato invariato. Il successo
qualifica il crash di processi dopo marker/fsync e prima della prima rinomina,
non power loss, durabilita hardware o RPO/RTO. MiniPET invariato18,3/46=39,78%
(~40% ±10),0/8gate,0/21AT,0/120oggetti reali; MinIO e autorita target invariati.

**Prossimo passo:** crash dopo `.cpd→.dat` e prima di `.cpx→.idx`, osservando la
coppia mista arrestata e verificando che la ripresa completi l'indice coerente senza
servire dati con offset precedenti e senza un nuovo vacuum. Questo intervallo rimane
OPEN; non e implicito nel risultato sopra. Rileggere head/run attivi prima di modificare.

## Preparazione e osservazioni iniziali conservate

Stato iniziale: IMPLEMENTED / NATIVE QUALIFICATION PENDING. Ripresa dal checkpoint
23fc41f569007432ac861c856d9d777ddc74def7, PR54 draft, branch
feat/m2-discovery-complete-profile-20261029. Nessun avanzamento successivo al checkpoint
presente prima dell'implementazione. Tutte le prove precedenti conservate.

## Singolo passo

Dodicesimo scenario separato: un solo vacuum sul volume della fixture con orfano
tombstoned e witness valido successivo. Osservatore esterno ptrace Linux x86_64:
SEIZE/TRACECLONE/TRACESYSGOOD/EXITKILL, lettura syscall/path, nessuna scrittura di
memoria, registri o storage. Intercetta l'ingresso della prima rinomina esatta
`/data/ouf-identity-fixture_N.cpd` verso `.dat`, senza eseguirla. Tutti i thread,
anche creati dopo l'attach, devono essere in ptrace-stop; PID/startTicks/cgroup e
SHA256 del binario invariato sono registrati. Scheduling strumentato, nessuna
pretesa di misura prestazionale.

La fase richiede `.cpc` vuoto, entrambe le copie, DAT/IDX originali con hash, inode,
dimensioni e blocchi invariati; fsync marker seguito da fsync directory entrambi
ritornati 0, osservati nativamente e legati a inode/device. L'osservatore resta vivo
senza riprendere la syscall fino ai quattro SIGKILL del controller. Se fallisce,
EXITKILL impedisce una ripresa involontaria; la fase rimane UNQUALIFIED.

Prima della ripresa si conservano bytes originali dei temporanei e stati
frozen/stopped/gated. Nuova generazione dei quattro servizi dietro gate/firewall,
stesse directory: il rollforward deve promuovere esattamente gli inode delle copie
in DAT/IDX, rimuovere marker e temporanei, recuperare spazio e tutti i needle vivi,
rilocare il witness con GET integro, preservare S3/metadati e i volumi non selezionati.
Nessun secondo vacuum o retry mutativo. Matrice 11 link/36 dinieghi ripetuta.

## Verifica e limiti iniziali

10 nuovi test puri PASS localmente, 12 test precommit precedenti PASS, parsing
Python/YAML PASS. Un ulteriore test Linux esercita ptrace su un figlio sintetico
con thread creato dopo l'attach: non eseguibile su questo host Windows, richiesto
nel runner prima del candidato. Suite precedente 146 test/11 scenari conservata.
La qualifica candidata e il readback indipendente restano PENDING fino a evidenza.

OCI e binary33 invariati, source-binding precedente esteso al nuovo harness.
Semantica ptrace: <https://man7.org/linux/man-pages/man2/ptrace.2.html>.
Il test qualifica crash di processi dopo fsync ritornati, non perdita di alimentazione,
durabilita hardware, RPO/RTO, oppure intervallo fra le due rinomine.

MiniPET invariato18,3/46=39,78% (~40% ±10), 0/8 gate, 0/21 AT, 0/120 oggetti reali.
Nessun VPS/merge/deploy/admission/replay/reset/grant. MinIO invariato.

## Avvio e osservazione GitHub

Producer `18b93a7f6f704a6b9f7c959c9f6c088eb5b1cb31`,
[run41864590947](https://github.com/GioNob/ouf-deploy/actions/runs/41864590947),
job126695427394. Prima osservazione: queued, nessun runner assegnato e nessuno step
eseguito. Nessuna evidenza nativa post-marker acquisita in questa fase; non e un PASS.

Readback separato `storage-generation33-commit-crash-readback.yml`, vincolato a
questo esatto run/commit/attempt1, senza secondo laboratorio. Attende con budget
finito il producer; richiede successo, scarica l'originale con digest GitHub,
verifica ogni membro/checksum e sorgente contro checkout esatto. Ricostruisce sia
il rollback precommit sia il nuovo rollforward, 157 test senza skip, 12 scenari,
60 arresti puliti, bytes/offset/inode e confini rete. Conserva originale e receipt
negli artifact per90giorni. Un timeout/fallimento rimane tale, nessun retry del
vacuum o promozione automatica della qualifica. Questa custodia temporanea non
equivale a un archivio durevole in Git.
