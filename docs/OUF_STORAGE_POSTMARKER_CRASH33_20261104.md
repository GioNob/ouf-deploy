# Crash dopo marker di compattazione33 — 2026-11-04

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
