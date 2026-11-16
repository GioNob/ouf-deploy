# D-042 — Antenati dei mountpoint a 0711

## Problema e regola

Task-56, 16 novembre 2026. La diagnosi VPS fornita dall'owner identifica
`run/ouf-semantic-provider` nello strato superiore containerd come
`root:root 0700`: il file bind `adapter.json`, pur essendo `10006:10006 0600`,
non è raggiungibile dall'uid 10006. Lo stesso antenato impedisce all'uid 636
del southbound di raggiungere `trust-bundle.pem`. Questa implementazione non
ha effettuato nuove osservazioni sul VPS.

D-042 modifica D-040 soltanto per le directory nuove, assenti dall'immagine,
che sono antenati e non target di mount:

| Elemento nello strato superiore | Proprietario e modo ammessi dopo la correzione |
| --- | --- |
| Directory nuova `change: ancestor` | `root:root 0711`, nessun xattr |
| Target file | `root:root 0600`, vuoto, un solo link |
| Target directory, incluso il tmpfs southbound | `root:root 0700` |
| Copy-up di directory dell'immagine | Regole D-040 invariate |

0711 concede attraversamento agli uid dei ruoli senza concedere elenco o
scrittura della directory. Non cambia proprietà o permessi dei bind sorgente.
La v2 e tutte le librerie storiche restano invariate per i replay.

## Strumento v3

`scripts/prepare-semantic-provider-b1-rootfs-v3.py` deriva dalla v2. Mantiene
gli input vincolati per hash, l'export limitato, le viste temporanee, il
confronto completo immagine/merged/upper e il sigillatore storico.

Il plan non modifica snapshot, mountpoint o evidenze persistenti. Per ciascun
ruolo espone `comparison.ancestors` con `currentMode`/`expectedMode`,
`currentSeal`, `expectedSeal` e `expectedUpperSeal`. `effectiveSeal` indica
l'aspettativa a 0711. I modi JSON sono numeri interi: 448 = 0700, 457 = 0711.
La previsione esegue il sigillatore storico con una copia privata dei suoi
globali, cambiando soltanto il modo passato all'encoder per gli antenati
approvati. Non modifica il modulo originale né introduce un nuovo algoritmo
di hash. Il sigillo previsto non vale come prova di applicazione.

Come nella v2, le osservazioni usano mount/export temporanei e scratch per
la CLI Docker e la vista dell'immagine, rimossi alla chiusura delle viste.
Il runbook prepara anche la consegna e quattro directory vuote 0700.
Queste attività non cambiano lo strato superiore dei successori.

L'apply richiede `--apply --plan-sha256 <hash>` e:

1. rivalida il piano completo di entrambi i ruoli, container fermi e frame
   completi inclusi; la v3 ammette `created` ed `exited`, PID 0,
   Running/Paused/Restarting/Dead tutti false;
2. valida tutta la differenza prima di aprire gli antenati fisici nel solo
   `upper` identificato dalla medesima procedura containerd della v2;
3. apre ogni componente con `O_NOFOLLOW | O_DIRECTORY`, trattiene gli fd di
   entrambi i ruoli e ricontrolla identità, proprietario, modo, xattr e figli
   dichiarati prima del primo chmod;
4. usa `fchmod(0711)` soltanto per gli antenati esattamente `root:root 0700`
   senza xattr; quelli già 0711 non vengono modificati;
5. riesegue osservazione, differenza D-042 e sigillatore storico senza
   proiezioni. Tutto il piano finale deve coincidere con quello previsto,
   salvo la transizione dichiarata dei modi e dei sigilli.

Qualsiasi stato diverso è negato prima dei chmod. Un guasto o un cambiamento
concorrente durante l'applicazione trattiene le evidenze parziali; non esegue
rollback, cancellazione o ripetizione automatica. L'ambiente operativo deve
mantenere fermi i successori durante l'intera operazione.

L'output esclusivo è:

```text
/var/lib/ouf-storage-migration/semantic-provider-b1-rootfs-20261116-mountpoint-0711/
  chmod-NNN.json             # una ricevuta per ciascun chmod riuscito
  adapter-comparison.json
  southbound-comparison.json
  result.json
```

`result.json` conserva schema `ouf.semantic-provider-b1-rootfs-evidence.v1`
e stato `SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED`. Aggiunge `rule: D-042`
e `chmods` con ruolo, percorso relativo e modi prima/dopo. Le comparison
persistite riportano il sigillo finale realmente osservato. `doNotRerunApply`
resta true: l'idempotenza del chmod non consente di sovrascrivere il risultato
o rimuovere un parziale. Non sono emesse firme né autorizzazioni di avvio.

## Runbook e composizione

`ops/vps/b1-rootfs-v3.sh plan` e `apply <planSha256>` riusano la stessa
consegna privata. Il pin `C=0000000000000000000000000000000000000000` resta
da compilare da Claude dopo review e commit D-001; il runbook si arresta
finché il pin non è impostato. Gli hash della consegna sono già quelli LF
dei sorgenti. Il risultato precedente è quello post-create del 15 novembre,
SHA256 `6f42e319a8c9ba3fe1385b6b2ea814aa40df77ce814b3b4ae60c6afb430905f9`,
ricavato dal pin esistente in `ops/vps/r3-issue-v9.sh`.

`ops/vps/acceptance-v51-g5.sh` deriva da g4: usa il nuovo risultato,
generazione 5, nomi di consegna/output g5 e nega il precedente hash g4 sopra
riportato. Le altre autorità, ricette e closure restano quelle di g4. Il pin
dell'issuer e `ISSUED_AT` sono conservati dal runbook g4. L'issuer v5.1 accetta
il risultato v3 senza modifiche, come verifica il test portabile.

R3 accetta già versioni intere positive e input rootfs/acceptance generici:
nessun modulo R3 richiede modifiche. Il test compone v10 con il risultato v3
e l'accettazione gen 5, verifica i sigilli e nega un sigillo non coincidente.
Restano attivi tutti i controlli storici di identità, ricette, catena,
accettazione e uguaglianza dei sigilli. Il task non genera
`r3-issue-v10.sh` o `r3-upgrade-v10.sh`: Claude dovrà vincolarvi i nuovi input.
Non sono stati cambiati runbook R3, STATE o releases.

## Qualifica

La suite `tests/test_prepare_semantic_provider_b1_rootfs_v3.py` copre i
dinieghi per modo, uid/gid, xattr, symlink, figli estranei, target directory
a 0711 e container attivo; verifica plan senza scritture applicative, hash
del piano, output esclusivo, applicazione e ripetizione senza chmod, evidenze
parziali, compatibilità gen 5 e composizione v10.

Il workflow `.github/workflows/semantic-provider-b1-rootfs.yml` aggiunge la
qualifica nativa con `OUF_B1_ROOTFS_V3_NATIVE=1`, Linux root e Python `-I -B`.
I prerequisiti mancanti causano fallimento, non skip. Riusa Docker 29.8.1
con archivio vincolato per hash e la fixture overlay/runc del task-49:

1. un vero `runc create` sotto umask 077 crea l'antenato assente dall'immagine;
2. un processo nel mount namespace/rootfs del task creato, con uid/gid 10006
   e gruppi supplementari vuoti, tenta il bind sintetico 0600: deve ottenere
   precisamente `PermissionError` con errno EACCES;
3. eliminato il task sintetico, il codice v3 valida la differenza, prevede il
   sigillo ed esegue il chmod tramite fd sullo strato superiore smontato;
4. un nuovo export verifica la differenza finale e il sigillo storico, anche
   dopo una seconda applicazione senza chmod;
5. un secondo vero create riusa l'antenato persistente: il processo con lo
   stesso uid apre e legge il payload. Il sigillo deve coincidere con quello
   restituito da `NodeObservation.observe` sul vero `root.path` Docker.

Il lifecycle è presente esclusivamente nella fixture usa e getta. Il codice
di correzione e sigillatura nativo è quello dello strumento, senza simulare
overlay, fd, chmod, accesso uid o sigillo. Solo i controlli Node su trasporto
e profili estranei a questa prova sono sintetici, come nel task-49.

I test nativi non sono eseguiti sul computer Windows locale. Il loro esito
CI e l'applicazione sul VPS restano da osservare: il codice e la configurazione
del workflow non attestano un PASS CI, readiness applicativa o E2E.
