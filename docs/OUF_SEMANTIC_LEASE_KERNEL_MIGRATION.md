# Migrazione governata del kernel del lease — D-050, task-65

## Contratto e stato della consegna

`scripts/migrate-semantic-lease-kernel.py` separa la migrazione del kernel
dall'emissione e dall'upgrade R3. Implementa plan, apply, restore e finalize.
La decisione blu/verde di Claude sostituisce la cancellazione/ricreazione N:
**N resta intatta fino a finalize**, compresi tutti gli handle del sigillo.

La consegna è codice e prove locali portabili. Il workflow nativo è predisposto
su `ubuntu-24.04`; la sua esecuzione non è attestata da questo documento.
Nessun accesso VPS, modifica runtime o emissione di autorizzazioni è avvenuto.
`tmp-ref-boot/` resta in sola lettura e fuori consegna. Le prove precedenti
`*semantic_lease_restore_seal*` conservano la dimostrazione del limite della
ricreazione; non rappresentano il ciclo blu/verde positivo.

La sezione «Perché le transizioni esistenti non bastano» di
[R3 v12 / destinazione originale](OUF_SEMANTIC_PROVIDER_R3_V12_LEASE_ORIGINAL_DESTINATION.md)
motiva questa operazione distinta da upgrade R3 ed estensione append-only.
Nessun modulo storico viene modificato.

## Input e precondizioni

Linux root:root, Python `-I -B`, file privati 0600 con un solo link, antenati
root senza scrittura di gruppo/altri, percorsi assoluti senza symlink o `..`.
Le directory nuove sono 0700. nft, systemctl, Docker, Python e unshare sono
legati per percorso/hash; si usa il percorso reale di Python, per esempio
`/usr/bin/python3.12`, anche se il comando storico usava il symlink `python3`.
Nessun input di chiavi private, nessuna firma nuova.

Il manifest `--inputs` è legato da `--inputs-sha256`. Schema esatto:

```json
{
  "schema": "ouf.semantic-lease-kernel-migration-inputs.v1",
  "owner": {"path": "/percorso/N/coordinated-configuration.json", "sha256": "<SHA256>"},
  "bootProfile": {"path": "/percorso/N/boot-profile.json", "sha256": "<SHA256>"},
  "pointer": {"path": "/etc/ouf/coordinated-boot-installation.json", "sha256": "<SHA256>"},
  "units": {
    "guard": {"path": "/etc/systemd/system/ouf-semantic-boot-guard.service", "sha256": "<SHA256>"},
    "docker": {"path": "/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf", "sha256": "<SHA256>"}
  },
  "dispatcherPath": "/etc/ouf/lease-kernel-boot-dispatcher-v1.py",
  "executables": {
    "python": {"path": "/usr/bin/python3.12", "sha256": "<SHA256>"},
    "unshare": {"path": "/usr/bin/unshare", "sha256": "<SHA256>"}
  }
}
```

I segnaposto non sono valori utilizzabili. Il manifest si compone dalle letture
custodite dell'installazione selezionata, senza riscrivere ricevute storiche.
Owner, kernel incorporato, profilo, configurazione boot, closure, journal e
puntatore sono riconciliati per binding. Per il successore storico del
9 novembre il direttorio della ricevuta può differire da quello dell'owner:
la selezione usa `configurationHash` e `bootProfileHash`, non il solo nome.

Argomenti comuni:

```text
--inputs PATH --inputs-sha256 HASH
--install-root R3_ROOT --wrapper WRAPPER --wrapper-sha256 HASH --lock GUARD_LOCK
--docker DOCKER --docker-sha256 HASH --docker-socket unix:///var/run/docker.sock
--systemctl SYSTEMCTL --systemctl-sha256 HASH --nft NFT --nft-sha256 HASH
--generation-directory NEW_GENERATION --output-directory MIGRATION_CLAIM
```

I genitori delle nuove directory devono già esistere, custoditi root. Usare un
genitore stabile riservato alle generazioni, ad esempio
`/etc/ouf/lease-kernel-generations`, e un claim separato. Il dispatcher si trova
fuori dai claim e dalle singole generazioni. Nessun percorso effettivo o hash
VPS è dedotto dagli esempi.

Plan acquisisce gli stessi lock dell'apply. Apply ripete tutte le letture sotto
lock, prima del claim: lock per CID in ordine, flock della directory delle
autorizzazioni (lo stesso dell'issuer), guard del wrapper, lock comune
del coordinatore. Un lock occupato produce HELD. Si riusa il lettore R3 di
`operate.observe()`: autentica la testa per entrambi i ruoli, verifica closure
runtime, storia terminale, configurazioni e CID. Non basta una descrizione
della testa fornita dal chiamante.

Sono obbligatori entrambi i container `created`/`exited`, PID zero, Running
false, restart policy `no`; per entrambi un'epoca terminale non live;
supervisore attivo e WAITING sulla sequenza corrente; nessuna tabella delle
epoche; journal QUIESCED con lease/start false, binding e liste vuote esatti;
struttura N uguale al sigillo dell'owner e set vuoti. Il target deve essere
assente nelle due famiglie e distinto dalle tabelle dei candidati R3.
Una sola famiglia presente è drift, mai uno stato da correggere cancellandola.

## Differenza autorizzata e impronte

`migration.POLICIES` dichiara i passi supportati. Oggi soltanto 1 → 2:

| Campo | Valore derivato |
| --- | --- |
| `generation` | `2` |
| `providerFlowMatch` | `ORIGINAL_TUPLE` |
| `tableName` | nome N seguito da `_g2` |

Il suffisso si accumula nei passi futuri: per esempio `nome_g2_g3`.
Non si tronca né si sostituisce parte del nome; oltre 32 caratteri il plan
nega. Il compilatore valida l'intero kernel. Ogni differenza dal target
derivato nega con `LEASE_KERNEL_DIFF_NOT_ALLOWED`; un passo senza politica
non è supportato. Il plan espone presenza e valore precedente di ogni campo
cambiato. DNS, flussi statici, indirizzi e altri campi rimangono identici,
anche se il compilatore crea i set senza elementi.

| Impronta | Confronto |
| --- | --- |
| JSON kernel | SHA256 del JSON canonico completo, incluso il nuovo nome tabella. |
| Struttura nft | Proiezione storica di `semantic_provider_lease_nft.structure_hash()`: conserva metainfo, handle di table/chain/set/rule ed espressioni; esclude contatori, expires ed elementi dei set. Un controllo separato impone set vuoti. |
| Boot | SHA256 di `stable(tables)`, contratto storico senza handle, contatori, expires e metainfo. Sono sigillati anche profilo, configurazioni, runner e closure. |

Plan compila N+1 in un **nuovo netns usa e getta**, con Python, unshare, nft e
sorgenti legati per hash. Registra struttura template e footprint boot atteso.
Gli handle del netns non predicono quelli assegnati sul target:
`nativeSealAssignment` dichiara esplicitamente questo limite. Apply confronta
il readback vuoto con il footprint indipendente, verifica ancora il sigillo N,
poi registra **tutti** gli handle N+1 in `native-after.json` prima di costruire
e pubblicare l'owner. Da quel momento restore/finalize richiedono il sigillo
N+1 esatto. Nessun handle è escluso dal confronto di ownership per fingere
la coincidenza con un template.

## Fasi e uso della CLI

I suffissi seguenti si aggiungono agli argomenti comuni; non sono comandi da
eseguire automaticamente in questa worktree:

```text
--plan --to-generation 2
--apply --to-generation 2 --plan-sha256 MIGRATION_PLAN_HASH
--restore --migration-directory MIGRATION_CLAIM --plan-sha256 MIGRATION_PLAN_HASH
```

Il digest riguarda il plan interno senza `planSha256`, non l'involucro JSON
di stdout che include `status`. Apply ricompone il plan e pretende lo stesso
digest. Il claim è esclusivo e contiene `plan.json`. Una volta creato,
`doNotRerunApply` vale anche su HELD: conservare il claim e usare restore.

1. Registra evidenza prima/dopo dello staging; crea la directory nuova, copia
   i byte storici e aggiunge compilatore v2, refresh v2 e runner boot v2.
2. Registra l'intento nft con assenza target provata. Un solo `nft -f -` crea
   le nuove tabelle `inet` e `bridge`, con set vuoti. N resta intatta.
3. Acquisisce il readback, sigilla `native-after.json`; completa owner,
   profilo, boot e journal nuovi. Scrive il journal prima dell'owner: anche
   uno staging interrotto lascia un percorso di restore verificabile.
4. Salva `publication.json` con entrambi i byte ammessi per ogni file;
   pubblica CAS delle unità e del puntatore senza modificare N. La ricevuta
   selezionata lega insieme il nuovo owner e il nuovo boot.
5. Esegue solo `daemon-reload`, verifica comandi realmente caricati, PID
   invariati, fragment, tutti i drop-in e proprietà della sandbox. Scrive
   `receipt.json` esclusiva con le tre impronte prima/dopo. Entrambi i journal
   del coordinatore restano QUIESCED, senza lease/start.

Ogni fase ha eventi esclusivi `event-XXXXXX.json` prima/dopo. Su errore la CLI
aggiunge una diagnosi HELD senza stampare stdout/stderr grezzi dei comandi.
Non c'è rollback automatico che nasconda il parziale.

## Boot e conversione delle unità

La ricognizione di `install_provider_network_guard`, `build_guard_profiles`,
`install-coordinated-boot-guard.py` e
`activate-discovery-coordinator-boot-20261109.py` mostra due comandi fissi:
`ExecStart` del guard e `ExecStartPre` Docker. Il solo puntatore non li
aggiornava. Alla prima migrazione diventano:

```text
PYTHON -I -B DISPATCHER --pointer /etc/ouf/coordinated-boot-installation.json --self-sha256 DISPATCHER_HASH
```

Il dispatcher è versionato, root-private, sigillato nel comando e copiato una
volta senza sovrascrittura. Legge lo schema autenticato a cinque campi del
puntatore storico, la ricevuta sigillata e la closure completa, poi esegue
il runner scelto sotto lock comune. Include un osservatore read-only per il
puntatore. Le migrazioni successive riusano gli stessi byte del dispatcher
e delle unità, cambiando il puntatore.

Con `ProtectSystem=strict` il primo cambio aggiunge alla sola unità guard
`ReadWritePaths` del **genitore stabile delle generazioni**, se non già
coperto. Serve per il journal nuovo; il plan espone contesto e percorso.
La sandbox rimane attiva. Le altre proprietà/drop-in sono confrontate dopo
reload; un successivo cambio di questo genitore viene negato. Percorsi
nascosti da ProtectHome o InaccessiblePaths e scope ReadOnly incompatibili
negano prima del claim. Gli altri precomandi Docker mantengono la stessa
sequenza caricata. Nessun restart Docker e nessun servizio avviato.

Il runner storico chiama `owner_cli.read_configuration()`, che pretende otto
sorgenti esatte, fra cui il solo compilatore storico. Il v2 ne importa
relativamente la versione storica; il refresh v2 usa un alias distinto.
Per questo `boot_runner_v2.py` è nuovo e non esegue il loader storico. I byte
storici della closure sono conservati e i nuovi file hanno nomi nuovi.
I quattro riferimenti di `tmp-ref-boot/` non sono sorgenti di consegna.

Al boot, se N+1 è presente ne verifica set vuoti e footprint; se assente
ricostruisce **solo N+1** dalle sorgenti sigillate, in un batch. Un oggetto
estraneo o una sola famiglia presente nega. Come nel contratto storico, una
ricostruzione assegna nuovi handle: journal BLOCKED, lease/start false e
riconciliazione governata necessaria. Il boot non adotta un nuovo sigillo
owner e non avvia il provider. Il ciclo nativo verifica questo limite:
ricostruzione della generazione corretta non equivale ad autorità di esecuzione.

Durante una prima conversione interrotta, unità dispatcher con puntatore
ancora storico negano il boot; restore riporta unità e puntatore precedenti.
Questo parziale non viene presentato come pronto.

## Restore e parziali

Restore legge il plan trattenuto e ne verifica digest, argomenti e percorsi.
Sotto gli stessi lock riverifica provider fermo, epoche, WAITING, journal,
sigillo N e testa R3 **identica** a prima della migrazione. Dopo una nuova
emissione, anche prima dell'upgrade, questo restore non è più ammesso.

Prevalida tutti i file: sono ammessi soltanto i byte N o N+1 derivati.
Ripristina CAS puntatore e unità in ordine inverso, reload e verifica esatta,
poi cancella soltanto la coppia N+1 verificata per sigillo. Una coppia già
assente non viene ricreata. N non viene toccata e deve conservare esattamente
l'impronta originale. `restore-receipt.json` è esclusiva: la seconda esecuzione
riverifica lo stato e restituisce lo stesso esito senza ripetere cancellazioni.

Sono coperti: guasto prima/dopo nft, commit prima del salvataggio readback,
staging incompleto, qualunque combinazione parziale di CAS, reload fallito e
restore interrotto. Per il solo commit-senza-readback l'intento esclusivo prova
l'assenza precedente; restore accetta solo la coppia vuota uguale al footprint
compilato, ne registra una volta il sigillo e solo dopo la elimina. Un handle
diverso dopo un sigillo già registrato viene negato. File, espressioni, set
non vuoti o tabelle estranee sono conservati e producono HELD.

Se il solo claim è incompleto senza un `plan.json` valido, nessun effetto
nft/pubblicazione è ancora autorizzato: la CLI nega la ripresa di quel claim.
Non si sintetizza il plan da una diagnosi parziale.

## Finalize e sequenza R3

1. Stop v11, entrambi i ruoli terminali, lease QUIESCED.
2. Plan/apply 1 → 2. La v11 conserva binding del kernel 1 e **non è più valida
   per start**. Durante la coesistenza N/N+1, provider fermo e set vuoti.
3. Se serve, restore **prima dell'emissione v12**.
4. Emissione e upgrade v12 dal task-66 sul nuovo owner/kernel/leaseGuard.
5. Nuovo plan di finalize e finalize a provider ancora fermo.
6. Start v12 solo dopo aver verificato l'assenza delle tabelle N: gate di
   responsabilità esplicita del task-66, senza modificare qui compositore
   o `operate.py` per simularlo.

Per finalize `--output-directory` indica un nuovo claim separato;
`--migration-directory` conserva quello della migrazione:

```text
--plan --operation finalize --migration-directory MIGRATION_CLAIM --migration-plan-sha256 MIGRATION_PLAN_HASH
--finalize --migration-directory MIGRATION_CLAIM --migration-plan-sha256 MIGRATION_PLAN_HASH --plan-sha256 FINALIZE_PLAN_HASH
```

Gli input originali restano gli stessi. Solo `--wrapper-sha256` viene aggiornato
al wrapper pubblicato dal task-66; il plan finalize ne lega il nuovo valore.
La testa autenticata deve indicare versione R3 almeno 12, hash owner N+1,
struttura N+1 e coordinatore corrispondente. Provider, epoche, journal e set
restano fermi/vuoti; la pubblicazione deve essere interamente N+1.

Il plan dichiara `pointOfNoReturn: true`. `finalize-intent.json` precede il
batch che cancella le due tabelle N e chiude il restore già all'intento.
`finalize-receipt.json` registra esito e impronte; N+1 resta intatta. Se il
comando si interrompe, lo stesso finalize riconcilia **lo stesso** plan:
N ancora esatta oppure assente, N+1 esatta, binding e precondizioni invariati.
Non ripete una cancellazione già avvenuta. Il ritorno funzionale richiede
poi una nuova generazione.

Task-66 deve aggiornare anche loader/alias della closure owner e refresh v2:
gli entrypoint storici conservati non diventano compatibili grazie al solo
nuovo `sourceHashes`. Questa migrazione non emette o compone v12.

## Prove e aggiunta di una generazione

La suite portabile esercita plan/diff, precondizioni, drift, testa incompatibile,
apply/restore, 23 punti di guasto apply, 13 restore, 9 finalize, idempotenza,
parziali inversi di pubblicazione, staging reale dell'adapter con custodia
sostituita e confronto con il verificatore storico importato intatto.

Verifica locale del 17 novembre 2026 con Python 3.12 QGIS su Windows:
18 test migrazione superati; 10 compilatore/refresh v2; 6 sigillo storico;
19 composizione R3; 9 upgrade R3. Totale 62 PASS, 4 test nativi saltati per
piattaforma/opt-in (1 migrazione, 1 sigillo, 2 upgrade). AST dei 10 file Python
nuovi e YAML del nuovo workflow validi; `git diff --check` senza errori.
La CLI operativa su Windows nega con HELD/ROOT_ISOLATED_REQUIRED. Questi
risultati non attestano il batch nft o systemd su Linux.

Il test nativo opt-in `OUF_LEASE_KERNEL_MIGRATION_NATIVE=1` richiede root:root
e non salta dipendenze mancanti. In netns vuoto prova IPv4/IPv6, ciclo
N → N+1 → restore → N con sigillo identico, nuova migrazione seguita da
finalize, errore semantico in fondo al batch con N intatta e N+1 assente,
dispatcher/runner reali, ricostruzione g2 e BLOCKED per nuovi handle, custodia
e CAS reali. Servizi host e Docker non sono modificati. Le osservazioni R3
e systemd sono fixture, non un'installazione su VPS.

Per un passo futuro aggiungere una politica esplicita (campi, valori, versioni
R3 coerenti), compilatore/refresh e runner sigillato compatibili, selezione
delle sorgenti nell'adapter e test nativi/portabili. La sola riga nella tabella
delle politiche non consegna un nuovo passo. Conservare i byte di compilatori,
runner e dispatcher pubblicati. Una variante incompatibile del dispatcher
richiede una nuova conversione governata, senza sovrascrivere il file v1.
