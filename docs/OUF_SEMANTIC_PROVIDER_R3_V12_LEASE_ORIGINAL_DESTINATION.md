# R3 v12 — destinazione originale del lease provider (R-027)

## Esito della ricognizione (task-63, storico)

La ricognizione seguente è conservata come stato del task-63. D-050 ha poi
separato compilatore (task-64), migrazione governata (task-65) e composizione
R3 v12 (task-66). L'implementazione del solo compilatore e le prove del task-64
sono descritte nella sezione «Generazione 2 (task-64)» in fondo; non attestano
una migrazione o una v12 installata.

17 novembre 2026. Worktree `ouf-deploy-task63`, branch
`sprint-01/task-63-lease-original-destination`, HEAD di partenza
`70a5fd8d45c99b4e4520c0f98507586f04b2cc52`, inizialmente pulita.

**Implementazione fermata al punto 4 del task.** Questo documento è una
ricognizione e una proposta; non è una consegna v12, una procedura eseguibile
o una ricevuta di installazione. Non sono stati modificati compilatori,
compositore, verificatori, workflow o runbook. Nessun accesso a VPS, reti,
servizi esterni o segreti.

Le transizioni esistenti esaminate non coprono la sostituzione della tabella
insieme alla migrazione dei binding owner/R3/boot e al loro ripristino.
L'upgrade R3 impone la conservazione del coordinatore condiviso; la migrazione
del guard ammette esclusivamente un nuovo flusso vuoto, conservando tutti gli
oggetti precedenti. Staging e collegamento al boot sono operazioni storiche
vincolate a ricevute e impronte precise, non aggiornatori generici.

Il task prescrive: «Se nessuna transizione esistente può farlo in modo
governato, fermati e descrivi le opzioni [...] non inventare un nuovo canale
privilegiato». Si applica questa condizione, conservando i contratti attuali.
L'estensione di uno di quei contratti rimane una decisione esplicita da
risolvere; non viene presentata come già implementata.

## Problema e regole proposte

Il caso VPS descritto dall'owner è southbound `172.22.0.2` verso
`auth.ouf-lab.it`, IP pubblico dello stesso host. Il DNAT di Docker precede il
filtro `inet forward`: il match sull'IP corrente non trova la destinazione
pubblica nel set `provider_1`. Nel verso di risposta il filtro può ancora
vedere l'indirizzo interno di Caddy. Questa spiegazione è coerente con il
generatore letto nel repository; il comportamento VPS non è stato verificato
nuovamente in questa sessione.

La futura v12 deve autorizzare la tupla originale completa:

- sorgente originale uguale alla sorgente del flusso;
- destinazione originale appartenente al set a scadenza del flusso;
- protocollo TCP e porta di destinazione **originale** autorizzata;
- verso originale con stato `new`/`established`, verso risposta solo
  `established`, distinguendo esplicitamente i versi;
- controllo del set anche sui pacchetti established e sulle risposte, affinché
  la scadenza del lease revochi anche le connessioni già aperte.

Schema di match da qualificare con nft nativo, non testo già validato:

```text
ct direction original ... ct original ip saddr <sorgente> ct original ip daddr @provider_N ... ct original proto-dst <porta> ...
ct direction reply    ... ct original ip saddr <sorgente> ct original ip daddr @provider_N ... ct original proto-dst <porta> ct state established ...
```

Il generatore supporta IPv4 e IPv6: la variante IPv6 dovrà usare gli indirizzi
`ct original ip6` e set `ipv6_addr`, conservando il vincolo su TCP/porta.
L'indirizzo interno di Caddy non deve diventare una nuova destinazione ammessa.

Le stesse regole provider sono oggi emesse nelle famiglie `inet` e `bridge`.
La futura forma deve restare coerente in entrambe; il test instradato fra
bridge non dimostra da solo il percorso di forwarding sulla stessa bridge.
ARP e Neighbor Discovery hanno regole distinte da conservare.

DNS e relay sono `staticFlows`, con coppia sorgente/destinazione e porta
esplicite, senza set provider. La ricognizione non prova l'assenza di NAT per
ogni loro profilo. Non si propone di modificarli incidentalmente: la futura
implementazione dovrà conservare i loro byte oppure qualificare e motivare
un'estensione della semantica originale anche a quei flussi. In questa
consegna tutti i byte rimangono invariati.

## Inventario: generazione, confronto e digest

I percorsi nella tabella sono relativi alla root. Le varianti storiche sono
elencate perché cambiare un blob condiviso altererebbe i replay precedenti.

| Punto | Percorsi e responsabilità |
| --- | --- |
| Generatore delle due famiglie | `tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py`, `materialize()`: regole statiche e provider, set timeout, chain e hook; una sola lista di regole alimenta inet e bridge. |
| Secondo generatore della stessa forma provider | `tools/semantic_guard_extension/extend_empty_lease_guard.py`, `forward_rules()` e `patch()`: due regole IPv4/443 inserite prima del drop, per entrambe le famiglie. |
| Costruzione del JSON kernel e del suo guard | `tools/semantic_transaction_network/build_target_network_policy.py`, `assemble()`: conserva lo scope, aggiunge OIDC e calcola `originalKernelHash` e `configurationHash` delle NIC dal kernel; è il produttore degli input della migrazione append-only. |
| Struttura nft del proprietario | `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py` e `tools/semantic_lease_recovery/nft_seconds_backend.py`: `structure()`, `structure_hash()`, `NftBackend.verify_ownership()`. Rimuovono contatori, expires ed elementi dei set; **conservano gli handle e le espressioni delle regole**. |
| Backend con deadline | `tools/semantic_lease_recovery/deadline_backend.py`: eredita la verifica dal backend seconds, non introduce una diversa impronta. |
| Owner e coordinamento | `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py`, `semantic_provider_lease_coordination.py`, `tools/semantic_lease_recovery/lease_owner_v2.py`: verifica prima/dopo le operazioni e binding `leaseStructureHash` del journal. |
| Supervisione e recovery | `tools/semantic_provider_operation/lease_supervisor.py`, `lease_supervisor_v2.py`; `tools/semantic_lease_recovery/{adaptive_supervisor,continuous_supervisor,resilient_lease_adapter}.py` e rispettivi `_v2.py`: consumano e ricontrollano l'ownership, senza installare tabelle. I supervisori fissano anche i pin delle librerie recovery. |
| Caricamento delle sorgenti owner | `tools/semantic_lease_recovery/activation_core.py`, `activation_core_v2.py`, `tools/semantic_lease_activation/activation_core.py`, `dns_recovery_core.py`: caricano la closure owner vincolata per hash. La v11 permette delta espliciti, non una sostituzione implicita del kernel del boot. |
| Refresh dei set | `tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py`, le copie in `tools/semantic_lease_activation/` e `tools/semantic_lease_recovery/`, più `readback_margin_compiler.py`: validano tramite il generatore, producono flush/add element; non sostituiscono regole o chain. |
| Lettori delle impronte | `tools/semantic_lease_recovery/{reader,resilient_reader,r12_reader}.py`: `structure()`/`lease_projection()` confrontano `expectedStructureHash`. `activate_resilient_r11.py` e `activate_resilient_r12.py` riusano owner e backend sigillati. |
| Guard della preparazione | `tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py`, `validate_global_guard()`: confronta SHA256 del JSON canonico del kernel, tableName, bridge e sorgenti. Le sue tabelle per candidato sono diverse da `ouf_sem_provider`. |
| Uso del guard | `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py` e copia conservata in `tools/acquisition_read_native/vendor/semantic_provider_preexec.py`: chiamano `validate_global_guard()`. `semantic_provider_preexec_native.py` verifica e installa le tabelle del candidato, non sostituisce la tabella globale del lease. |
| Binding delle NIC e dei peer | `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py`, `semantic_provider_peer_bindings.py`: validano la forma di `leaseGuard`. |
| Composizione R3 | `tools/semantic_provider_r3/compose.py`: `SOURCE_MAP`, `SOURCE_MAP_V6`, `REPLACEMENTS_V11`, `SOURCE_MAP_V11`, `lease_guard_hash()`, `check_lease_guard()`. Da v9 `configurationHash` delle NIC e dei peer è l'hash del **JSON kernel**, non il digest dell'intero owner e non il testo nft. |
| Propagazione R3 | Nello stesso `compose.py`: template preparer con kernel/binding; transport con `leaseGuard`; hash sorgenti del broker e supervisore; configurazione runtime; payload `lease.ownerConfigurationSha256` e `leaseStructureHash`; mappa `hashes` di tutti i documenti. |
| Ammissione e loader | `tools/semantic_provider_admission_v2/{broker_v2,preparer_v2,driver_v7}.py`, entrypoint `scripts/semantic-provider-{admission-preparer,deployment-broker,preexec-hook}-v2.py`: closure chiusa, template e kernel sigillati, backend con struttura attesa. |
| Emissione e upgrade | `tools/semantic_provider_r3/install_common.py`, `upgrade.py`, e `scripts/issue-semantic-provider-operation-authorization.py`: manifest degli input, confronto con composizione e autorizzazione, owner esterno e journal QUIESCED. |
| Impronta di migrazione/boot | `tools/semantic_guard_extension/{extend_empty_lease_guard,build_guard_profiles,install_provider_network_guard}.py`: impronta senza handle per template/boot, struttura con handle per lease; hash owner, boot-profile, boot-configuration, receipt e puntatore. `publish_guard_files.py` implementa CAS e ripristino dei file. |
| Lettura e successore boot | `scripts/read-discovery-nft-drift-20261109.py`, `stage-discovery-coordinator-successor-20261109.py`, `activate-discovery-coordinator-boot-20261109.py`: controllano le impronte native/boot, le sorgenti e le ricevute esatte. |
| Installazione boot storica | `scripts/stage-coordinated-provider-owner.py`, `install-coordinated-boot-guard.py`, `bootstrap-coordinated-owner-package.sh`, `bootstrap-coordinated-boot-installation.sh`, `privileged-discovery-preflight-v2.py`: closure e profili storici. Alcune implementazioni del guard sono dipendenze consegnate in snapshot, referenziate per hash, non sorgenti locali da ricostruire arbitrariamente. |
| Altri consumatori, con scope diverso | `tools/m2_discovery_installation_profile/{lease_capsule,lease_service,installed_lease_guard,transport_owner}.py` lega configurazione, source closure e struttura del lease; `tools/semantic_peer_replacement/peer_rebind.py` confronta struttura e footprint e produce sostituzioni di peer per tabelle del candidato. Non è una transizione del kernel globale provider. I lettori in `tools/semantic_target_review/` e `tools/semantic_transaction_profiles/` conservano binding e osservazioni delle rispettive generazioni. |

Sono inoltre presenti source-lock e copie di consegna in
`tools/semantic_cohort_admission/cohort-draft/sources.json`, negli script
storici di quel pacchetto, in `tools/semantic_lease_activation/installed-owner-source-bindings.json`,
nei manifest `tools/semantic_transaction_profiles/` e
`tools/m2_discovery_installation_profile/`, e nelle closure delle precedenti
operazioni applicative. Sono riferimenti storici da conservare, non punti nei
quali riscrivere indiscriminatamente il digest del generatore.

La ricerca ripetibile seguente individua anche i consumatori indiretti e le
fixture; sulla worktree iniziale ha restituito 172 file. Non sostituisce la
lettura dei punti funzionali elencati sopra: alcuni, incluso il generatore
stesso, non contengono il proprio nome o il nome concreto della tabella.

```powershell
rg -l --glob '*.py' --glob '*.sh' --glob '*.md' --glob '*.yml' --glob '*.json' -F -e '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de' -e 'materialize_southbound_kernel' -e 'ouf_sem_provider' tools scripts ops .github docs tests
rg -n 'verify_ownership|structure_hash|leaseGuard|configurationHash|kernel|expectedFootprint' tools/semantic_provider_r3 tools/semantic_provider_operation tools/semantic_lease_recovery tools/semantic_guard_extension
```

### Runbook e contratti di installazione

- `ops/vps/r3-install.sh`, `r3-issue.sh`, `r3-issue-v2.sh` fino a
  `r3-issue-v11.sh`, `r3-upgrade-v2.sh` fino a `r3-upgrade-v11.sh`,
  `r3-operate.sh`, `r3-restore.sh`, `r3-autostart-install.sh`: consegnano
  sorgenti/hash e selezionano il coordinatore; non sono un aggiornamento
  generico del kernel globale. Sono stati solo letti.
- `ops/vps/runtime-v51-install.sh` e `runtime-v51-restore.sh`: altri
  riferimenti storici al compilatore, senza una nuova autorità v12.
- `scripts/deliver-discovery-coordinator-{quiesce,successor,boot}-20261109.sh`,
  `deliver-discovery-nft-drift-20261109.sh` e relativi workflow
  `discovery-coordinator-quiesce.yml`, `discovery-coordinator-successor.yml`,
  `discovery-successor-boot.yml`, `discovery-nft-drift-read.yml`: consegne delle
  operazioni storiche, da non rigiocare.
- `docs/OUF_SEMANTIC_PROVIDER_R3_{COMPOSE_AND_ISSUE,INSTALL,UPGRADE,OPERATE,AUTOSTART}.md`,
  `docs/OUF_SEMANTIC_PROVIDER_LEASE_SUPERVISOR_V2.md`,
  `docs/OUF_SEMANTIC_PROVIDER_LEASE_DNS_TOLERANCE.md` e
  `docs/OUF_DISCOVERY_SUCCESSOR_BOOT_20261109.md`: contratti e limiti letti.

## Perché le transizioni esistenti non bastano

1. `upgrade.observe()` rifiuta il cambio di coordinatore con
   `R3_UPGRADE_SHARED_STATE_DRIFT`: ammette solo il diverso binding DNS.
   `apply()` pubblica la versione, sostituisce l'unità del supervisore e il
   wrapper. Non ha una fase nft né una transazione di migrazione owner/boot.
   Il contratto documentato conserva i journal e non esegue rollback automatici.
   Aggiungere un solo `nft -f` non soddisfa questi vincoli.
2. `install_common.coordinator_state()` richiede l'owner esatto vincolato dagli
   input e il journal corrispondente QUIESCED. Il supervisore v11 legge la
   closure conservata accanto all'owner; il nuovo compilatore copiato sotto
   R3 non aggiorna automaticamente quell'owner o il compilatore del boot.
3. `extend_empty_lease_guard.extension()` richiede `len(newFlows) ==
   len(oldFlows)+1`, prefisso invariato e set vuoti. `rollback()` verifica che
   ogni vecchio oggetto/handle sia identico e rimuove solo tre oggetti aggiunti
   per famiglia. Non può ripristinare regole sostituite. Il suo installer è
   inoltre legato a un owner storico e a un claim specifico.
4. `build_guard_profiles.assemble()` sa legare profili e impronte, ma chiama
   proprio `extension()`: non è una via alternativa per sostituire regole.
5. Il vecchio installer coordinato rifiuta un puntatore già esistente.
   Staging e binding del 9 novembre fissano ricevute, closure e footprint:
   modificare i loro pin o riusare i claim non qualifica una migrazione v12.

Una sostituzione nft atomica, da sola, non è una transazione atomica con file,
autorizzazione R3 e comandi di boot. Occorre mantenere l'assenza di autorità
lease/start durante tutte le fasi, verificare entrambe le famiglie per digest
e definire il recupero dei parziali. Rigenerare gli handle cambia anche il
sigillo nativo del lease; eliminarli dal confronto per far passare il test
indebolirebbe il contratto esistente.

## Versionamento richiesto per la ripresa

Non è stata aggiunta `SOURCE_MAP_V12`. Le composizioni v1–v11 e i loro input
sono intatti. La futura modifica dovrà congelare i blob storici e selezionare
solo da `version >= 12` le nuove sorgenti, compresi gli alias del compilatore.

Ci sono tre digest distinti da non confondere:

1. hash del JSON kernel usato da `leaseGuard` e dal guard condiviso;
2. hash della struttura nft nativa usato da backend/owner/journal;
3. impronta del boot, senza handle, più hash dei file di configurazione e
   delle sorgenti che il boot esegue.

Cambiare il codice del compilatore lasciando identico il JSON kernel cambia
la closure delle sorgenti, ma **non** cambia da solo il digest al punto 1.
La v12 deve dichiarare come lega la nuova semantica/testo delle regole e
aggiornare il verificatore corrispondente, senza cambiare il significato dei
digest v1–v11. Non è stato scelto un nuovo schema al posto dell'owner.

## Test eseguiti e test ancora richiesti

Interprete locale: `C:/Program Files/QGIS 3.40.14/apps/Python312/python.exe`.
I comandi seguenti eseguono soltanto suite esistenti sulla baseline:

```powershell
& 'C:/Program Files/QGIS 3.40.14/apps/Python312/python.exe' -I -B -m unittest discover -s tests -p test_semantic_provider_r3_compose.py -v
& 'C:/Program Files/QGIS 3.40.14/apps/Python312/python.exe' -I -B -m unittest discover -s tests -p test_semantic_provider_r3_upgrade.py -v
```

Risultati: composizione 19/19 superati; upgrade 9 superati e 2 saltati perché
richiedono Linux root. Le prove includono le fixture storiche e il profilo
v11. Non sono una prova della correzione R-027 né un nuovo replay completo
v1–v11 acquisito per v12. Nessuna nuova prova nativa o esecuzione CI.

Dopo la decisione sulla transizione, restano necessari:

- golden dei byte v1–v11 acquisiti prima di modificare la closure;
- testo v12/v11, IPv4/IPv6, porta originale, digest e ownership, con diniego
  per regole alterate e per sorgente/porta/destinazione non ammesse;
- guasti di installazione, readback, pubblicazione e ripristino, inclusi
  timeout dopo commit nft e rilevamento di oggetti estranei;
- test Linux root in `unshare`, client southbound, due bridge, DNAT locale
  dell'IP pubblico: v11 scarta, v12 passa, destinazione originale esterna al
  set scartata, flusso esterno senza NAT ancora ammesso;
- scadenza/svuotamento dei set anche su connessioni established e controllo
  della famiglia bridge separato dal solo percorso instradato;
- aggiunta al workflow esistente
  `.github/workflows/semantic-provider-r3-integration.yml`, già su
  `ubuntu-24.04`, con dipendenze nft/iproute2 e gate root esplicito.

## Domande aperte e opzioni

Occorre scegliere il contratto che migra **insieme** regole e autorità
strutturali; non serve un nuovo consenso generico all'obiettivo R-027.

1. **Estendere l'upgrade R3** con una fase versionata di migrazione del
   coordinatore e del boot. Richiede un piano esplicito di vecchi/nuovi
   profili, sorgenti, puntatore e comandi caricati, sostituzione nft atomica
   sotto lock a CID fermi/lease QUIESCED, verifica per digest e recupero dei
   parziali. Cambia il contratto attuale di conservazione del coordinatore e
   di mancato rollback; non è la sola aggiunta del compilatore v12.
2. **Versionare la transizione del guard coordinato**, separandola
   dall'upgrade R3: sostituzione governata di regole/profili/boot con una nuova
   generazione e ricevuta, poi composizione/emissione/upgrade R3 sul nuovo
   owner. Occorre qualificare la sostituzione e il suo ripristino, invece di
   allargare implicitamente l'attuale operazione append-only. Nessun claim
   storico va riutilizzato.

Entrambe richiedono di definire esplicitamente la relazione fra nuova
semantica del kernel, digest `leaseGuard`, sigillo nativo e ripristino boot.
Nessuna delle due è stata introdotta come canale privilegiato aggiuntivo in
questa consegna. I file esclusi dal task e i dati operativi sono preservati.

## Generazione 2 (task-64)

17 novembre 2026, D-050/R-027. Solo formato, compilatori e prove; nessuna
installazione o migrazione. Stesso branch e HEAD della ricognizione.

### Formato e compatibilità

Il **JSON kernel**, cioè l'oggetto che il documento owner contiene in `kernel`,
mantiene `tableName`, `guardedInterfaces`, `existingInterfaces`, `staticFlows`
e `providerFlows`. Per selezionare la nuova semantica si aggiungono allo stesso
livello entrambi i campi:

```json
{
  "generation": 2,
  "providerFlowMatch": "ORIGINAL_TUPLE"
}
```

L'esempio mostra solo i due campi aggiuntivi, non un kernel completo.
L'assenza di entrambi seleziona la generazione 1. È ammessa anche la coppia
esplicita `generation: 1` / `providerFlowMatch: "CURRENT_TUPLE"`; coppie
parziali, generazioni non intere, sconosciute o combinazioni incoerenti sono
rifiutate. Nessun altro campo nuovo è ammesso. La coppia esplicita di
generazione 1 cambia il JSON e quindi il suo digest; per conservare i digest
storici si conserva il JSON storico **senza aggiunte**.

`tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel_v2.py`
è un modulo nuovo, accanto al generatore storico. Rimuove esclusivamente i due
campi di versione prima di invocare `materialize()` storico: validazione di
forma, esclusione interfacce condivise, indirizzi, eccezioni private, porte e
limiti rimangono quelli del modulo immutato. La generazione 1 restituisce
direttamente l'intero piano storico, compresi schema e byte nft.

Per la generazione 2, dopo la stessa validazione, sostituisce esclusivamente
le due righe provider per flusso: pretende esattamente una corrispondenza per
famiglia e rifiuta derive del generatore storico. Il piano risultante usa
`ouf.southbound-kernel-plan.v2`, riporta `generation` e `providerFlowMatch` e
aggiunge il requisito `NATIVE_BRIDGE_CONNTRACK_REQUIRED`. I flag di prova e
`installed` rimangono falsi: compilare non prova l'esecuzione dei pacchetti.

La funzione **esistente e immutata** `compose.lease_guard_hash()` calcola SHA256
del JSON canonico dell'intero kernel (`sort_keys=True`, separatori `,`/`:`).
I nuovi campi partecipano quindi all'impronta 1, senza inventare una diversa
proiezione o modificare `compose.py`. Il test usa quella funzione reale e
verifica digest diversi fra kernel senza versione e kernel di generazione 2.
Il collegamento ai sigilli owner/boot e la migrazione delle impronte native
restano task-65; l'inserimento nella closure R3 resta task-66.

### Regole emesse

Esempio IPv4, provider_0, sorgente `10.64.0.2`, HTTPS porta originale 443:

```text
ct direction original ct original ip saddr 10.64.0.2 ct original ip daddr @provider_0 ct original protocol tcp ct original proto-dst 443 ct state { new, established } counter accept
ct direction reply ct original ip saddr 10.64.0.2 ct original ip daddr @provider_0 ct original protocol tcp ct original proto-dst 443 ct state established counter accept
```

Le medesime righe sono emesse in `inet` e `bridge`. IPv6 usa `ct original ip6`
per entrambi gli indirizzi e set `ipv6_addr`; protocollo e porta originali
restano vincolati. Non viene ammesso genericamente `ct state established`:
ogni pacchetto, comprese le risposte, deve ancora trovare la destinazione
originale nel set. Lo svuotamento/la scadenza revoca il transito della
connessione; non distrugge il socket o l'entry conntrack.

DNS e relay (`staticFlows`) conservano **esattamente** tutti i byte storici,
così come set, hook, priorità, ARP, Neighbor Discovery e drop. Il test inverte
solo le sostituzioni provider e confronta l'intero testo nft con lo storico.

La famiglia `bridge` richiede conntrack nativo del bridge. Il workflow carica
esplicitamente `nf_conntrack_bridge`; la prova non usa `br_netfilter` come
scorciatoia: disabilita gli eventuali hook iptables/ip6tables/arptables del
bridge **nel namespace privato** e verifica contatori original/reply della
tabella bridge su traffico nella stessa bridge, IPv4 e IPv6. Un fallimento di
caricamento, `nft --check`, installazione o pacchetti è un errore, mai uno skip
quando il gate nativo è abilitato. La compatibilità concreta di questi match
con il kernel Ubuntu 24.04 **non è ancora attestata in questa sessione**.

### Refresh separato

`tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py`
è una variante nuova del `readback_margin_compiler.py`, con import del
compilatore v2. Conserva sottrazione del budget e del tempo trascorso, margine
intero minimo di due secondi, validazione separata di ogni risoluzione,
scadenze finite e diniego dell'intero batch per dati mancanti, storici o
invalidi. Lo schema del piano refresh resta v1: il contratto della transazione
non cambia. Il worker futuro dovrà includere e sigillare esplicitamente questa
nuova closure; i loader e gli owner correnti non sono stati alterati.

La transazione è sempre `flush set` per tutti i set, seguita eventualmente da
`add element` per i valori validati, in entrambe le famiglie. Non contiene
operazioni su regole, chain o tabelle. Tutte le copie storiche del refresh e
`extend_empty_lease_guard.py` sono intatte.

### Prove e stato verificato

| Prova | Copertura | Esito locale |
| --- | --- | --- |
| `tests/test_semantic_lease_kernel_v2.py` | Equivalenza dell'intero piano e byte g1, IPv4/IPv6, flussi combinati/vuoti e limiti; testo g2; statici invariati; dinieghi; digest reale; refresh anche equivalente al readback-margin storico; sei pin SHA256 storici | **10 test PASS**, Python 3.12.12 |
| `tests/test_semantic_lease_dns_tolerance.py` | DNS, owner e closure v11 | **19 test PASS** |
| `tests/test_semantic_provider_r3_compose.py` | Documenti storici v1–v10, closure v11 e binding del kernel | **19 test PASS** |
| Parsing AST dei cinque nuovi file Python; parsing YAML del workflow | Sintassi e runner `ubuntu-24.04` | **PASS** |
| `git diff --check` | Whitespace dei file tracciati modificati | **PASS** |
| `tests/test_semantic_lease_kernel_v2_native.py` + `tests/native_semantic_lease_kernel_v2.py` | Pacchetti reali, nft/ip, conntrack, DNAT e revoca established | **NON ESEGUITA**: host Windows, WSL `E_ACCESSDENIED` |

I pin SHA256 dei sorgenti storici usano i byte di consegna LF; solo per quei
pin viene normalizzato CRLF dei checkout `core.autocrlf`. Il confronto dei
**byte nft generati** e dell'intero piano g1 non normalizza nulla.

La prova nativa avvia `unshare --mount --net --fork`, verifica entrambi i
namespace diversi da PID 1, rende privati i mount e monta `/run` su tmpfs prima
di creare netns nominati. Nessun daemon Docker. Il router di prova ha tre
bridge: `egress`, `servers`, `external`. Southbound è su egress; un server
separato riceve DNAT `198.51.100.10:443 → 10.65.0.2:8443`, così si verifica
anche la porta **originale**; il secondo server è raggiunto direttamente.
Un peer aggiuntivo sulla stessa egress esercita il forwarding bridge nativo.
Tutti gli IP, comprese le destinazioni TEST-NET e private, sono fixture locali
con eccezioni esatte: nessuna risoluzione DNS o rete esterna.

La prova, predisposta ma non ancora eseguita, richiede:

1. Controlli positivi di connettività prima del guard anche per le destinazioni
   e sorgenti poi negate, per distinguere un drop da listener/route mancanti.
2. Generazione 1: DNAT scartato, destinazione diretta e peer bridge ammessi,
   compresi i percorsi diretti/bridge IPv6.
3. Generazione 2: DNAT e percorsi diretti/bridge ammessi; destinazioni
   originali fuori set e sorgenti diverse scartate. Contatori reali delle due
   direzioni in entrambe le famiglie e per entrambi i tipi di indirizzo.
4. Cinque socket già stabiliti (DNAT, diretto e bridge IPv4, diretto e bridge
   IPv6) non scambiano più dati dopo il batch flush-only prodotto dal refresh;
   espressioni e handle delle regole prima/dopo sono identici, contatori esclusi.

Nel workflow esistente `semantic-provider-r3-integration.yml` sono aggiunti
filtri path, test portabili, gate esplicito root:root, dipendenze `nftables` e
`iproute2`, caricamento del conntrack bridge e prova nativa. Runner esclusivo
`ubuntu-24.04`, nessun `self-hosted`. Il gate `OUF_LEASE_KERNEL_V2_NATIVE=1`
rifiuta sistemi non Linux/root:root invece di saltare la prova.

Comandi di validazione locale (PowerShell; `$python64` indica
`C:\Program Files\QGIS 3.40.14\apps\Python312\python.exe`, runtime già presente):

```powershell
& $python64 -I -B -m unittest discover -s tests -p test_semantic_lease_kernel_v2.py -v
& $python64 -I -B -m unittest discover -s tests -p test_semantic_lease_dns_tolerance.py -v
& $python64 -I -B -m unittest discover -s tests -p test_semantic_provider_r3_compose.py -v
git diff --check
```

Comando **predisposto in CI, non eseguito qui** dopo le dipendenze e il gate:

```sh
sudo -n env OUF_LEASE_KERNEL_V2_NATIVE=1 /usr/bin/python3 -I -B \
  -m unittest discover -s tests -p test_semantic_lease_kernel_v2_native.py -v
```

### Punto aperto per la qualificazione

Il criterio nativo rimane aperto finché un runner Ubuntu 24.04 non esegue il
workflow con successo. Non è stata osservata né dimostrata un'incompatibilità
`ct original` nella famiglia bridge: non se ne inventa una, né si presenta il
solo testo come prova di compatibilità. Se il gate fallisce specificamente
per tale incompatibilità, fermare la qualificazione e riportare kernel,
versione nft ed errore esatto; l'alternativa da decidere sarebbe un percorso
provider esclusivamente instradato con guard bridge che neghi il transito
diretto. Non rimuovere la protezione bridge e non ripiegare silenziosamente
sulla tupla post-DNAT. Nessuna alternativa è implementata in questo task.
