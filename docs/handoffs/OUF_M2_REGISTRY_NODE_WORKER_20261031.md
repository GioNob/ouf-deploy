# M2 — Registry nativo, token owner e worker sigillato

31 ottobre 2026, Europe/Rome. Sorgentebc82ccef della PR54 draft/unmerged:
tutti e tre i modi nativi e IAM251/33/0skip PASS, report finali letti.
Anche il protocollo esteso PASS457test/54suite/0fail/0skip (834.377s),
PR41165277205/job124431387665, report finale letto. Non è accettazione target/coorte/E2E.

La modalità CI `--registry-worker` sostituisce il predecessore Registry simulato
con DiscoveryNodeOwner e TransportInstallationAdapter concreti. OCI atteso da
baseline indipendente, sigillo rootfs da Registry di controllo separato prima
del candidato/review. Cinque file, configtree DB e token sono letti nativamente.
Il prefisso nativo è conservato nel successivo handoff al worker sigillato.

InstalledTokenOwner usa sorgenti protetti, vere firme Ed25519, journal/lifetime
conservati e TLS pinning/discovery/introspection reali. La CI crea le due maschere
systemd dei writer storici solo dopo averne provato l'assenza; il guard le legge
davvero. Un solo grant iniziale, nessun rinnovo/reset durante le osservazioni.
La revoca finale nell'issuer CI deve negare il readback senza cambiare token o
journal. Il trasporto confronta footprint nft isolato e applica/legge il proprio
tavolo sotto il coordinatore esistente. Il worker usa lo stesso nodo/provider/
parent/child/kernel/inode per materializzazione, tre firme, pubblicazione
create-only, registrazione e un solo start systemd. Java resta fermo al gate.

## Confine OCI e namespace

4286d67d passa l'attestazione Registry, poi il reader privato nega il
config.json containerd root0644. EngineTransportBackend legge esclusivamente
parent/CID/config.json approvati: root:root, regolare0600/0644, un link,
dimensione finita/no-follow, identità descriptor/path stabile e hash fullOCI
firmato. Reader privati e backend originale SHAef0b98c9… restano byte-esatti.

L'errore successivo di ancestry non era spiegato dall'ipotesi alias Docker.
6ab4e4e3 prova che OCI_CREATED usa /proc/<stesso-pid>/ns/net con parent uid/gid10001
dopo exec; il SandboxKey Engine punta allo stesso inode firmato.63d5d2 usa solo
quel riferimento Engine attuale su container esattamente corrispondente,
running+paused, con PID/startTicks/inode verificati prima e dopo. OCI e profilo
firmati conservano il path originale; nessuna ancestry /proc è allentata.
Parità AST di tutti i controlli namespace/NIC/peer/generazione, salvo i due punti
di lettura OCI e namespace. Sei casi di confine e sei owner trasporto PASS locali.

## Profilo distinto per l'installazione completa

Con63d5d2 Registry e trasporto passano; la firma ATTEST del worker è negata alla
scadenza del mandato provider90s.8313e3c introduce un contratto distinto
ouf.discovery-provider-profile-installation-scope.v2 con policy esplicita
REGISTRY_TRANSPORT_AND_SEALED_WORKER_INSTALLATION, massimo iniziale300s entro il
limite300s del protocollo già esistente. V1 conserva il limite90s.

Il nuovo hash richiede una nuova review esatta del componente parent prima dei
candidati. Tre firme create-only, scadenza limitata ai parent/child/gate originali;
nessuna estensione live, rinnovo automatico o adozione di claim consumati.
La nuova CI crea parent/child/gate iniziali300s e token iniziale600s con authority
token300s; gli altri due modi conservano120s. Le nuove prove negano vecchia review,
policy/schema alterati e superamento300s. Dieci test profilo PASS64.304s/0skip.
Nessuna nuova firma o review target emessa.

## Interferenza del lettore con il worker

8313e3c supera installazione/start e riconciliazione della reply manager persa.
La seconda osservazione diretta nega DISCOVERY_WORKER_CHANGED_DURING_OBSERVATION;
il worker è BLOCKED/SAFE_PAUSE_UNPROVEN, attempts1/publications18/reentry1.
Il prefisso acquisito non equivale alla qualifica completa del terzo modo.

Quattro prove con flock kernel reale riproducono un meccanismo concreto: il
lettore prende il lock esclusivo e può negare sia il writer sia la pausa di
sicurezza; Recovery.pause restituisce proprio SAFE_PAUSE_UNPROVEN. Due casi
falliscono sul reader esclusivo, tutti e quattro passano col nuovo reader.
Non è una retrodiagnosi conclusiva del singolo incidente831 o degli UNKNOWN
storici, le cui cause restano aperte.

bc82ccef autentica lo stesso inode approvato prima/dopo senza flock, conserva
ownership, journal completo/stabile e membership positiva uguale nelle due
famiglie/subset del receipt. Journal transitorio, drift e inode sostituito negano
il read; nessun nuovo retry, start, effetto, reset o budget. La generazione firmata,
manager/processo e contatori non regressivi restano obbligatori. I37pin e il
writer non cambiano. Tredici test start/osservazione PASS6.677s/0skip locali.
La conferma nativa della sorgente corretta ora passa tutti e tre i modi
(41165277183, Registry124431388213), report finali letti. Anche revoca IAM
e readback Registry negato senza rinnovo/reset passano. Il protocollo completo
della sorgente corretta PASS457test/54suite/0skip;8313e3c aveva passato453/54.

## Compatibilità IAM e limiti

Il workflow IAM ha scoperto test che iniettavano il compiler corrente in comandi
storici fissati a SHAa8cf18ea…. Byte storici verificati identici a cinque
riferimenti Git, conservati in fixture .source. Comandi/hash delivery e compiler
corrente SHAdcfab9f3… invariati; il test nega i byte correnti prima di sudo.
Nessuna riesecuzione target.63d5d2: IAM41164064718/job124427943260
PASS251test/33suite/0skip, report letto, incluso Keycloak usa e getta reale.
8313e3c passa anche la propria suite IAM251/33/0skip (41164674399/124429568069),
report letto; nessuna qualifica issuer/credenziali target.

HUMAN, realm IAM, immagini/pacchetti e precedenti fasi transizionali sono fixture.
Il trasporto host CI non qualifica Gateway applicativo. Solo l'host usa
cryptography distro per il certificato TLS; capsula/worker conserva -I -B -S,
37pin originali e sola CAP_NET_ADMIN.

Teatri M1/G4 technical8/8 functional6/6 acquisiti. Farmacie stesso SUCCEEDED61righe/
10colonne, ministerial STRING/all10OPEN; nessun upload/profiling/acquisizione.
Coorte corrente/TLS/IAM/DB applicativi, compiler/review/CLI privati, capability,
Farmacie→UDP/all61esiti, reimport/fault/chat/boot/rotazione/due client e cause
UNKNOWN/MCP/worker storiche restano aperti. M2/G5–G7/24AT/8UX/8stability aperti.
Nessun apply target, authority/grant/budget/reset/replay/merge/accettazione.
Vecchi scope consumati; nessun comando operatore pronto.

[Evidenza, tentativi e stato CI](../../evidence/m2-registry-node-worker-native-20261031.json).


Qualifica finale corrente: tre modi nativi PR41165277183, protocollo
PR41165277205/job124431387665457/54/0skip, IAM
PR41165277274/job124431388446251/33/0skip. Tutti i rispettivi log finali letti.
Il workflow generale Chatbot41165277221 era ancora in corso all'ultimo snapshot;
non è ricavato un PASS globale delle Actions.
