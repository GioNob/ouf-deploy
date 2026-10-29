# OUF — Scope consumato; autorizzazione e proposta installativa discovery qualificate

29 ottobre 2026. Il risultato operativo riuscito è `f759d397c000eba5b3113bcfee44bedf215577c81e9c40eccd98616a38714c6d`. [Esito target](../../evidence/m2-discovery-installation-inputs-target-20261029.json), [rifiuto del duplicato](../../evidence/m2-discovery-installation-inputs-duplicate-delivery-20261029.json), [qualifica sorgente PR53](../../evidence/m2-discovery-authorization-source-qualification-20261029.json).

## Esito selezionato e blocco anti-replay

La lettura ha restituito `M2_DISCOVERY_INSTALLATION_REFERENCES_CAPTURED_NOT_AUTHORIZED`, complete=true, Exit=0 e DeliveryExit=0: quattro componenti, nove GET Engine, due metadata privati, 700148 byte. Tutti i contatori di effetti applicativi, IAM/OAuth, SQL, scritture, import e lifecycle sono zero. Gli altri nove peer non sono stati riosservati. La fonte è il JSON/footer incollato dall'operatore; il dossier è una trascrizione minimizzata, non i byte originali del JSON, né una lettura indipendente dei log host o degli inputs privati.

Lo scope `/etc/ouf/deploy-snapshots/m2-discovery-installation-inputs-14e42ac9-20261029-v1` è CONSUMATO. Il successivo tentativo nella directory `/home/oufadmin/ouf-m2-discovery-installation-inputs-delivery.1FN41iD7` ha restituito `POLICY_READ_SCOPE_CONSUMED_NO_REPLAY`, DeliveryExit=1. Il checksum OK prova il download verificato del codice, non una seconda lettura riuscita. Il rifiuto non sostituisce il primo risultato. Non cancellare o ricreare scope e non rilanciare reader/bootstrap/controller. Il launcher corrente è ritirato e termina senza download o accesso al target.

## Riferimenti osservati e lacune

Registry dichiara IAM=true, Gateway auth=true, provider=false e worker=false. Provider client `ouf-semantic`, audience `ouf-api-gateway`, scope `gateway.southbound.invoke`; base `https://ouf-semantic-southbound-v2:10443`, percorsi `/internal/providers/schema-gov/search` e `/internal/providers/schema-gov/fetch`. Issuer `https://auth.ouf-lab.it/realms/ouf`; token endpoint nello stesso realm. Sono riferimenti dichiarati: il provider non è uno dei quattro componenti riosservati e non ne è provata disponibilità, fiducia TLS o ammissione.

I due percorsi Registry `/run/secrets/schema-gov-client-secret` e `/run/secrets/semantic-discovery-owner.key` non sono coperti dai mount osservati. Questo non prova l'assenza dei file nell'intero filesystem e non prova la loro custody. L'import Spring della configurazione è presente; i contenuti effettivi non sono stati letti. APISIX non espone un nome Env di chiave discovery nell'inventario osservato. Le chiavi di read/proposal/delegation/OIDC esistenti non vanno riusate per il nuovo dominio.

MCP dichiara client `ouf-mcp-server`, execute/recovery/policy-bundle su api.ouf-lab.it e mount esatti readonly per credenziale e fingerprint. La discovery Registry dichiara lo stesso workload MCP. Anche qui contenuti, proprietà e custody non sono provati. Nessun valore segreto è richiesto in chat.

## Modifica sorgente conclusa

[PR53](https://github.com/GioNob/ouf-deploy/pull/53), sorgente `1cc920deba64d09d2ed063045f93bbe5541a1a11`, aggiunge al percorso owner firmato e durevole il profilo fisso `ouf.semantic-discovery-authorization.v1`: tre capability request/status/candidates con il solo scope OAuth `ouf.semantic.discovery`. Conserva grant, ruoli, assegnazioni e binding esistenti; nessun permesso di adozione, approvazione o pubblicazione è aggiunto. La conferma HUMAN resta nel percorso nativo. Registrazione, scope OAuth e policy pubblicata restano passaggi distinti.

Su push e PR: 73 test PASS per job, zero errori e zero skip; 23 nuovi e 50 regressioni. Sono usati helper owner fissati, codec Java reale, firme e journal durevoli reali, con trasporti HTTP/IAM e conferma HUMAN dichiaratamente di fixture. Il primo CI ha rilevato Java21 compilato/Java17 sotto sudo: il percorso Java è stato corretto senza indebolire i controlli. Nessuna prova di runtime target o E2E deriva da questi test.

Il compiler puro `tools/m2_discovery_installation_profile/audit.py` accetta esclusivamente gli inputs privati esatti vincolati all'hash: rifiuta questa trascrizione pubblica. Rileva copertura mount mancante/readonly/antenato ambiguo, deriva riferimenti dal capture e richiede un riferimento di chiave discovery distinto. Non legge file o segreti, non emette authority e non autorizza esecuzione. Non è stato invocato sugli inputs privati target.

## Profilo discovery completo: proposta sorgente qualificata

[PR54](https://github.com/GioNob/ouf-deploy/pull/54), commit `db9555c92cd7c71292d6afd102ca151940176d76`, sopra PR53; [evidenza](../../evidence/m2-discovery-complete-profile-source-qualification-20261029.json). Il nuovo `DiscoveryProfile` e `frame.compile_policy` descrivono cinque ruoli file distinti (chiave consultazione, chiave proposal, credenziale provider, chiave discovery, truststore CA pubblico) più configtree DB e directory del token policy rinnovabile. Sono sette mount con ruoli diversi dal vecchio frame proposal. I percorsi, riferimenti di identità e rete sono scelte esplicite dell'owner, senza default target nel codice.

Il profilo preserva le impostazioni estranee alla discovery, impone IAM/auth/provider/worker espliciti, gate applicativo esatto e risorse finite. Le tre chiavi MAC hanno anche identità di contenuto differenti. Riusa tutte le 13 fasi del journal discovery, incluse installazione del trasporto autenticato e nuovo worker distinto; il percorso file-only a 11 fasi non viene adattato spegnendo temporaneamente flag. Il compiler generico, FileOnlyProfile, gate e journal sono byte-identici al checkpoint precedente.

Qualifica push40839724353/job123332897229 e PR40839794969/job123333126587: 87PASS/0errori/0skip per esecuzione (14nuovi test puri e73regressioni), log riletti. I nuovi template/request/mount/context sono fixture sintetiche dichiarate; nessuna osservazione Docker nativa, custodia o chiamata provider è stata eseguita da questa qualifica. Il codice produce una proposta completa, con nativeExecutorIntegrated=false, externalProviderCallsAllowed=false e nessuna authority/start/apply. Reboot/rotazione sono requisiti dichiarati, non meccanismi installati.

## Prossimo lavoro autorizzato

Integrare e qualificare l'osservazione nativa e l'assemblaggio esecutivo della proposta discovery completa sopra i primitive esistenti: conservazione del file/onboarding, DB V1–V10 e aggiunta V11/V12, configurazione effettiva, mount e custody dei due riferimenti mancanti, chiave discovery distinta coerente tra APISIX e Registry, workload provider, TLS/rete/DB e rinnovo/rotazione. Il vecchio profilo file-only e il frame a sette mount del canale proposal non coprono automaticamente questa configurazione: nessun rilassamento dei guard e nessuna semplice accensione dei due flag.

La review di manutenzione dovrà includere pacchetti esatti coordinati Registry/MCP/Gateway, backup/fencing/reconciliation, provenienza e generazioni correnti, più nuova autorità nativa finita dove richiesta. Le catture consumate forniscono provenienza; non ammettono una generazione attuale né rilanciano authority R9/R12. Il pacchetto Registry già qualificato resta selezionato nel [delta](../../releases/m2-discovery-persistent-installation-delta-20261029.json); gli altri pacchetti e il full frame restano da qualificare. Nessuna nuova operazione SSH è pronta da eseguire in questo checkpoint e nessun login/token/finestra va richiesto prima che sia concreta.

Seguono pubblicazione coordinata di descrittori/route/permessi tramite i rispettivi owner e review HUMAN; poi discovery OntoPiA reale tramite chatbot → MCP → Gateway → Registry → provider, stessa idempotencyKey/requestId, snapshot e provenienza canonici, adozione/pubblicazione governate, riavvio/reboot/rotazione/fault e due client reali. Le capability discovery non sono ancora esposte dal connector corrente. I test sorgente non provano operatività stabile.

Farmacie mantiene asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513`, job `677480c8-3d10-44fd-9dad-f72ddeed20a4`, profilo `f3061699-4fde-4085-89c8-bc8703f65686` SUCCEEDED: 61 righe, 10 colonne; codice ministeriale STRING, CAP STRING e tutti i 10 campi OPEN già confermati. Nessun nuovo upload, profiling, budget, resume o acquisizione. M1/G4 acquisiti; M2/G5/G6/G7/D5–D7, otto criteri di stabilità e E2E aperti. Nessun merge, release acceptance, subagente o automazione. Nessun webfetch/Turtle/ontologia locale sostitutivo.
