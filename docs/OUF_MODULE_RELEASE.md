# Rilascio governato di un modulo

La pipeline di deploy approva il profilo di un modulo e sostituisce l'immagine su un servizio già avviato a cancello. Il primo profilo riguarda la PR 63 di Onboarding, commit `8b1251fd9a16d39bd9ff48758c4921a3cc434220`, albero `c961f41375f6a0a15756baea2481e412570fa7b4`. Il CID del predecessore resta disponibile per il ritorno. [Profilo di esempio](../config/module-release/onboarding.example.json)

## Artefatto e installazione

1. Selezionare il run riuscito di `module-ci.yml` per la PR e l'ID dell'artefatto `source-onboarding-governed-image-<runId>`. Il publisher costruisce e prova l'immagine nella CI del modulo. Nel workflow di trasporto indicare i due ID numerici. La variabile di environment `MODULE_RELEASE_INBOX` indica una directory assoluta predisposta nell'installazione. Il runner richiede Python 3.10+ e GitHub CLI.
2. Il trasporto legge da GitHub repository, workflow, esito, PR, SHA di testa, tentativo e appartenenza dell'artefatto al run. Verifica lo SHA-256 dello ZIP originale contro i metadati GitHub. Controlla il manifest del publisher, lo SHA-256 dei byte di `image.tar.gz`, tag, label di provenienza e identità dell'immagine. Per il merge di prova verifica il genitore revisionato e l'albero testato. Pubblica lo ZIP per digest nell'inbox e una ricevuta con le coordinate CI. [Workflow di trasporto](../.github/workflows/onboarding-release-artifact-transport.yml)
3. Preparare il profilo privato dell'installazione a partire dall'esempio. Il custode seleziona il digest GitHub dell'artefatto approvato e l'image ID per lo store Docker di destinazione. Il formato Docker classico identifica il config, containerd può identificare il manifest. Il plan verifica sui byte entrambe le identità ammesse dall'archivio. L'ID di un altro run, un artefatto scaduto o un albero difforme richiedono una nuova selezione verificabile.
4. Completare `oldImage`, nome di servizio, nomi liberi per predecessore e candidato ritirato, tutte le reti, IPv4, alias funzionali, comando applicativo completo con gli argomenti nell'ordine effettivo e contratto HTTP. Le destinazioni di bind e le opzioni provengono dall'inspect del predecessore, vincolato al plan. I percorsi assoluti di inbox, journal, socket Docker ed eseguibile nsenter appartengono al profilo dell'ente. Usare una directory di journal privata del custode, separata dall'inbox scrivibile dal trasporto.
5. Qualificare la compatibilità del predecessore con lo schema e gli effetti di avvio del candidato esatto. Solo dopo questa verifica il custode può impostare `migration.rollbackCompatible` a `true`. Con `false`, plan e apply restituiscono `HELD / MIGRATION_ROLLBACK_BLOCKED` prima del caricamento o del fermo. Nel profilo pubblico i pin di esercizio e la compatibilità restano da compilare.

## Aggancio al task-17b

L'operazione tipizzata è `module-release`. Installare il package da una revisione approvata insieme al codice dell'esecutore, in un percorso controllato da root. L'esecutore risolve internamente l'identificativo del modulo nel suo profilo privato. Il runner passa identificativo, fase e, per apply, l'impronta già approvata. Comandi, percorsi, oggetti Docker e profili arbitrari forniti dal workflow sono fuori dal contratto.

```python
from tools.module_release.operation import apply, plan

# Dopo la verifica 17b dell'approvazione della fase plan.
proposal = plan(installed_profile)

# In una seconda invocazione, dopo la verifica dell'approvazione apply.
receipt = apply(installed_profile, approved_plan_sha256)
```

L'esecutore autentica deployment dell'environment, ref, commit di deploy, run, tentativo, fase e digest. Serializza le operazioni privilegiate sulla stessa installazione anche rispetto agli altri owner. Il modulo gestisce inoltre esclusione per modulo e consumo durevole del singolo piano. Il parametro opzionale `runtime` serve a iniettare il driver nei test portabili.

Il workflow di esempio espone due job manualmente approvati in `ouf-vps-privileged`. Il plan pubblicherà l'output `plan_sha256` solo per `PLANNED`. Il nome del job apply mostra l'impronta all'approvatore. I due segnaposto terminano in errore fino al collegamento dell'esecutore. Configurare nell'environment revisore richiesto e ref protetto. [Workflow di rilascio](../.github/workflows/onboarding-module-release.yml)

## Contratto del plan e dell'apply

Il plan effettua letture locali di archivio, Engine, PID 1 e readiness, senza scritture del modulo. La risposta `PLANNED` contiene `planSha256` e il piano redatto. L'impronta copre profilo, provenienza CI, digest del frame del predecessore, generazione e richiesta di creazione. L'apply ricalcola il piano sotto lock. Copia il payload in un file temporaneo privato verificato sullo stesso stream, carica l'immagine e rilegge image ID e label prima dello stop.

L'apply ferma il vecchio CID, scollega le reti e lo rinomina. Crea una sola volta il candidato con nome di servizio, Config, HostConfig, bind mount, comando e binding di rete del predecessore. Imposta l'image ID verificato. Confronta l'inspect con la baseline prima dello start e verifica reti e configurazione al cancello. Mantiene ENV e label del container anche quando l'immagine ha nuovi valori predefiniti. Ogni delta applicativo causa `HELD`.

La prima versione supporta il cancello storico con trap USR1, restart policy `no`, bind mount espliciti e IPv4 su ogni rete. Per una riallocazione, richiede gli IP originari e conserva gli alias. Docker assegna MAC, identificativi di collegamento e nome DNS breve del nuovo CID. Il passaggio `OomKillDisable` da default nullo a `false` nella CREATE viene controllato per fase con API 1.44. [Regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) · [Precedente del confronto per fase](OUF_MCP_IMAGE_SWAP.md)

| Modalità | Comportamento |
|---|---|
| `none` | Verifica il gate e rilascia il processo applicativo. |
| `dedicated` | Esegue nel candidato l'argv approvato con Docker exec. Richiede exit code zero e ricontrolla PID 1 e handler prima del segnale. |
| `spring-flyway` | Onboarding esegue Flyway durante l'avvio Spring, dopo il segnale. La transizione a readiness completa la verifica di avvio. |

Prima di ogni rilascio il modulo verifica CID, image ID, frame, argomenti del PID 1, eseguibile della shell e handler USR1. Registra l'intento durevole prima dell'unico segnale alla generazione. Per Onboarding verifica quindi Java con comando esatto e `GET /actuator/health/readiness` con HTTP 200 e `status` di primo livello uguale a `UP`, nello stesso namespace di rete e sulla stessa generazione. Come nel task-20c, `acceptStatus` definisce i codici accettati e `jsonStatus` è opzionale per servizi con risposta vuota. [Upgrade storico Onboarding](../scripts/upgrade-onboarding-wide-20261108.py)

## Ricevute e ritorno

Una ricevuta `READY` identifica piano, entrambi i CID e readiness. Un errore dopo l'intento di stop mantiene lo stato di rilascio `HELD`. Il modulo ferma e isola il successore conosciuto, riconcilia anche distacchi parziali, ripristina nome, reti, IP e alias sul CID originario e controlla configurazione e readiness. Il predecessore riavviato ha una propria generazione al cancello e riceve un proprio segnale. La ricevuta riporta `rollback: ROLLED_BACK`, `restoredCid` e `predecessorReadiness: UP` solo a ripristino verificato. I dati applicativi e le registrazioni già persistite seguono la compatibilità qualificata nel profilo.

Il journal conserva baseline privata, intenti, CID creato e `receipt.json` nella directory del digest consumato. L'esecutore conserva anche le risposte di rifiuto antecedenti al consumo. Un crash, un nome occupato da un CID incerto o un ritorno incompleto richiedono riconciliazione del journal con lo stato Docker. In questi casi mantenere l'esclusione e sottoporre il recupero all'owner. Un segnale dall'esito incerto non viene ripetuto. La prova funzionale D-071 di cataloghi, proposta MCP e conferma THS segue il rilascio. [Registro della configurazione](CONFIGURATION_REGISTER.md)

## Prova portabile

```text
python -B -m unittest discover -s tests -p test_module_release.py -v
python -I -B tests/test_vps_workflows_manual_only.py -v
```

Le fixture costruiscono un archivio sintetico e simulano Engine, processo e HTTP. La prova nativa richiede la pipeline integrata, i pin dell'artefatto e il profilo privato qualificato.
