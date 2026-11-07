# SUPERATO — diagnosi ESEGUITA, riuscita e scope CONSUMATO

[Ricevuta 95e66e21 / prova f54c14e3](../../evidence/m2-image-graph-target-20261101.json),
ImageGraphDiagnosticExit=0: 13 match runtime classico→OCI, nessun membro classico
mancante; 22 manifesti assenti di altre piattaforme o ausiliari nonruntime.
Tutti i 9 scope precedenti preservati, cumulativi 10 controlli/35 GET.
NON eseguire il comando sotto. [Passo corrente](OUF_M2_SELECTED_RUNTIME_BYTE_VERIFICATION_20261101.md).
Il successo è diagnostico: configurazioni/layer/diff ID non sono ancora verificati.
Le qualifiche seguenti sono storia, non nuovi comandi da eseguire.

# M2 — diagnosi della struttura degli archivi conservati

1 novembre 2026, Europe/Rome. Sorgente e consegna QUALIFICATI; nuova diagnosi VPS NON eseguita.
[Secondo STOP](../../evidence/m2-image-byte-reconciliation-target-stop-20261101.json):
ImageByteReconciliationExit=1, PRIVATE_IMAGE_BLOB_OR_EXACT_CANONICAL_EMPTY_CONFIG_REQUIRED,
risultato canonico8bec830155b26ee665298b6e35f8bb53d41e1ee8ba0333e4e2209829dfea1380,
9controlli/35GET. Entrambi i verificatori sono consumati; non rieseguirli.

## Dato certo e ipotesi da distinguere

Il ramo fallito richiede un blob presente oppure la sola configempty canonica
ammessa. La ricevuta non espone se manchi un manifesto, una config o altro.
La correzione del data opzionale è valida ma non risolve il caso privato.
Le prove precedenti usavano tredici immagini locali linux/amd64; mancava un
export multipiattaforma con varianti non presenti nello store.

La [specifica OCI layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md#blobs)
ammette riferimenti a blob assenti dal layout. Il contratto [Docker save](https://docs.docker.com/reference/cli/docker/image/save/)
esporta le varianti presenti nello store. Questo rende plausibile un indice
parziale ma NON prova la causa VPS e NON autorizza skip indiscriminato o fetch.

## Controllo diagnostico distinto

Confronta tutti i nove scope esistenti, i due risultati esatti e i profili/claim,
root0700/file0600/no link/metadata stabili. Rilegge i tredici archivi della stessa
catturafa95a719/receipt9733fa7c; autentica ogni archivio con hash e dimensione
originali. Poi apre solo TARheaders e JSON indice/manifesti bounded. Config e
layer NON vengono aperti come membri né espansi: i loro byte attraversano
soltanto lo streaming indifferenziato per l'hash integrale dell'archivio.

Enumera presenza/assenza dei riferimenti, contesto e classe piattaforma:
INDEX_MEMBER, RUNTIME_CONFIG/LAYER, ATTESTATION_CONFIG/LAYER, SUBJECT e classic
member. Verifica digest dei documenti presenti; gli altri membri sono soltanto
presenza/dimensione, non prova dei loro digest/diffID o dell'identità eseguibile.
Confronta il manifest.json classico con le configurazioni/liste layer dichiarate
nei manifesti OCI presenti, senza selezionare un candidato o ammetterlo.
Sotto-grafi di manifesti assenti restano esplicitamente non osservati.

Il report completo rimane privato sul VPS. Pubblico: ordinali non nominativi,
conteggi/classi enum e hash aggregato della prova; niente path, nomi/tag, valori,
descrittori, hash individuali o configurazioni. Nessuna sintesi o ammissione dei
blob mancanti, fetch esterno, Engine, mount host, credenziali, SQL/OAuth, import,
estrazione, processo applicativo o lifecycle. Zero authority/budget runtime.

Nuovo scope fisso /etc/ouf/deploy-snapshots/m2-image-graph-diagnostic-fa95a719-20261101-v1,
root0700/file0600/create-only/fsync. Massimo1controllo/600s; cumulativi10controlli/
35GET. È diagnosi diversa, non nuovo tentativo di verifica o riarmo. STOP e
interruzione conservano ogni file; nessun rilancio o directory alternativa.
Limiti:2GiB/archivio,8GiBset,2048membri,256documenti/1024riferimenti,2MiB/documento,
16MiBmetadata/immagine,profondità4,16MiBreportprivato/64KiBJSONpubblico. Tutto bounded senza retry.

## Riuso Teatri e baseline consultata

Riletti [handoffM1](OUF_M1_COMPLETED_20261026.md),
[dossier26join/13identità/20proprietà/8Cinema](../../evidence/csv-m1-f5-f6-owner-verification-20261026.json)
e [auditM2: metodo, generazioni e riuso concreto](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md).
Si riusano owner/provenance/riconciliazione/recovery; nessuna terza acquisizione
Teatri o riscrittura dei motori. Il contratto specifico del formato Docker è
qualificato separatamente, senza dedurre l'installazione da prove del caso M1.
MiniPETM2v1.3 WP2/WP6/§10; policyresilienzav3 regole3–9/14–18;
GatewayPET1.5 T11/T11.3; AuthorizationPET1.5 separazione attori/human-only.
La diagnosi è manutenzione, non il normale percorso file MCP→Gateway→owner.

M1tecnico8/8 e funzionale6/6 acquisiti, stessa Farmacie61righe/10colonne10OPEN/
ministerialeSTRING. M2/G5/G6/G7 e dueclient restano OPEN; nessun upload/profiling/
acquisizione/attivazione/releaseacceptance. Pipeline fino a UDP con ogni riga,
poi grafo/search e verticali/API scheduler/delta. Publisher/source/membership,
Gatewayproposal, owner/policy/custody/bearer, coorte/pacchetto/review/authority
correnti rimangono distinti e aperti.

## Qualifica sorgente acquisita

[Source5fe74816](../../evidence/m2-image-graph-source-qualified-20261101.json),19moduli.
Push41332158720 e PR41332165729, ciascuno20test/4suite:8struttura/limiti,
5controllo9scope e limiteprivato,5capsula,2Docker29.8.1. Tutti quattro log finali
letti, zero failure/error/skip/ResourceWarning.13export originali e13binding
classic→OCI integri. La fixture pubblica busybox1.37.0 produce un export originale
2.235.392byte/nativea7dbc319… con8manifestaltrepiattaforme+7auxassenti,1runtime
classic/OCI presente, e riproduce esattamente lo STOP col verificatore corrente.
È prova del formato pubblico, NON identificazione della causa privata VPS.

Capsula271.453byte, SHA480c97e51a7377346dba754b6ef8fb4641f9d5bb1c11287159a3e8971ef72a04,
pubblicata inaf237a7eaa20a47f70e36c6ba6e1c8f8db2d38af. ZIPoriginale13093722988,
99.810byte/SHAf71a739f…, scaricato; tutti cinque membri letti e builder locale
identico. Verifica crittografica gh2.97 eseguita sul runner; bundle, statement,
certificato, subject/source/repo/workflow/ref/runner letti e confrontati. Nessun
rerun crittografico locale della trustchain dichiarato. Tutti235sorgenti congelati
e tutti17sorgenti del verificatore precedente restano esatti.

Nuovo launcher71a1d6710767a2e0572f5ea9de19db35d333873e,
SHA36037795acf4292935c3f973a4f5602bd60dc0e275b17796c301dccb3692a737.
Push41332434946 e PR41332441062 SUCCESS, ciascuno28test/6suite, tutti sei log
finali letti, zero failure/error/skip/ResourceWarning. Include7test del launcher e
1consegnaHTTPS esatta,8struttura,5controllo9scope/limiti,5capsula,2Dockerreali.
[Qualifica finale](../../evidence/m2-image-graph-delivery-qualified-20261101.json).
[Comando preparato](../../releases/OUF_M2_IMAGE_GRAPH_DIAGNOSTIC_COMMAND_20261101.sh)
QUALIFICATO e unica azione operatore corrente. Le capsule rigenerate nelle CI
del launcher dichiarano revisioni CI diverse; non sostituirle alla480c97e5
originale consegnata e vincolata al publisher sopra.

## Unica azione operatore ora

Come oufadmin in SSH interattivo sul VPS eseguire UNA SOLA VOLTA il
[nuovo comando](../../releases/OUF_M2_IMAGE_GRAPH_DIAGNOSTIC_COMMAND_20261101.sh).
Il plugin non espone questi archivi amministrativi privati; l'agente non dispone
di SSH. Questa diagnosi di manutenzione resta distinta dal percorso ordinario MCP.
Eventuale password sudo soltanto nel terminale locale; niente login IAM o token.
Non ricattura né duplica gli archivi e non richiede altri9GiB; zero effetti Engine.

Atteso PRIVATE_IMAGE_GRAPH_STRUCTURE_DIAGNOSED_NOT_ADMITTED e
ImageGraphDiagnosticExit=0. Exit0 significa diagnosi completa dei13archivi;
i riferimenti mancanti possono restare numerosi e non sono ammessi. Il JSON
pubblico enumera contesti/classi per ordinali; il report strutturale con riferimenti
resta privato. Restituire SOLO JSONpubblico e footer, niente report/archivi/config.
STOP/interruzione preserva ogni file; nessun rilancio o percorso alternativo.

Dopo il risultato usare i contesti reali per preparare il solo delta verificabile
sul sotto-grafo runtime e sui relativi contratti/source/publisher; niente skip
indiscriminato o nuova acquisizione. Coorte completa, Gatewayproposal/policy-owner,
custody/bearer/pacchetto/review/authority e provaFarmacieUDP restano aperti.
