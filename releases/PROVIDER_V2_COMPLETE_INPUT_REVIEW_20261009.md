# Provider v2: revisione degli input completi, 9 ottobre 2026

La proposta riguarda i sedici documenti privati già preparati nello snapshot `/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-draft-g1yrsazc`. Ricevuta operatore: `evidence/provider-v2-transaction-draft-target-20261009.json`. Non è stata acquisita indipendentemente dal cloud. La preparazione è conclusa e non deve essere ripetuta.

## Decisione richiesta

Accettare questi specifici input di creazione completi e i due sigilli rootfs v1 come base della revisione della transazione firmata. L'accettazione delle immagini e dei componenti custom OUF-LAB è già registrata con approvalRef `OUF_PROVIDER_V2_LAB_IMAGE_REVIEW_20261008_233809` e resta valida nel suo perimetro.

Questa nuova decisione riguarda frame OCI/context/launch, sorgenti montate vincolate per hash, vincoli, preparer, evidenze di provenienza/dipendenze e sigilli dei due CID. Non produce mandati ACTIVE, firme, letture di chiavi, switch del wrapper/allowlist, richieste Docker, lease o accettazione del rilascio. I mandati di ruolo e il pacchetto di esecuzione richiedono il successivo perimetro esplicito, dopo la verifica completa.

## Comportamento proposto

| Proprietà | Adapter | Southbound |
|---|---|---|
| CID | `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67` | `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916` |
| UID/GID | 10006/10006 | 636/636 |
| Root readonly | Sì | No, campo OCI omesso |
| No new privileges | Sì | Sì |
| Memoria e swap | 256 MiB / 256 MiB | 512 MiB / 512 MiB |
| Limite PID | 128 | 128 |
| Sorgenti vincolate | 5 | 3 |
| Mount OCI complessivi | 15 | 13 |
| NIC approvate nella proposta | 2 | 3 |
| Dichiarazioni peer reciproche | 1 | 1 |

Entrambi richiedono un namespace di rete OCI nuovo. Le NIC sono vincolate a bridge/MAC/IP espliciti; i due bridge provider sono `oufsp-int` e `oufsp-egress`. Il southbound ha anche la NIC backend su `br-113b5f0a3c53`. La relazione southbound→adapter usa `172.21.0.2 → 172.21.0.3 TCP9443`; l'ingresso Semantic usa `172.18.0.6 → 172.18.0.14 TCP10443`, con host port1377. La preparazione ha verificato indice/bridge del port host; non ha rivalidato l'identità/MAC del child Semantic.

Il guard installato è vincolato al configurationHash `656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8`. Le due NIC provider di ogni ruolo dichiarano il distinto hash del kernel completo dello stesso owner. Il provider SPARQL e OIDC restano separati per sorgente/destinazione, con set provider vuoti e resolver dell'installazione. Nessuna lease viene autorizzata da questa revisione. DNS rimane quello della specifica installazione; questi indirizzi non sono un default universale OUF.

## Sigilli e frame

| Ruolo | Hash OCI completo | Sigillo runtime rootfs v1 |
|---|---|---|
| Adapter | `816cdcc143d99047151c337eefefe3df29d5ea8a999d50597f1d0b899cd295f4` | `8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73` (3390 entry, 46079786 byte) |
| Southbound | `fc99be8319b210322292a6f468121de97f764800f5e4fb9717e9ac85a9293322` | `52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39` (7458 entry, 255900260 byte) |

Questi sono i sigilli runtime v1 riportati dalla comparazione target già completata. I digest OCI manifest/config e i sigilli portabili/offline hanno significati distinti e non li sostituiscono. Ammissione e sigilli dovranno essere osservati realmente dalla catena node-v4/broker/installer prima del rilascio dell'applicazione.

La chiusura di 29 sorgenti runtime + frame observer è `dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4`. Gli hash seguenti vincolano l'intero corpo di ogni input, senza pubblicare ambiente, argv o contenuti delle sorgenti montate.

| Documento | Adapter SHA256 | Southbound SHA256 |
|---|---|---|
| context | `ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca` | `e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb` |
| dependencyEvidence | `3e66cfb38a24923e1880cd1c28e53abdbd39d09fdca2f2cdfd105115f16b193b` | `5c60aa4def36d5ea09cb01f0b2a76ac93640b9df2878b5cdd5b83232b7db53c9` |
| deploymentConstraints | `2ea27b1d19bf4bd151b3f9199a651a5f693aced13ad9b02490485452aec82ef7` | `e349f6f9c059fa11415b6255a115d4d00972468e892624376b45d43365e718c2` |
| framePolicy | `e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd` | `f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822` |
| launch | `061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943` | `cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39` |
| preparerTemplate | `0a9a12a36b9f28eca2edcb3a2ad2c3d741559abb5d3699029bcc105c287dab53` | `7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894` |
| provenanceEvidence | `0e5de8878e68d8fe555024cd5c0b911361c713e6547f93ebebd243ca34791f9f` | `75fc6a4022bbec82cad2e77e1d48fae3b3af77218edb1f8bade4d46c867dfa8b` |
| template | `bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01` | `0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05` |

## Evidenze e limiti

La CI verifica il percorso node-v4/installer con due runc reali e frame attesi preparati prima della creazione. Il test Docker29.8.1/overlayfs usa un daemon isolato e dimostra due creazioni concorrenti e assenza dei marker applicativi prima del rilascio degli hook. Non è ancora la prova del completo percorso di ammissione della coppia attraverso Docker e il runtime di produzione. Nessuna CI concede autorità al target.

La ricevuta della bozza non osserva il guard nft vivo, lo stato attuale dei CID, i mount live o il child Semantic. Queste osservazioni rimangono obbligatorie ai checkpoint di ammissione. La preparazione conserva sedici input privati, nessun mandato. Non vengono dedotte autorizzazioni da hash, contatori o booleani di CI.

Le evidenze fresche di dipendenze già verificate scadono il **9 ottobre 2026 alle 08:31:48 Europe/Rome**. Issuance e ogni finestra firmata devono restare entro il limite di freshness; una decisione umana non lo estende. Non ripetere scansioni/verifiche ancora valide.

Riferimenti normativi consultati: Matrice L0v1.7; Authorization1.5 AUTH-05/06/07/09/12; Gateway1.5 T16/T17; Semantic1.3 supply-chain159.2. I documenti richiedono separazione delle autorità, default deny e audit; non costituiscono una richiesta umana di firmare o avviare.
