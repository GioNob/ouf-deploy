# Onboarding — approvazione HUMAN autenticata e resolver PostgreSQL limitato

## Due passi completati

1. Adapter server per l'approvazione del comando esatto, collegato ai componenti IAM OUF e al valutatore condiviso di policy. Firma RSA, issuer, audience, identità HUMAN, scope, tenant, freschezza e vincoli di assurance sono verificati nella qualifica.
2. DataSource dedicata al resolver con attese finite e profilo SQL ristretto, provati su PostgreSQL reale, pool saturo e peer TCP che accetta senza rispondere.

Sorgente `d5155899b09dda298494b68cefa7e1f281167652`, [PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54), [contratto](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/docs/STORAGE_RECOVERY_HUMAN_APPROVAL.md).

## Cosa autorizza il comando

Il server deriva attore e riferimento della decisione dal token IAM verificato e dalla policy. La richiesta lega UUID comando, UUID/digest/generazione della lease, motivo e prova esatta della generazione successiva revocata. Header o attributi di capability forniti dal client non bastano. La capability dedicata è `installation.storage.authority.reconcile`, EXECUTE, HUMAN; il codice non la registra né concede.

L'approvazione dura al massimo 30 secondi, entro scadenza del bearer e cinque minuti dall'autenticazione. Ogni tentativo richiede una nuova richiesta autenticata; non si salva un'autorizzazione riutilizzabile. La ricevuta di riconciliazione conserva attore, motivo, decisione e fingerprint; leggere una ricevuta già conclusa non concede un nuovo intervento. Non vengono persistiti token grezzi.

Il resolver continua a ricavare l'esito dalla transazione PostgreSQL registrata. Una policy revocata dopo il preflight SQL blocca la modifica e conserva il marker. Soltanto per il tratto finale sotto il guard del file viene acquisita la nuova lease locale del SDK: nessun SQL o rete, nessuna attesa. Durante quel tratto la pubblicazione di una nuova policy restituisce contesa, non conferma una revoca non ancora applicata; dopo close può procedere.

**Questo è un confine locale al processo.** Distribuzione corrente della policy, revoca globale, sessione IdP e conferma HUMAN tramite UI restano da integrare/qualificare. Non è stato installato un endpoint o un bean operativo. I test chiamano decoder Nimbus reale con firma RSA, converter e bridge OUF: non simulano un IdP remoto o un flusso HTTP/MCP/Gateway completo. I consumer SDK esterni restano ai propri commit.

Una lease non chiusa può bloccare la pubblicazione locale; current() scade dopo 30 secondi ma non sblocca automaticamente una modifica eventualmente ancora in corso. Approved e Prepared vanno chiusi in ogni percorso.

## Privilegi e attese

Il pool del resolver è separato dalla DataSource owner: una connessione, zero idle minime, acquisizione 1s, validazione 0,5s; driver connect 2s, login 3s, socket 2s e cancel 1s. Query 2s, lock 1s, idle transaction 5s. Un solo indirizzo IPv4 letterale evita attese DNS e fallback multi-host. L'esecuzione resta una sola operazione senza rinnovo dei budget; Hikari può tentare internamente la connessione fisica entro l'attesa del chiamante.

TLS è una scelta esplicita verify-full/disabilitato; la prova usa loopback senza TLS. La factory non emette grant né cambia connessione owner. DNS, IPv6, certificati, TLS e failover richiedono qualifica separata.

Il ruolo della fixture è LOGIN, senza superuser, creazione DB/ruoli, replication, bypass RLS o appartenenza pg_monitor; SELECT/UPDATE sulle tabelle owner, lettura policy e CREATE SCHEMA vengono negati. L'unico grant aggiuntivo di funzione è EXECUTE su pg_control_system(). **PostgreSQL17 la espone anche tramite PUBLIC**: per verificare la revoca effettiva la fixture rimuove temporaneamente quell'accesso e ripristina l'ACL iniziale al termine. Gli altri default PUBLIC restano; non si dichiara una revisione completa dei privilegi di produzione.

## Qualifica del commit finale

| Verifica | Esito |
|---|---|
| [Native owner 42049204934](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42049204934), job 127320409146 | **103 scenari nativi + 8 API/storage + 5 HUMAN = 116 PASS**, zero fallimenti/errori/skip |
| SDK condiviso | **12 PASS**, inclusi due nuovi test di contesa concorrente e scadenza |
| Prove conservate | 32 ricevute provider, 17 log JVM, otto ricevute complete degli esiti PostgreSQL |
| Readback nativo locale | **191 membri, 190 checksum, 301 blob Git esatti**, incluso manifest SDK |
| Attese misurate | Pool saturo **1.001ms**; TCP accettato senza risposta **1.003ms**, entro soglia di qualifica 4s |
| [Regressione fisica 42049204791](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42049204791) | producer 127320408530 e readback 127321576514 SUCCESS; **39 membri, 38 checksum, 304 sorgenti, 1.695 file backup, 15 alterazioni respinte** |
| CI sorgente | **8/8 SUCCESS**; generale 473 riportati − 103 skip nativi = **370 eseguiti PASS**; scan bloccante e boot immagine riusciti |
| Checkpoint deploy precedente 7e04721 | **50/50 SUCCESS**; i controlli del nuovo commit documentale sono distinti |

I 14 file modificati sono stati riletti integralmente al commit finale. Il driver fisico precedente non integra il nuovo adapter HUMAN/resolver, e il suo readback non esegue un secondo restore nativo; lo ZIP fisico non è stato nuovamente verificato in locale. Gli artifact di questa qualifica scadono il 3 febbraio 2027; dimensioni e digest completi sono nella ricevuta.

[Ricevuta completa](../evidence/storage-human-approval-qualified-20261105.json), [verificatore dell'archivio nativo](../scripts/readback-human-approval-native-20261105.py). Eseguire Python senza -O dal checkout al commit esatto passando lo ZIP scaricato. Il readback locale verifica bytes, checksum, blob Git, suite, ricevute e deadline osservate; non riesegue la qualifica nativa.

## Correzione verificata

Il primo candidato `a0f95109a2d21b2deef87b01d5aa439c31003cd2` ha avuto due assert nativi falliti perché il grant PUBLIC rendeva inefficace la revoca al solo ruolo. Gli altri 114 test selezionati, i cinque test HUMAN inclusi e i 12 test SDK erano riusciti. Il producer fisico era PASS; il readback negava EXACT_SOURCE_BINDING_SET perché il suo elenco non includeva ancora il SDK aggiunto al producer.

Il commit finale corregge l'ACL della fixture, allinea il verificatore fisico e chiarisce il contratto. Il codice di produzione resta quello del primo candidato. Esiti iniziali, job e cause sono conservati nella ricevuta. Il test Python del formato restore è riuscito usando una directory temporanea nel workspace; il primo tentativo locale era stato limitato dai permessi di cleanup della directory temporanea Windows.

## Prossima coppia e invarianti

Prossimi due passi: collegare il comando alla superficie HUMAN/approval challenge già esistente con conferma dell'intento esatto e audit dei dinieghi; qualificare il percorso HTTP autenticato fino al resolver con configurazione esplicita e disabilitata per default. L'attivazione operativa richiede ancora policy e grant governati, distribuzione delle revoche, custodia e ammissione dell'installazione. Il rebind dopo restart/restore resta negato.

MinIO/source-lock invariati; MiniPET **18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun merge, deploy, grant operativo o riapertura del traffico. Custodia/rollback dello store, budget dopo rollback owner completo, UDP/Ingestion, rollout misto e RPO/RTO restano aperti. PR54 source e deploy draft/open.
