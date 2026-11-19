# R3 v11 - tolleranza DNS del lease (D-043, R-022)

16 novembre 2026. Implementazione locale per `version >= 11`; nessuna installazione,
firma, chiamata DNS reale o operazione sul VPS.

## Contratto DNS

`dns_v2.py` conserva il parser wire, il fallback UDP/TCP, la catena CNAME (massimo
otto alias), la prova negativa SOA e i controlli HTTPS, famiglie e indirizzi del
modulo storico. Ogni resolver della famiglia richiesta lavora in un daemon.
A e AAAA restano sequenziali nello stesso worker e usano la stessa deadline.
Il collector attende tutti i worker oppure la scadenza del budget di 10 secondi.
Un resolver veloce non causa una conclusione anticipata mentre un altro lavora.

Per evitare due finestre sequenziali da 10 s sui due providerFlow di R3,
`observe_many` raccoglie i flussi in una sola finestra di 10 s: un thread per
resolver, senza thread aggiuntivi per flusso. Ogni worker percorre i flussi della
propria famiglia e risolve A/AAAA/CNAME per ciascuno. EÃŒâ‚¬ un limite complessivo piÃƒÂ¹
restrittivo del budget per flusso: nessuna query puÃƒÂ² prolungarlo. Un worker ÃƒÂ¨
utilizzabile solo quando termina; un flusso incompleto non contribuisce indirizzi
o TTL. Un errore di integritÃƒÂ  termina subito quel worker e prevale sugli errori
di disponibilitÃƒÂ  anche negli altri flussi.

Sono tollerati esclusivamente questi codici di mancata risposta:

- `DNS_RESOLVER_TRANSPORT_FAILED`, `DNS_DEADLINE_EXPIRED`;
- `DNS_TCP_RESPONSE_INCOMPLETE`, `DNS_TCP_RESPONSE_TRUNCATED`;
- `DNS_EMPTY_ANSWER_WITHOUT_NEGATIVE_PROOF` (risoluzione incompleta).

Gli altri errori mantengono il rifiuto: indirizzo vietato/fuori policy, CNAME
ambiguo/ciclico/in conflitto, risposta wire non valida, famiglia provider mancante
e limite di indirizzi. Il controllo degli indirizzi avviene subito dopo ciascun
tipo: un A fuori policy non viene nascosto da un successivo timeout AAAA.
Una risposta negativa completa puÃƒÂ² coesistere con una risposta positiva di un
altro resolver; l'unione complessiva deve restare non vuota, entro 32 indirizzi,
e contenere la famiglia richiesta.

Per ogni flusso almeno un resolver completo consente di usare l'unione delle sole
risposte complete. Il TTL minimo include solo queste risposte e le relative
catene/prove negative. `missedResolvers` conserva esclusivamente resolver e codice,
senza indirizzi provider parziali. Se nessun resolver ÃƒÂ¨ completo, l'errore ÃƒÂ¨
`DNS_UNAVAILABLE` con `missed_resolvers`. L'adapter proietta gli errori di integritÃƒÂ 
su `INTEGRITY_UNPROVEN`, quelli di disponibilitÃƒÂ  su `DNS_UNAVAILABLE` e la finestra
TTL insufficiente su `DNS_WINDOW_TOO_SHORT`.

Il risultato dei worker ÃƒÂ¨ privato fino alla consegna sotto lock. Dopo la deadline
o la chiusura del collector nessun worker puÃƒÂ² scrivere nella raccolta condivisa;
lo snapshot restituito ÃƒÂ¨ una copia. I worker tardivi sono ignorati. Il registro
locale, modificato soltanto dai collector, impedisce di accumulare daemon nelle
osservazioni successive: nessun nuovo worker per un resolver ancora occupato,
mai piÃƒÂ¹ di otto worker registrati vivi. Una vecchia risposta non viene riutilizzata.

Il retry TTL resta di massimo tre osservazioni fresche, con l'attesa limitata
originale; tutti i tentativi e le attese condividono i 10 s iniziali. Una deadline del
chiamante più breve limita anche il collector, oltre alle query di trasporto. TTL zero,
`expired/noncacheable`, prova negativa e sottrazione del tempo non sono allentati.

## Percorsi e autorizzazione

I due percorsi attivi R3 usano gli stessi bytes DNS v2:

1. bootstrap del servizio -> `lease_supervisor_v2.runtime` ->
   `continuous_supervisor_v2.RenewingLeaseAdapter` -> `resilient_lease_adapter_v2`
   -> `dns_v2.observe_many`;
2. broker/preparer/driver -> alias `tools.semantic_provider_lease_owner` v2 ->
   alias `tools.semantic_provider_dns` v2 -> `observe_many`.

`SOURCE_MAP_V11` installa i nuovi bytes sui nomi attesi dai loader esistenti,
comprese le copie repository-relative di DNS e owner. Le source closure v1-v5 e
v6-v10 restano esatte. Il bootstrap v3 viene installato sul percorso bootstrap
storico dentro la directory v11. Il supervisore v2 aggiorna soltanto i pin dei
cinque moduli recovery sostituiti e include nella propria closure anche gli alias
DNS/owner. `activation_core_v2` aggiunge un override owner con controllo di
`originalSha256`, identico al contratto degli override preesistenti.

La composizione deriva `dns-profile.json` da `owner.dns`, sostituendo soltanto
`timeoutSeconds` con 10. I template di entrambi i ruoli ricevono quel profilo.
L'autorizzazione continua a legare `lease.ownerConfigurationSha256` ai bytes
originali del coordinatore e lega `lease.dnsProfileSha256` al profilo derivato.
Runtime e template sono a loro volta legati per hash all'autorizzazione.
Il supervisore ricontrolla che il profilo derivato coincida esattamente con
`{**owner.dns, timeoutSeconds: 10}`; una differenza ulteriore viene rifiutata.

Il loader conserva e verifica tutti i sorgenti dell'owner installato; esegue i due
override DNS/owner dal sourceRoot sigillato v11. Kernel, binding, journal, lock,
configurazione originaria e relativi hash non sono riscritti. Non occorre
ripreparare la configurazione del coordinatore sul VPS per comporre questa variante.
Issuer e upgrade riconoscono l'input set v11; il compositore continua a rifiutare
closure vecchie/miste per la nuova versione.

## Rinnovo senza buchi

La formula DNS resta `min(TTL minimo, maxLeaseSeconds) - ceil(tempo DNS)`.
Il risultato v2 aggiunge l'expiry monotona assoluta calcolata nello stesso clock
del resolver. Owner e adapter la consumano direttamente, conservando tutte le
sottrazioni successive del compilatore. La vecchia formula dell'adapter
`prima_DNS + remainingLeaseSecondsAtObservation` sottraeva una seconda volta il
tempo DNS: con 10 s avrebbe lasciato solo 10 s dopo l'osservazione. Le varianti
v11 eliminano quella doppia sottrazione senza estendere il TTL DNS originario.

`readback_margin_compiler` resta invariato: sottrae il budget apply e richiede
almeno 2 s di TTL nft. Lo scheduler v2 usa il minimo TTL reale dei set inet/bridge,
ancorato all'inizio del readback, e riserva:

`timeoutSeconds + applyBudgetSeconds + 2 = 13 s`.

L'attesa ÃƒÂ¨ `min(pollSeconds, remaining/2, remaining-13)`; se la finestra residua
non supera 13 s, il percorso chiude in sicurezza. Il supervisore limita inoltre
la deadline del tentativo al minimo tra il budget recovery corrente e la scadenza
precedente meno 1 s. Le verifiche di autoritÃƒÂ /custodia e i budget recovery restano
invariati. Un lease breve o un ritardo oltre i margini non autorizza continuitÃƒÂ 
artificiale: comporta la chiusura sicura prevista.

Esempio limite testato, TTL almeno 30 s, due flussi, DNS da 10 s: osservazione
100-110, expiry DNS <=130; compilazione a 110, timeout nft 19 s e scadenza
conservativa del lease attivo 129. Dopo 0,5 s di pubblicazione/readback, lo
scheduler attende al massimo 5,5 s e il rinnovo parte a 116. La nuova osservazione
finisce a 126; il budget apply/readback termina prima di 127, quindi prima di 129.
Il test ripete cinque cicli con entrambi i flussi nella stessa finestra.
Non si promette continuitÃƒÂ  per TTL DNS inferiori al margine necessario o pause
arbitrarie del processo; i controlli continuano a rifiutarli.

## Verifiche locali e limiti

Interprete disponibile: Python 3.12.12 di QGIS, su Windows. Resolver finti,
orologio controllato e un test con veri thread daemon bloccati su Event locale;
nessun socket viene aperto dai nuovi test. Le prove coprono budget 10 s,
parallelismo 3 s, unione, risposta fuori policy, nessun resolver valido, CNAME,
prova negativa, famiglie, TTL, worker tardivo e limite dei daemon tra osservazioni.
Il test del loader esegue i sorgenti reali con lettura in memoria e confini
journal/flock sostituiti; verifica i due percorsi v11 e il rifiuto del profilo
alterato. Non attesta custody nativa Linux o installazione.

Passano localmente: DNS/v11 (19 test), R3 (85, 16 skipped nativi), supervisore
(37, 8 skipped), B1 accettazione (19, 8 skipped), issuance (16, 12 skipped),
runbook (5), scheduler storico (7), compilatore margine (4), backend nft (4).
I dieci digest in `tests/fixtures/r3-v1-v10-dns-tolerance-hashes.json` sono stati
ricavati eseguendo il compositore originale da HEAD `9dcc07d4` con fixture
sintetiche; vincolano l'intera mappa dei digest di documenti e autorizzazione.
Il confronto locale originale/nuovo ha verificato anche l'uguaglianza dell'intero
risultato, non solo dei digest. Il test v11 verifica alias, pin, profilo e hash.

La discovery estesa `tools/semantic_lease_recovery/test_*.py` non passa su Windows
(58 test: 2 failure, 23 error): moduli `fcntl`/`os.geteuid`, `/usr/bin/bash`, path
POSIX e hash dei file CRLF. Non sono stati modificati i moduli storici per
adattarla. La CI Ubuntu include le suite pertinenti `test_bounded_recovery`,
`test_continuous_supervisor`, `test_adaptive_supervisor`,
`test_readback_margin_compiler`, `test_nft_seconds_backend`, i nuovi test e la
composizione/accettazione. L'esito CI e le prove native restano da osservare.

I runbook `ops/vps/r3-*` sono conservati: i cinque test locali verificano i blob
a HEAD, non una consegna v11. La consegna, i nuovi pin e gli eventuali runbook v11
restano al loro generatore previsto; nessun vecchio runbook diventa una consegna
v11 per effetto di questa modifica. `docs/STATE.md`, `releases/` e lo script di
staging del coordinatore sono invariati.

`py_compile` passa sui 13 sorgenti Python creati o modificati; `git diff --check` passa.
