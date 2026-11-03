# Valutazione SDK OpenBao e dipendenza mapstructure

La migrazione del solo adapter SeaweedFS a `github.com/openbao/openbao/api/v2` non chiude il modulo archiviato `github.com/mitchellh/mapstructure`. Il tag API più recente osservato il 3 novembre 2026 è `api/v2.7.1`, commit `36ba71c26ede7ba3e89b90a8064a8cd28d37de39`: usa direttamente `go-viper/mapstructure/v2 v2.5.0`, ma richiede ancora `hashicorp/go-secure-stdlib/parseutil v0.2.0`, che importa il vecchio decoder. Lo stesso arco rimane nel main OpenBao osservato `6539c32aa1d260aa0bb0ebe4dd74bc41b7aab313`.

Il tag API richiede Go 1.25, compatibile in principio con la toolchain candidata Go 1.27.3. Le firme pubbliche usate dall’adapter (`DefaultConfig`, `NewClient`, `ConfigureTLS`, `SetToken`, `Logical.Write`, `WriteWithContext`, `ReadWithContext`) sono disponibili. Questo è un confronto di sorgente, non una qualifica compilata o wire. Il client OpenBao dà priorità alle variabili `BAO_` rispetto alle corrispondenti `VAULT_`, anche quando la variabile `BAO_` è presente ma vuota: la migrazione richiederebbe prove di binding e credenziali ambientali, oltre a errori, timeout, retry, AppRole, TLS e Transit.

## Parseutil ufficiali verificati

| Origine | Pin osservato | Esito |
|---|---|---|
| HashiCorp | `parseutil/v0.2.0`, commit `856520952b2937e9cf2d8368e9200c5b05e66c67` | Nessun tag successivo restituito dall’API; main e pin conservano mapstructure v1.5.0 |
| OpenBao | `parseutil/v1.1.0`, commit `e238ea0d4570f814e033ba4fec10636735ba0bc0` | Conserva mapstructure v1.5.0; go.mod contiene inoltre un riferimento strutil con pseudo-versione zero e replace relativo |

Il fork OpenBao non risolve quindi il problema con un pin pronto da sostituire. Non viene applicato un alias di modulo, un fork dell’intero SDK Vault o un client HTTP costruito a mano.

## Profilo standard senza provider OpenBao/Vault

È un’alternativa tecnica da qualificare esplicitamente, non una migrazione trasparente: rimuoverebbe la capacità di creare/decrittare envelope Transit attraverso entrambi gli alias `openbao` e `vault`. Resterebbero da provare gli altri provider KMS e le modalità S3 effettivamente richieste. Un semplice tag di compilazione non pulisce il grafo root durante tidy, che considera i tag: andrebbero esclusi dall’albero candidato anche il sorgente dipendente e il test upstream `test/kms/openbao_integration_test.go`, che importa direttamente Vault API; la storia upstream resterebbe conservata tramite la patch.

L’esclusione deve essere visibile e non aggirabile: tentativi di compilare un profilo OpenBao/Vault non qualificato devono fallire; un binding che richiede il provider escluso deve fermare la preparazione e l’avvio, senza fallback né servizio apparentemente sano. Il codice attuale non basta: `initializeKMSFromConfig` nasconde gli errori KMS, e `loadS3ApiConfigurationFromFile` si limita a registrarli. Serve un guard esplicito prima degli effetti su identità/provider, con propagazione dell’errore dal caricatore; il costruttore già interrompe l’avvio su errore del caricatore. Anche il reload deve rifiutare il nuovo binding e preservare lo stato precedente.

La baseline pubblica conservata riporta 120 oggetti, zero oggetti cifrati, zero riferimenti KMS e cifratura assente nei due bucket osservati. Tuttavia inventario writer, assenza di consumer esterni e snapshot temporale completo non sono provati. Questi conteggi permettono di motivare un candidato di laboratorio ristretto; non dimostrano che l’esclusione sia ammissibile per ogni consumer target. G0/G1/G2 e il gate sulle funzionalità richieste rimangono aperti. Se emerge un binding necessario OpenBao/Vault, il profilo escluso deve essere respinto.

## Esito e fonti

Nessuna migrazione SDK eseguita e nessun nuovo sigillo di generazione. La patch LDAP mantenuta rimane indipendente e utile; dopo di essa restano due importatori produttivi del vecchio decoder, Vault API e parseutil. La scelta successiva deve qualificare una rimozione esplicita della funzionalità opzionale, oppure aspettare/adottare una catena upstream mantenuta che non riporti il vecchio decoder. Zero operazioni target e nessuna richiesta operatore prodotta da questo audit.

- [OpenBao API go.mod al commit osservato](https://github.com/openbao/openbao/blob/36ba71c26ede7ba3e89b90a8064a8cd28d37de39/api/go.mod)
- [OpenBao regole delle variabili d’ambiente](https://github.com/openbao/openbao/blob/36ba71c26ede7ba3e89b90a8064a8cd28d37de39/api/env.go)
- [OpenBao API supportata](https://github.com/openbao/openbao/blob/36ba71c26ede7ba3e89b90a8064a8cd28d37de39/README.md#importing-openbao)
- [HashiCorp parseutil al pin](https://github.com/hashicorp/go-secure-stdlib/blob/856520952b2937e9cf2d8368e9200c5b05e66c67/parseutil/go.mod)
- [OpenBao parseutil al pin](https://github.com/openbao/go-secure-stdlib/blob/e238ea0d4570f814e033ba4fec10636735ba0bc0/parseutil/go.mod)
