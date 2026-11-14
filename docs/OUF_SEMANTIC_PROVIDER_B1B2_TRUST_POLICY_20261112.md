# Trust policy separata B1/B2 — 12 novembre 2026

## Contratto e decisione D-016

La policy `ouf.semantic-deployment-trust-policy.v1` e tutti i suoi consumatori
restano invariati. I relativi insiemi chiusi di ruoli e i controlli dell'installer
non ammettono estensioni compatibili. D-016 introduce quindi un documento distinto,
`ouf.semantic-provider-b1b2-trust-policy.v1`, con percorso e SHA-256 propri. La
chiave pubblica installer esistente viene copiata, senza generare chiavi o leggere
materiale privato. D-014/D-015 assegnano esclusivamente i nuovi ruoli
`ARTIFACT_ACCEPTANCE` (B1) e `RUNTIME_ARMING` (B2).

I campi esatti della policy sono `schema`, `installationRef`, `entityRef`,
`basePolicy`, `authorityProfile`, `keys`. I due binding contengono soltanto `path`
assoluto normalizzato e `sha256` minuscolo. `keys` contiene da 1 a 8 mandati con
campi esatti `keyRef`, `issuerRef`, `roles`, `publicKey`, `notBefore`, `expiresAt`,
`state`. I riferimenti seguono `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`, la chiave
Ed25519 è espressa in 64 cifre esadecimali minuscole e i tempi sono interi epoch
con `0 <= notBefore < expiresAt`. `keyRef` è unico; `state` è `ACTIVE` oppure
`REVOKED`. Sono ammessi soltanto sottoinsiemi non vuoti, senza duplicati, dei due
ruoli B1/B2. Campi aggiuntivi, chiavi JSON duplicate e ruoli legacy o sconosciuti
sono rifiutati.

La preparazione produce un solo mandato con entrambi i ruoli. L'installer è
identificato da `authorityProfile.keyRefs.installer`; nella base deve essere
`ACTIVE`, con ruoli esattamente `DEPLOYMENT_INTENT` e
`FINAL_DEPLOYMENT_APPROVAL`. `intentIssuerRef` e `approvalIssuerRef` devono
corrispondere al suo issuer. Il profilo deve avere lo schema esatto prodotto da
`install-creation-issuer.py`, identità coerenti e `policyBinding` coincidente con
il binding base passato alla CLI. `keyBindings`, `sourceRoot` e il riferimento
alla ricevuta di custodia sono controllati solo nella sintassi: i loro percorsi
non vengono seguiti, risolti, sottoposti a stat o aperti. Le sole letture di input
del controller sono base policy e profilo esplicitamente indicati.

Non esiste una scadenza implicita al 2036: per arrivarci l'operatore deve passare
un epoch esplicito entro `base.expiresAt`. La condizione richiesta è
`base.notBefore <= notBefore < expiresAt <= base.expiresAt`. Un errore restituisce
`HELD/B1B2_WINDOW_OUTSIDE_BASE` con i quattro valori della finestra. La preparazione
può riguardare una finestra futura; la validità corrente è controllata al consumo.

## Firme e verifica

L'envelope `ouf.semantic-provider-b1b2-detached-signature.v1` ha campi esatti
`schema`, `algorithm` (`Ed25519`), `keyRef`, `role`, `issuerRef`,
`installationRef`, `entityRef`, `payloadHash`, `signature`. L'hash è SHA-256 dei
byte esatti del payload; la firma è di 64 byte, rappresentati da 128 cifre hex
minuscole. Il frame di firma è:

```text
b"OUF-SEMANTIC-PROVIDER-B1B2-EVIDENCE\x00V1\x00"
  || uint32_be(len(header_json)) || header_json
  || uint32_be(len(payload)) || payload
```

`header_json` esclude `signature`, usa chiavi ordinate, separatori `,` e `:`,
`ensure_ascii=True`, codifica ASCII. Il dominio deployment esistente
`OUF-DEPLOYMENT-EVIDENCE\0V1\0` è diverso. I test usano il modulo deployment reale
e chiavi Ed25519 effimere: provano firme valide di entrambi i contratti, rifiuto
incrociato, rifiuto dopo sostituzione di schema/ruolo e rifiuto cambiando soltanto
il dominio a header invariato, in entrambe le direzioni.

API pubblica in `tools/semantic_b1b2_authority/authority.py`:

```python
verify_b1b2_detached(
    raw, signature_raw, role, issuer, installation, entity,
    policy_binding={"path": policy_path, "sha256": policy_sha256},
    openssl_binding={"path": openssl_path, "sha256": openssl_sha256,
                     "version": openssl_version},
    budget=VerificationBudget(18),
)
```

Restituisce `True` solo dopo verifica; i rifiuti sollevano `AuthorityDenied` con
codice pubblico. `B1B2Authenticator` espone lo stesso metodo e consente di
condividere il budget di un'operazione. Il budget predefinito è di 18 secondi
dalla costruzione dell'autenticatore; un'istanza non rinnova automaticamente la
propria deadline. Ogni subprocess usa al massimo due secondi del budget residuo.
Sono accettate solo policy root:root 0600 a link singolo, sotto antenati root non
scrivibili da gruppo/altri, senza symlink. La chiave deve essere `ACTIVE` e nella
finestra sia all'inizio sia alla fine; il clock civile non può regredire. Policy e
hash sono riletti alla fine. Base e profilo sono riferimenti di derivazione: il
verificatore non li apre, né propaga implicitamente una loro successiva modifica.
Per revocare B1/B2 occorre aggiornare il mandato B1/B2 e distribuire esplicitamente
il nuovo binding ai suoi consumatori.

Il binario OpenSSL è vincolato per percorso, hash, custodia e versione restituita
da `openssl version`, e viene ricontrollato dopo la verifica
`pkeyutl -verify -pubin -rawin -keyform DER`. Solo frame, firma e chiave pubblica
vengono scritti nei temporanei. Il modulo replica minimamente queste primitive
del verificatore deployment: importare quel modulo richiederebbe distribuire il
package cohort e le sue dipendenze sotto `python3 -I`. Non vengono modificati o
estesi i moduli legacy. Non viene introdotto un firmatario B1/B2 in questo task.

## Sequenza per l'operatore umano

Questa modifica prepara codice e test, senza effettuare la consegna, accedere al
VPS, pubblicare policy o abilitare consumer. Il controllo locale del launcher
con segnaposto termina prima di ogni download. Prima della consegna Claude deve
sostituire tutti i pin nel launcher:

| Segnaposto | Valore |
| --- | --- |
| `__PIN_COMMIT__` | Commit Git di 40 cifre dei due sorgenti approvati |
| `__PIN_SHA256__` | SHA-256 dei byte del controller Python |
| `__PIN_AUTHORITY_SHA256__` | SHA-256 dei byte di `authority.py` |

Il launcher rifiuta pin non compilati prima di ogni download. Scarica soltanto
i due file dal commit su `raw.githubusercontent.com`, controlla entrambi gli
hash e ripete i controlli dentro `sudo /usr/bin/python3 -I -B`. Modulo e controller
sono poi eseguiti dai medesimi byte verificati; non vengono riaperti per l'import.
`__init__.py` non è necessario nel pacchetto consegnato. L'esecuzione diretta dal
checkout carica il modulo da un percorso esplicito relativo al controller e
presuppone che il checkout sia stato verificato dall'operatore.

1. Confermare percorso/hash della base in produzione (attualmente indicata come
   `/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json`)
   e del profilo di autorità corrente. Non dedurre gli hash da documenti storici.
   Scegliere una directory padre esistente root:root, con antenati in custodia,
   e un nuovo nome `[A-Za-z0-9][A-Za-z0-9_-]{0,95}`. Non riusare un output parziale.
2. Impostare riferimenti e due epoch espliciti, verificando il limite della chiave
   base. Eseguire il launcher fissato con tutti gli argomenti sotto e `--plan`.
3. Esaminare il JSON pubblico: `PLAN_READY`, policy completa, `policySha256`,
   `inputHashes`, scritture root 0700/0600, `privateKeysRead: 0` e `planSha256`.
   Il digest lega l'intera proiezione canonica, inclusi entrambi gli hash e
   l'identità osservata della directory padre; `status` non entra nel digest.
4. Eseguire gli stessi argomenti con `--apply --plan-sha256 DIGEST_DEL_PIANO`.
   L'apply riosserva gli input, richiede lo stesso digest, crea la directory con
   mkdir esclusivo e il temporaneo con `O_EXCL`, esegue fsync, pubblica mediante
   link esclusivo e rimuove il solo link temporaneo dopo successo. Rilegge policy
   e input. Il risultato atteso è
   `SEMANTIC_PROVIDER_B1B2_TRUST_POLICY_PREPARED`, `privateKeysRead: 0`,
   `publication.readbackVerified: true`. Nessuna sovrascrittura è consentita.
5. Conservare il report e il binding della nuova policy per i futuri consumer
   B1/B2. Questo stato non prova accettazione di artefatti, arming o readiness.

Argomenti obbligatori, oltre alla modalità:

```text
--base-policy PATH --base-policy-sha256 SHA256
--authority-profile PATH --authority-sha256 SHA256
--installation-ref REF --entity-ref REF
--not-before EPOCH --expires-at EPOCH
--output-root DIRECTORY_ESISTENTE --output-name NUOVO_NOME
```

Root:root e umask 077 sono obbligatori anche in plan. I rifiuti di esecuzione
producono JSON `HELD`, un codice `reason` e exit 1; errori di sintassi CLI sono
gestiti da argparse con exit 2. Gli errori non riversano gli input nei report.

## Ripristino e parziali

Non esiste rollback automatico. Se mkdir o pubblicazione sono già iniziati, il
report `publication` conserva l'avanzamento e il percorso dell'eventuale
temporaneo. Non rigiocare lo stesso apply: un output esistente, anche symlink
pendente, viene rifiutato. Riconciliare i parziali e conservarne l'evidenza.

Se la nuova policy non è mai stata usata, l'operatore può rimuovere manualmente
la sola directory nuova, dopo averne verificato percorso e contenuti. La policy
base e il profilo originario non devono essere rimossi o riscritti. Se esistono
già consumer, prima riconciliare i relativi binding e l'eventuale revoca: la sola
rimozione della directory non costituisce una procedura di ripristino completa.

## Verifica ripetibile

Il workflow `semantic-provider-b1b2-authority.yml`, su pull request e sui soli
path del task, usa Ubuntu 24.04 e checkout fissato come il workflow installation
profile. Il comando di accettazione è:

```sh
sudo -n env OUF_B1B2_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_semantic_b1b2_authority.py -v
bash -n scripts/deliver-semantic-provider-b1b2-trust-policy.sh
```

I test nativi creano fixture effimere sotto `/run`, con vera custodia root e
OpenSSL locale; non accedono a reti, VPS o segreti esistenti. Una chiave fittizia
000 e una assente sono referenziate dal profilo; un audit hook intercetta ogni
tentativo di apertura durante plan/apply. Le chiavi generate per i soli test
crittografici sono distinte. Sono coperti anche hash/versione OpenSSL errati,
deadline, revoca, finestre, deriva della policy, digest obsoleto, custodia degli
input, output già presente e conservazione dei parziali. Con
`OUF_B1B2_NATIVE=1` un ambiente privo di root Linux fallisce anziché saltare i test.
Senza la variabile sono eseguibili i soli test puri di contratto e budget.

Nella sessione di implementazione Windows Python non è disponibile nei comandi
o nei percorsi locali controllati; WSL restituisce `E_ACCESSDENIED`. I test nativi
e il risultato CI restano da attestare sul runner, senza dichiararli PASS locale.
