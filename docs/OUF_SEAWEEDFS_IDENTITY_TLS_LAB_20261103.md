# SeaweedFS 4.52 — laboratorio sintetico identity/TLS/egress

Stato iniziale: **13 test locali PASS; esecuzione OCI reale hosted PENDING; NOT_ACCEPTANCE**.

Questo lotto prepara una prova riproducibile della coorte OCI15 già qualificata,
senza ricostruire o sostituire il binario. Non chiude SW-AT07/SW-AT08 né gate,
non migra oggetti target, non concede autorità HUMAN/THS e non cambia MinIO attivo.

## Identità esatta e confini

| Elemento | Valore |
|---|---|
| Sorgente upstream | `984eac6a790be89e2a11de175a7413e1e3e32dd3` |
| Lock candidato SHA256 | `81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea` |
| Manifest OCI | `sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4` |
| Config/image ID | `sha256:add1988121001fe6339a31635d5f61bc560b3c9a540da8027e376a4ebdf0df35` |
| Binario SHA256 | `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033` |
| Artefatto produttore | `13224053625` |
| ZIP SHA256 | `bca4d0a493717812d464f9dc6c7478d918c5dd7f56cd7b5d21f0d4fbcccaeed9` |

Si riusano importlib e `prepare_image`, identificatori, primitive di budget,
diagnostica, riconoscimento lock ring e stop/cleanup del runner cold-recovery
aggiornato in `74cd400b`; nessuna modifica al runner precedente. SHA256 del
runner riusato alla preparazione: `ea888abe20ef92aa58762b3cac715f7b986e4f52b90f544ed443008344a7437d`.

Quattro container massimi: master, volume, filer e S3, tutti UID/GID65532,
filesystem root read-only, capability eliminate, no-new-privileges, limiti
CPU/memoria/pid/log e nessuna porta pubblicata. Il master usa Docker `none`;
gli altri condividono esclusivamente quel namespace loopback. Prima di ogni
prova si verificano immagine, mount, rete, routing e l'unica interfaccia `lo`.
La presenza del membro filer nel lock ring è una precondizione read-only
prima del primo PUT, come nel runner cold-recovery corretto.

## Prove previste nel job

La fixture bootstrap ha soltanto `Admin:ouf-identity-fixture` e
`Admin:ouf-identity-other`, non Admin globale. Crea i due bucket sintetici e
due oggetti protetti; le credenziali sono stringhe pubbliche esplicitamente
fixture, senza secretRef o credenziali target.

L'identità applicativa non ha azioni coarse: la policy IAM nominata consente
soltanto `s3:GetObject`/`s3:PutObject` su
`arn:aws:s3:::ouf-identity-fixture/staging/*` e `s3:ListBucket` sul solo bucket
con `StringLike s3:prefix=staging/*`. Non concede DeleteObject.
La struttura `policyNames`/`policies[].content` è documentata nel sorgente
`weed/s3api/auth_security_test.go`; l'engine estrae `s3:prefix` dalla richiesta.

23 richieste S3 registrate, ognuna con un solo tentativo:

- 4 operazioni bootstrap su due bucket esatti.
- PUT/GET/LIST applicativi sul prefisso, con uguaglianza byte e insieme chiavi.
- 9 rifiuti `403 AccessDenied`: GET/PUT fuori prefisso, GET/PUT altro bucket,
  DELETE non concesso, LIST senza prefisso e con prefisso diverso, modifica
  versioning con tentativo di escalation tramite `prefix`, accesso policy admin.
- 3 rifiuti autenticazione: anonimo, chiave sconosciuta, firma errata; codici
  XML esatti `AccessDenied`, `InvalidAccessKeyId`, `SignatureDoesNotMatch`.
- 4 letture finali: oggetto applicativo e protetto invariati, nessun oggetto
  creato dai due PUT negati (`404 NoSuchKey`).

TLS usa una CA effimera e certificato server SAN `DNS:localhost`; il sorgente
`weed/command/s3.go` abilita TLS-only sulla porta principale con `-key.file`,
`-cert.file`, `-port.https=0`. Ogni richiesta S3 valida CA e hostname. Due
handshake negativi richiedono precisamente `SSLCertVerificationError` con CA
errata e hostname IP non presente nel SAN; un errore generico non vale PASS.
Le chiavi private non sono raccolte nell'artefatto evidence; solo certificati
pubblici e configurazione di credenziali pubbliche fixture.

Dopo la verifica loopback-only, un tentativo TCP443 e uno UDP53 verso
`192.0.2.1` richiedono `ENETUNREACH`/`EHOSTUNREACH`, registrando errno e
destinazione. È una prova del namespace isolato locale; non prova firewall,
allowlist Internet o rete di produzione. Non vengono contattati target reali.

## Budget, prove e riproduzione

Workflow indipendente [storage-452-identity-tls.yml](../.github/workflows/storage-452-identity-tls.yml):
manuale o push limitato ai tre file propri sul ramo di sviluppo; concorrenza
dedicata, `cancel-in-progress: false`, massimo20minuti. Nessuna dipendenza da
credenziali di servizio target. Download producer esatto, verifica SHA,
readback OCI e identità daemon precedono l'avvio. Azioni GitHub fissate a SHA.

Richieste operative timeout30s e response budget1MiB, nessun retry mutativo;
il primo PUT può allocare volumi (nel cold lab l'allocazione osservata ha
richiesto5.747s): un timeout5s produrrebbe un fallimento ambiguo prematuro.
Readiness timeout massimo5s/residuo,
solo GET, massimo60tentativi/80s, stop immediato su errore permanente,
certificato o classe sconosciuta. Il lock ring ha budget90s; processo client
massimo240s. Cleanup e log bounded sono riusati dal runner cold-recovery.
Il fallimento conserva diagnostica e ricevuta senza qualificare l'esito.

L'evidence hosted include digest immagine, snapshot container, rete e routing,
policy fixture, certificati pubblici, lock ring, casi S3, errori TLS, probe
egress, stato stop, log, inventario SHA256 e attestazione GitHub. I log
contengono soltanto dati sintetici; non dimostrano redazione segreti target.

Qualifica locale: `python3 -I -B -S -m unittest discover -s tests -p test_seaweedfs_452_identity_tls.py -v`.
13 PASS: scope policy, firma legata a byte/target/credenziale, codici deny
esatti, errore permanente/TLS senza retry, PUT ambiguo senza retry, timeout operativo30s per allocazione iniziale,
readiness tardiva rifiutata, egress
kernel-denied distinto da timeout/refused, blocco fuori CI, handshake TLS
OpenSSL reale in memoria con CA valida e due rifiuti. Ricevuta:
[JSON locale](../evidence/seaweedfs-452-identity-tls-local-20261103.json),
[log locale](../evidence/seaweedfs-452-identity-tls-local-tests-20261103.txt).
Nessun Docker disponibile localmente: **nessuna esecuzione S3/OCI reale ancora
dichiarata**, risultati live da integrare soltanto dopo la CI.

## Limiti e autorità preservate

Fonti normative: miniPET§8 SW-AT07/08; Matrix1.7 contratti/binding sintetici
vs effettivi; UDP PET1.3§109.4/109.5 provider-as-binding, identità/allowlist e
custody; policy resilienzav3, budget finiti e deny nell'incertezza. Il polling
di startup è una prova CI bounded, non il budget resiliente di un servizio.

Non qualificati: isolamento laterale fra ruoli (condividono loopback), mTLS,
rotazione/revoca, STS/tenant reali, binding UDP/staging effettivi, gestione
segreti target, policy di rete target e validazione HUMAN. Nessun gate/AT
chiuso, nessun grant/replay/deploy/merge/release. Scope17 e52DockerGET consumati,
Teatri/M1 8/8tecnici e6/6funzionali, Farmacie61/10OPEN/STRING restano invariati.
Il lotto offre prova sintetica parziale, non una percentuale di accettazione.
