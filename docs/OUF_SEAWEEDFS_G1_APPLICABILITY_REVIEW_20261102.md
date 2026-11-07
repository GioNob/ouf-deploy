# SeaweedFS — valutazione di applicabilità accettata per SW-G1

2 novembre 2026, Europe/Rome. L'owner ha approvato la proposta esatta dopo la raccomandazione tecnica: «Mi hai convinto, e sia.». Decisione `OUF-SW-G1-20261102-01`, limitata a un advisory e a un binario. La [proposta originale](../evidence/seaweedfs-g1-applicability-review-proposal-20261102.json), revisionata al commit `c08c4312fcbd0632bad93c9fcdaf5303c0453921`, resta byte per byte invariata come documento storico DRAFT; il nuovo [record della decisione](../evidence/seaweedfs-g1-applicability-owner-decision-20261102.json) ne registra l'accettazione. Nessuna firma o decisione THS viene rivendicata.

## Classificazione e perimetro

| Campo | Valore |
|---|---|
| Advisory | GO-2026-5932 |
| Stato | `not_affected` |
| Motivazione | `vulnerable_code_not_present` |
| Binario server | SHA256 `bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74` |
| Sorgente | SeaweedFS `153ab668c99731a6d29492bf6c61d0b4fa701101`, build OUF distinta dall'asset upstream |
| Build | Go1.27.3, CGO0; patch JOSE4.1.6 / x/net0.62.0 |
| Grafo compilato |1738 pacchetti; famiglia OpenPGP interessata assente |
| SHA256 del grafo | `67534a54978a5a157673a6a21ea26c147b0dbcb60c60d30497ce39e6ee3c435b` |
| Rapporto raw conservato |0HIGH/CRITICAL,1UNKNOWN; gate raw HELD |
| Irrisolti dopo la valutazione accettata |0HIGH/CRITICAL/UNKNOWN nell'insieme esaminato |
| Sotto-controllo vulnerabilità |PASS_WITH_EXACT_DISPOSITION |
| SW-G1 complessivo / release / migrazione |OPEN / non ammessa / non eseguita |

Il modulo `golang.org/x/crypto` rimane presente per altre funzionalità. L'[advisory Go](https://vuln.go.dev/ID/GO-2026-5932.json) riguarda la famiglia `golang.org/x/crypto/openpgp`; i pacchetti elencati non compaiono nella compilazione del binario. La [specifica OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) prevede la motivazione vulnerable_code_not_present quando il componente contenitore è incluso ma il codice vulnerabile è escluso dalla build. Non si dichiara assente tutto il modulo x/crypto e non si attribuisce una correzione upstream inesistente.

## Recepimento nel MiniPET

MiniPET v1.1 §5 conserva zero HIGH/CRITICAL/UNKNOWN irrisolti e provenienza verificabile, ammettendo questa sola valutazione di applicabilità documentata dall'owner. Nessuna soppressione viene aggiunta agli scanner e nessun rapporto storico viene riscritto. Il nuovo [OpenVEX](../evidence/seaweedfs-g1-openvex-20261102.json) identifica unicamente il prodotto tramite SHA256; non contiene una regola per tutte le release4.51. Il suo autore è il progetto OUF e la decisione è registrata dalla conversazione, senza presentarla come credenziale o firma HUMAN/THS.

Qualsiasi variazione di binario, sorgente, patch dipendenze, toolchain/opzioni, grafo o advisory richiede nuova valutazione. Nuovi HIGH/CRITICAL/UNKNOWN rimangono bloccanti. La classificazione non completa licenze, SBOM, immagine OCI, custodia durevole, coorte o qualifica della destinazione.

## Qualifica del recepimento

[CI41519037628](https://github.com/GioNob/ouf-deploy/actions/runs/41519037628), source `214c0e8a9681340fa71ea7f03ed6875a015097b6`, PASS:9 test con sotto-casi per nuovo rilievo, stesso advisory su un altro eseguibile, build/grafo/dipendenze/advisory cambiati, decisione non accettata o estesa, VEX ampliata, inventari vuoti, severità sconosciute e riferimenti di prodotto errati. Nessun eseguibile incluso nelle prove originali viene avviato. Advisory scaricato nuovamente dalla fonte ufficiale e confrontato con lo snapshot canonico approvato.

Il workflow ricontrolla l'artifact originale4.4MB,25checksum,8sorgenti del core/compilatore e tutte28sorgenti precedenti. Verifica Sigstore dell'esatto workflow/source/ref OUF originale su runner hosted. L'attestazione della nuova valutazione è disponibile; la sua firma non viene dichiarata verificata indipendentemente in questo dossier. [Dossier e archivio integrale dei16membri checksum](../evidence/seaweedfs-g1-accepted-applicability-qualified-20261102.json).

Nessuna nuova operazione VPS:17controlli/52DockerGET, tutti gli scope13–17 consumati.120corpi reali da verificare; writer/consumer/DB/ACL, backup coerente, profilo destinazione, capacità fresca e recovery ancora aperti. Teatri/M1 8/8tecniche,6/6funzionali e stessaFarmacie preservati; nessuna accettazione M2.
