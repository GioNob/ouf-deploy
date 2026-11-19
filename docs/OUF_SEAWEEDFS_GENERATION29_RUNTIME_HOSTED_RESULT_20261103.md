# Generazione 29: ripristino sintetico, MIME, identità e TLS hosted

Il run [41701381292](https://github.com/GioNob/ouf-deploy/actions/runs/41701381292), commit `7a71218586bcdbc50e1c983a1a12158dc9660de9`, ha completato tutti e tre i job con successo. Il laboratorio runtime si è avviato automaticamente dopo `qualify-cohort`, senza dispatch umano. Il risultato resta **NOT_ACCEPTANCE**: nessuna autorità runtime/release, operazione target, gate o AT chiuso.

Il job runtime `126147936979` ha prodotto l'artefatto `13264096077`: ZIP di 171103 byte, SHA256 `6027b062e35772a315101d4719aabae78f7702cd519a2fabef02edaa312ed61b`. Il readback locale indipendente ha controllato dimensione e digest GitHub, 60 membri univoci e sicuri, 652742 byte estratti e tutti i checksum interni. I nove file della coorte inclusa coincidono byte per byte con l'artefatto predecessore `13264050910`. Le prove raw UTF-8 sono conservate senza alterazioni; solo la ricevuta di readback e questo documento sono derivati.

| Verifica effettiva | Risultato |
| --- | --- |
| Immagine eseguita | OCI `sha256:f8679022d5baff88c33285b501317510ac4d1713cc4901f99999a1df937b18bd`; binario `a0c74718e584942f58c02214f6b3abe46b71cd47d4995b8da3aa002dcdadeef7` |
| Ripristino cold | 5 oggetti sintetici, 8388702 byte; corpi, hash metadata, overwrite e cancellazione preservati |
| MIME esplicito | `application/octet-stream` conservato su GET e HEAD, prima e dopo il ripristino del file `octet-stream.txt` |
| Backup e isolamento | 110 file, 8417467 byte; stop pulito, 8 container distinti e radici di ripristino indipendenti |
| Identità S3 | 23 casi esatti: prefisso autorizzato, dinieghi fuori scope e amministrativi, credenziali anonime/errate, assenza di effetti delle mutazioni negate |
| TLS negativo | Host/IP errato rifiutato (verifyCode 64); CA errata rifiutata (verifyCode 20) |
| Egress | TCP/443 e UDP/53 verso TEST-NET 192.0.2.1 rifiutati dal kernel con ENETUNREACH |
| Budget operativo | Cold e identity sequenziali; massimo 4 container simultanei, 12 ID complessivamente distinti; un tentativo per mutazione |

Il readback ha inoltre verificato UID 65532, filesystem immutabile dei container, tutte le capability rimosse, no-new-privileges, limiti CPU/memoria/PID, assenza di porte pubblicate, rete condivisa con sole interfacce/rotte loopback, e corrispondenza dei sorgenti congelati. La policy dell'identità applicativa ha solamente GetObject/PutObject sul prefisso staging/* e ListBucket con condizione sul prefisso; i permessi bootstrap non sono ereditati dall'identità applicativa.

La regressione MIME della precedente immagine 15 resta conservata come risultato storico: questa evidenza qualifica il percorso sintetico della nuova immagine 29 e non riscrive il fallimento precedente. Non dimostra migrazione dei 120 oggetti reali, ripristino coordinato PostgreSQL, RPO/RTO di accettazione, rotazione certificati, mTLS o isolamento laterale tra ruoli. Licenze, accettazione della redistribuzione e custodia durevole rimangono autorità aperte separate. L'attestazione hosted è riuscita; questo readback non dichiara una seconda verifica crittografica locale della firma.

Ricevuta derivata: `evidence/seaweedfs-generation29-runtime-hosted-20261103.json`. Prove originali: `evidence/seaweedfs-generation29-runtime-hosted-41701381292/`. Metadati job: `evidence/seaweedfs-generation29-runtime-jobs-41701381292.json`.
