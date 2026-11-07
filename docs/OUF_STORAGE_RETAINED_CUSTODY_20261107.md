# Custodia storica del materiale di cattura OUF

Decisione proposta `GIOVANNI-NONPROD-HISTORICAL-CUSTODY-20261107-01`. L'esecuzione sul VPS richiede la decisione distinta su questo perimetro e la qualifica nativa con age. La decisione di cattura precedente copriva un tentativo, ora consumato.

## Evidenza del VPS

Il secondo inventario termina al comando 56, con 145 container, zero in esecuzione e stati dei selezionati invariati nei dati conservati. Il comando eventi 57 è assente. Nel codice, tra inventario ed eventi, restano la verifica completa dell'inventario e delle sorgenti runtime e il confronto dei manifest con il filesystem. Il readback non identifica la causa. I 72 secondi misurano dal claim interno all'ultimo output osservato e non misurano la durata totale del tentativo. [Ricevuta](../evidence/storage-capture-post-export-operator-20261107.json)

I 34 tar sorgente, 14 tar rootfs e il tar immagini sommano 6.540.999.168 byte. I manifest sorgente sono conservati. Il materiale è storico e incompleto rispetto alla procedura di backup. La continuità delle sorgenti, la copertura degli eventi e il restore restano aperti.

## Operazione proposta

- Un solo scope nuovo `capture-historical-custody-20261107-v1` sotto `/var/lib/ouf-storage-migration`. Gli originali restano privati e conservati.
- Vincolo su decisione, claim e piano originali, stadio osservato a 56 comandi e dimensioni aggregate esatte. Rivalidare i 34 tar sorgente contro i manifest col verificatore del produttore. Includere 53 membri del payload, hashati durante lo streaming, e i claim di provenienza nel manifesto cifrato. I 14 rootfs e il tar immagini sono conservati come artefatti storici con hash dei byte. L'esercitazione di restore rimane separata.
- Una invocazione del binario age già verificato e stesso destinatario. Flusso tar verso age con tetto **8 GiB** sul cifrato e tempo **900 secondi**. Lo scope non contiene un nuovo bundle in chiaro. Output privato, con ricevuta finale soltanto dopo uscita di age, sincronizzazione, verifica di stabilità e SHA-256. Gli errori conservano claim e parziale.
- Scadenza invariata **7 novembre 2026, 20:53:39 ora di Roma**. Avvio entro **20:38:39**. Restano contabilizzati 184 comandi e 2400 secondi del fermo, 56 marker e 3600 secondi della cattura. Zero richieste al provider, segnali, cambi di policy, riavvii o apertura del traffico.
- `HISTORICAL_CUSTODY_ARCHIVE_SEALED` espone percorso, byte e SHA-256 per la successiva copia indipendente. Custodia storica distinta da backup operativo. MiniPET **39,78%**, zero credito nuovo.

[Script](../scripts/seal-retained-storage-capture-20261107.py) · [Qualifica nativa](../.github/workflows/storage-retained-custody.yml)

La fixture locale ha verificato corruzione, idempotenza del claim, errore del cifratore, integrità dei membri e conservazione degli originali. Il test locale usa pass-through. Il workflow separato verifica cifratura e decifratura con age su fixture isolate.
