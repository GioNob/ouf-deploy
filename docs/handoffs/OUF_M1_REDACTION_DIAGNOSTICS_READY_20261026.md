# OUF M1 — diagnostica owner qualificata, prossimo passo sola cattura metadati — 26 ottobre 2026

## Punto esatto e fonti

Continuazione autorizzata dall'owner: «puoi proseguire sulla road to M1».
Il precedente [handoff owner REDACTED](OUF_POST_OAUTH_OWNER_REDACTION_20261026.md) rimane prova live: due READ runbb2/sourceTeatri sotto51 dopoIAM/OAuth corretto, bindingpub/filehash eACKprefix/watermark positivi, itemlineage/UDP redatti. ZERO nuove acquisitionREAD in questa continuazione; nessun retry/seconda run o rinnovo51.
[Prova CI e pins completi](../../evidence/acquisition-redaction-diagnostics-qualified-20261026.json).

## Codice candidato, NON installato

Ingestion PR47 source7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7.
UDP PR48 source125510cf9d970aff7db66a0a8f27eb98b50bb6de.
Aggiunta additiva redactionReasons: categorie fisse, ordinate e deduplicate, nessun valore/label negata/ID nascosto/conteggio per motivo.
Ingestion distingue DATA_LABEL_METADATA_INVALID da DATA_LABEL_NOT_AUTHORIZED.
UDP distingue anche RETAINED_TENANT_NOT_VERIFIED, OBJECT_NOT_AUTHORIZED, PROPERTY_NOT_AUTHORIZED.
Il primo guard negato ferma quella riga; failuretenant non rivela motivi più fini.
Nessuna modifica alle condizioniALLOW, dati/cursor nascosti restano tali, nessuna queryaggiuntiva/migrazione/worker/route/grant.
Normative consultate negli originali allegati: Authorization PET1.5 §§23.2/36.10 eOA, UDP PET1.3 §§36/40/50, miniPET CSV-R20.
Causa LIVE della redazione ancora NONnota: non aggiungere labelgrant alla cieca.

CI dedicate con logletti:
- Ingestion40330319054/job121597693272:18PASS/2condizionali su20; successiva immagineDockerHTTP1PASS/0skip. Modulo40330319286/job121597695104:193PASS/4skip su197.
- UDP40330625386/job121598776010:10PASS/1condizionale su11; successiva immagineDockerHTTP1PASS/0skip. Modulo40330626919/job121598783161:217PASS/4skip su221.
Identità/dati sintetici; PG17 e Docker effettivi. Gli altri skip pairwise/vettoriesterni restano dichiarati; non affermare che questa patch riqualifica tutto.
PrimoUDPdee1693 falliva perché il NUOVO test aggiornava property_contribution append-only; corretto solo fixture per inserire labelproperty indipendente. Protezione rimasta intatta.
Artefatti immagine CI conservati:
Ingestion12653588090/140865783byte/SHAe8a50b1069e4e2055a559bfa6860f56b3334bff065107103f2defcb185dc7e74.
UDP12654892222/122361115byte/SHAfe7ec53d57785fb663cf6e40d4a9b9c13917c42a567cfe16113782abfce39177.
NON ancora scaricati/preparati/importati sul VPS. Non assumere DockerconfigID=nativeManifestID: riusare riconciliazione immagine qualificata.

## Nuova lettura metadati distinta, non replay

Source reader102f5a212b1d9b818ea8842ab782367be2504b47, SHA0459b4d9fc444ce518a6bbbb6deba07cd05c5d99233516eec7d8064b7059228e.
Delivery d4118d861d14da33aecabd223f89c77f861d6544, wrapper releases/prepare-acquisition-redaction-update-inputs-20261026.sh, SHAa4af73fa6276a4351fe086254e0088ee2223adbea210f2b321bd314f16c04050.
Nuovo scopeFISSO /etc/ouf/deploy-snapshots/acquisition-redaction-update-inputs-v1, una esecuzione. Nessun vecchio controller o scope riaperto.

Legge ESATTAMENTE quattro file rootprivati:
1. inputsMCP catturati precedentemente, hashfb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4;
2. review53baa1e1be6b600da78f5f4915a21e19e6e553b0f610bc66080fd6bf3a4af86e;
3. result della sola ultima installazioneMCP diagnostica;
4. recovery journal corrispondente.
Verifica COMPLETE/11stageAPPLIED/reviewauthoritye2d940ff.../counts116GET8writes/6altriimmutati, bootesatto.
Usa il MCP NUOVO dal journal, hashbindingf5a014435647efb7aa059abb1ee84a60c347641399b2eef012c88c2a83d27550; NON seleziona il vecchioMCP trattenuto.
Massimo10EngineGET=info+7componenti+2rilettureREAD,90s,2MiBresponse/20MiBcumulativiEngine. Custodia root/peer/proc/generazioni/fonti esatte, nessun valoreconfigpubblico.
Zero applicationdata/SQL/OAuth/credenzialifile/chiavifirma/import/stop/restart/write. Non osserva policylabel effettive: prepara SOLO futuro piano2READ.
Wrapper HTTPS/commit/hash/root0400 echecksumroot/logprivati; nessun gh.
Output atteso ACQUISITION_REDACTION_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED,complete=true,Exit0/DeliveryExit0. STOPconsuma scope: conservareprove eNONrilanciare.

Qualifica source/custodia delivery: push40331490696/job121601764396 ePR40331500414/job121601798638:8unit+2nativePASS/0skip ciascuno, logdirettiletti. Native=AF_UNIX/rootpeer/procpin reali e copierroot400 con negazione nonroot; storia/APIapp sintetici, soli destinationrootscopier adattati alfixture. Wrapperbash-nPASS; wholecurl/sudodelivery non eseguita inCI.
Primiworkflow40331106216/40331096165 falliti perché tempfixture sottoancestryrunner-nonroot; corretto SOLOpathCIprotetto/var/lib, non guardproduction. Nello scratch AF_UNIX/chown65534 bloccati; prove native valide sonoCIroot, nonlocali.

## Comando unico di SOLA LETTURA da oufadmin sul VPS

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_redaction_bootstrap=$(mktemp -d "$HOME/ouf-redaction-inputs-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/d4118d861d14da33aecabd223f89c77f861d6544/releases/prepare-acquisition-redaction-update-inputs-20261026.sh" \
    -o "$ouf_redaction_bootstrap/run.sh"
  printf '%s  %s\n' 'a4af73fa6276a4351fe086254e0088ee2223adbea210f2b321bd314f16c04050' "$ouf_redaction_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_redaction_bootstrap/run.sh"
  /usr/bin/bash "$ouf_redaction_bootstrap/run.sh"
)
```

Non è APPLY, non richiede APPROVO o nuovo login. Incollare soloJSONpubblico+Exit/Directory/Log/DeliveryExit. Non allegare fileinputsprivati oambienti.

## Passo successivo dopo la ricevuta

Preparare immagini e piano esatto della SOLA sostituzione2replicheREAD, mantenendo workeroriginali, MCP9a corrente, PostgreSQL, Gateway/82+2route e Registry.
Nessun nuovoMCP/updateIAM/sourcegrant.
Serve qualifica controller/review concreta PRIMA di consegnare nuovaAPPLY; mandatoHUMAN terminale solo perquelpianofresco.
Non simulare APPROVO. STOP/CLAIMED niente replay/rollbackautomatico.
Dopo installazione provata, diagnosiowner governata undergrantvalido. Policy51scade15:14:26CET26ottobre; nessuna estensione/propostaautomatica.
In base al motivo provato preparare solo correzionenecessaria; un eventualegrantREADulteriore richiede mandatoHUMANspecifico.
SoloDUErun bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f/sourceTeatri.
G4/M1/F5/F6 aperti, WP5/6parziali/G5/6nonchiusi, WP7/M2nonaccettato. Supervisor dopoE2E.
Nessuna terzaacquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.

## Consuntivo conservato

Baseline miniPET1.1 non riscritta: M1centrale24h/range18–30, M2centrale55h/range40–70.
Intervallo tecnico di questa continuazione misurato dal primoUTCosservato13:20:39Z al checkpoint13:36:14Z:935s=0.259722h. È lavoroWP4diagnosi/codice/custodia; leCI hanno lavorato mentre proseguiva altro lavoro.
Restano nonconsuntivati integralmente i giorni21–26: NON trasformare9.19h storiche+questointervallo nel totaleprogettospeso. Nessuna oraHUMAN o attesaretroattiva inventata.
