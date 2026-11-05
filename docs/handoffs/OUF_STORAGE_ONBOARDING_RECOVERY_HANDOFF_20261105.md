# Ripresa storage — restore Authorization qualificato, 5 novembre 2026

Continuare per **due passi alla volta, senza subagenti**. Verificare branch e CI prima di modificare; non ripetere prove concluse senza modifiche o un motivo documentato.

- Deploy: PR54 draft, branch `feat/m2-discovery-complete-profile-20261029`; leggere l'HEAD che contiene questo handoff. Precedente254228b5f96130cc072a80e17079a2bbd2747513 con 50/50 CI SUCCESS.
- Onboarding: PR54 draft, branch `feat/storage-upload-intent-20261105`, fonte `087fcf21e7402cd5057972093dc0565f03e35427`.
- [Dossier](../OUF_STORAGE_AUTHORIZATION_RESTORE_20261105.md), [ricevuta](../../evidence/storage-authorization-restore-qualified-20261105.json). 63 scenari nativi + 8 API/storage PASS; common-cut/readback SUCCESS, 39 membri/38 checksum/272 sorgenti/1695 file backup, 15 negativi.
- **CI sorgente 8/8 SUCCESS**, incluse PR42018532139/push42018524519, scansione immagine bloccante e avvio container. Suite generale: 428 riportati meno 63 nativi saltati = 365 eseguiti PASS; i 63 nativi sono tutti eseguiti nel job dedicato.
- La prova fisica usa davvero Authorization: decisioni A/B, seconda consegna che revoca A, proiezione versione2, 5 eventi delivery e 4 owner; bundle e audit registry inclusi. Dopo il cut revoca B, proiezione3/null, policy2 senza grant e autorità esterna2/revocata. Restore torna alla policy1 e a B DELIVERED, ma nuova preparazione, riconsegna e owner sono negati. Anche l'autorità esterna assente blocca; snapshot owner/policy/audit invariati dopo dinieghi e verifica S3.
- `StorageRecoveryAuthorityFence` obbligatoria, indipendente dal set ripristinato; default senza verificatore nega. V41 registra generazione immutabile; vecchie righe V40 a zero inutilizzabili. Verifica corrente su prepare/deliver/uso owner e dopo audit. Il verificatore produttivo deve mantenere l'esclusione della revoca fino al commit, senza rete sotto lock. Nessuna implementazione produttiva installata.
- Il file esterno della fixture è sintetico, limitato a 4096 byte e usato con revoca sequenziale; non prova un protocollo distribuito concorrente. Runtime/sessione/postmaster, custody separata e budget128/24h restano in vigore. Nessun bean/endpoint/registrazione/grant automatico.
- Primo788046bf: native e restore PASS, readback fallito su confronto dell'ordine di righe dopo cambio stato. Diagnosi locale dell'originale con digest verificato; correzione solo readback, confronto completo per ID e nuovo negativo di generazione. Fallimento e archivi preservati nel dossier. Pacchetto finale non scaricato localmente.

Prossima coppia proposta: **1)** definire il binding del verificatore corrente indipendente agli owner piattaforma/Authorization esistenti; **2)** qualificare rollback logico a postmaster invariato e generazioni obsolete, senza grant target. Il restore fisico di V40 popolata è ora qualificato; il rollback logico rimane aperto.

MinIO/source-lock, MiniPET18,3/46=39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. Autenticazione Gateway/THS, custody completa, audit dinieghi, revoca distribuita, UDP/Ingestion, rollout misto, riapertura e RPO/RTO OPEN.
