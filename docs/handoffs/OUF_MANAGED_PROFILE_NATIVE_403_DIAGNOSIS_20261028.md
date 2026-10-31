> **SUPERATO: risposta nativa ricevuta, scope preview assente nel contesto negato.** Non ripetere la lettura browser. Seguire [la nuova cattura corrente della richiesta OAuth](OUF_MANAGED_PROFILE_THS_SCOPE_CAPTURE_20261028.md), qualificata e non ancora eseguita; nessun nuovo login/grant/budget/resume.

# 403 della scheda nativa: risposta da distinguere — 28 ottobre2026

L'utente ha aperto la scheda delsolo asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4 e riporta esattamente:

> Accesso negato (HTTP 403). Il controllo di accesso ha negato la richiesta; sessione, scope e permessi devono essere verificati. Un nuovo login non concede permessi. Il lavoro è conservato; nessuna azione è stata inviata.

[Evidenza completa](../../evidence/managed-profile-native-card-403-20261028.json). È una segnalazione deltestoUI,non una lettura agentdellaTHS o dell'intera rispostaHTTP.Nessuna mutazione inviata secondoUI;nessun budget/resume/job/upload/acquisizione eseguito dall'agent.

## Stato da non riaprire

Policy58 giàverificataPUBLISHED per stessaproposalfb54d330-0ec2-400a-ae71-e4ac3cf45319/rev1.8ruoli/12assegnazioni,137grantconfiguratiouf-admin,7+11e134precedenti preservati,tre permessisoloexactjob.Instradamentoouf-admin eidentitàeffettivaconnector provati,NON principalbrowser/scopestokenTHS.[Prova58](../../evidence/managed-profile-job-control-policy58-access-20261028.json).Non creare un'altra proposta o rinnovaregrant.Servicepermission strutturale56 preservata.Descriptor57/publisher eprecedenti reader/APPLY/imageplan/authoritysonoCONSUMATI:non rieseguire o riapprovare.Owner9890b318 eMCPd2454f3c sono giàinstallati.Nessun riavvio/reinstallazione Registry.

MCP exactjobread dopo58 ha restituito soloINVALID_ARGUMENT,non ritentata.Nessuno statusHTTP/fase/correlation/cause oaccessoeffettivoMCP provati.Non confondere quelmessaggio conil403nativo attuale.

## Risultati dell'ispezione delcodice

SourceOnboarding9890b318,letti PermissionThsSecurity,ManagedProfileRecoveryThs,ManagedProfileRecoveryApi,TrustedActorResolver,ServletAuthorization,ManagedFileService,profile-recovery.js e testpertinenti.LaUIrichiede credentials same-origin e nonmostra bodyarbitrari:solo code/Code inallowlist ecorrelationIdUUID.In assenzacodicericonosciutoqualsiasi403diventa iltestogenerico riportato.Questo è comportamento riprodotto direttamente dalramoaccessFailure,NONprova causadi autorizzazione.

PermissionThsSecurity richiede sessioneclientouf-ths eJWT-HUMANvalidato;ilcatchgenerico invia403 anche per disponibilità/scadenza/validazione sessione.BFFcard richiedequelcontesto e inoltra4xx dellachiamataGateway,mentresuccessoagganciaCSRF.Cardowner derivarisorsadaltenant/subjectedasset/jobdurevoli prima deipermessifile.profile.LePOSTrichiedonoanchequarantine.release,writeproof econtrolli expectedstate/review.I grant configurati non sostituiscono scopeoownership.

ContrattoGatewayGETversionato bf179e96200deb84942ad32507edef52a4284cd0 richiedepreview/OIDC/HUMAN sulwildcardmanaged-files;ownercard richiedefile.profile.Sono duegate distinti.SourceGatewaymaterializerTHS pulisce bearer/headercaller ma mantienecookiesessioneinoltrataall'owner;ilBFFrecuperailbearerserver e attraversaGateway.Nonèuna prova della current route runtime né deltokenusato dalbrowser.Non allentare len2/scope/ownership o inventare labeldati.

**Causalive del403NON provata**:sessione/principalbrowser,scope effettivi,rawbody/headers eorigine Gateway/owner nonosservati.Non scegliereunfixgrantscope/token basatosolo suquestotesto.Non chiedere unaltrologin oautenticazione conclientdiverso come tentativo.

## Percorso Teatri controllato

Letti integralmente [policy51/SCOPE_MISSING](OUF_POLICY51_SCOPE_MISSING_HANDOFF_20261026.md) e[IAMREAD completato](OUF_IAM_READ_SCOPES_COMPLETED_20261026.md).Allora ilguard MCP aveva fornitoreasonSCOPE_MISSING epolicy51:solo dopo quella provafudistinto ecorrettoilclientHUMANeffettivo.Ouf-chatgpt,ouf-human-admin eouf-ths nonsonointercambiabili.IlcasoTeatri nonautorizzareplaydei6READscope storici suTHS né grantlarghi;nonrileggere vecchitoken/scopiconsumati.Nuovaautenticazione ha senso dopo specificaprova ecorrezionedelcontratto,nondal403generico.Nessun codice diE2E/ingestion/UDPvagiàrifatto.

## Unica lettura fondamentale dell'utente

[Aprire la risposta nativa delmedesimo job](https://api.ouf-lab.it/trusted-human/managed-files/recovery/api/9c502da5-b5d8-405e-b3f5-60eb31ecb513/677480c8-3d10-44fd-9dad-f72ddeed20a4).MetodoGET,nessunbody/azione,stessapaginaorigine/sessione.Ilpercorsoèverificato sulcodice installatoManagedProfileRecoveryThs.cardapi/{assetId}/{jobId},non la rootgenericaapi.ouf-lab.it.Questaèun'osservazione delbodychelaUI nasconde,NONunaripetizione diapprovazione/budget/resume.Nessunarichiesta browseragent:THSesclusivaUTENTE.

Riportaresolo campierrorestatus,code/Code,error,message/error_msg,path/correlationId presentie nonsegreti.Noninviarecookie,bearer/access_token/refresh_token/id_token ocsrfToken.Se ilGETriuscisse,restituiscecard+CSRF:condividere SOLOS card.status,card.cumulativeAttempts,card.recoveryPermissionAvailable,MAIl'interowrapper.Non ènecessarioinviarescreenshot ocredenziali.

Con questi dati:confrontare sicurezza sessioneclient/scopes/Gateway/owner ecorreggere ilsolo delta dimostrato,riusando procedure Teatri qualificate.Nonautomaticretry del403oINVALID_ARGUMENT;erroridimutazioneambigui restanodriconciliare stessocomando/sessione.Nonaccumularebudget.

## Proseguimento mantenuto

UltimojobFAILED5 conservato;nessun accessooriginale/hashserver/parser/preview61righeancoraprovato.Dopoaccesso/card/reviewcorrenti,HUMAN3/900 e successivoresumesonoDUEdecisionidistinteSTESSOjob/sessione,cumulativi6–8,maireset.Poi originale13903byte/SHAf670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311→profilo61righe→semantica/Ingestion/UDP,tutte righe/provenance.Riusaretyped/ASSETS/LATESTeM1Teatri.M1/G4acquisiti;M2/G5/G6/G7,dueclient,D5/D6/D7,E2Eeaccettazioneaperti.[Piano](../../releases/csv-m2-plan-20261026.json),[roadmap](../OUF_M2_ROADMAP_20261026.md).Nessun nuovo upload/job/terzaacquisizione/attivazioneimplicita/Registryrestart/reinstall/merge/releaseacceptance/subagente/automazione.SupervisordopoE2Ecompleto.
