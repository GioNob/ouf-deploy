# Trasporti nativi: invarianti apprese dalle prove esistenti

27 ottobre 2026. Prima di introdurre guard di rollout o compatibilità, confrontare il trasporto già usato e le forme effettivamente conservate. Non dedurre proprietà del server da fixture CI più ristrette.

## Peer Unix root con PID1

Il peer catturato ha hash canonico `7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772`, equivalente a `[1,0,0]`. Il predicato nuovo `PID>1` ha causato uno STOP evitabile prima della review. PID1 è positivo e valido: il codice MCP storico [b9697462](https://github.com/GioNob/ouf-deploy/blob/b9697462f293d7481c9fd7cdd84c549b70214eda/tools/mcp_diagnostic_update/transport.py) e i trasporti acquisizione/redazione verificano già tupla completa esatta e UID0, senza escluderlo. Non attribuire il PID1 a systemd o altra causa senza prova.

Conservare socket path/custodia, confronto LIVE dei tre elementi e UIDroot. Non eliminare il peer dai binding correnti, riscrivere hash storici, accettare qualunque peer o indebolire il confronto. La compatibilità dell'unico profilo storico privo di peer è esplicita, vincolata al report riconciliato e ai due hash esatti; non una normalizzazione generica.

Regressioni: `tests/test_onboarding_peer_compatibility.py` copre hash/tupla reale, tipi, root/nonroot, mutazioni, claim e contatori; `tests/qualify_onboarding_pid1_peer.py` crea realmente il server socket come PID1 in un namespace CI, poi usa il trasporto live con SO_PEERCRED dal kernel. Le fixture Docker classiche con daemon PID maggiore di1 non sostituiscono questa prova.

## Continuazioni di preflight consumati

Uno STOP prima della review non autorizza un replay. Conservare vecchi scope/file/claim/codice/log e sommare i tentativi già riservati. Nel caso Onboarding3+8=11 restano nello stesso massimo64; nuovo child esclusivo e nuova review concreta nel terminale. Prima di procedere, il controller verifica che i vecchi scope non contengano authority, journal, review o effetti inattesi. Le prove CI non attestano lo stato runtime VPS.

[Ricevuta del difetto](../evidence/onboarding-pid1-peer-stop-target-20261027.json) · [Handoff corrente](handoffs/OUF_FARMACIE_DIAGNOSTIC_PID1_CONTINUATION_20261027.md).
