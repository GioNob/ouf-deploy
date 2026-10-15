# Conferma terminale della review — 15 ottobre 2026

La preparazione completa sul VPS è riuscita due volte. Nell'ultimo tentativo la review5cc4b24c718a2ecc303e0184086c4697745dee83629b5ba7e9a8efe2337bf4e3 è stata pubblicata e mostrata; il lettore /dev/tty ha poi rifiutato la conferma. Il testo visibile riportato dall'operatore coincide con la richiesta. I byte letti dal programma non sono disponibili: la causa specifica rimane sconosciuta.

Il vecchio lettore confrontava i byte esatti una sola volta e non forniva diagnosi del formato. Con un vero controlling PTY, il testo ASCII esatto passa; una sequenza standard di bracketed paste o input rimasto in coda riproduce lo stesso FULL_ACTION_NOT_APPROVED. Queste prove spiegano due modalità possibili, senza attribuirle automaticamente allo smartphone dell'operatore.

La correzione nel sorgente6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a:
- elimina la coda precedente prima di mostrare la review corrente;
- accetta il testo esatto oppure un solo involucro standard di incolla attorno alla riga o al solo hash;
- permette massimo tre risposte nello stesso prompt, mostrando classificazione e conteggi senza riportare l'input;
- continua a richiedere APPROVO e l'intero hash corrente, senza normalizzare spazi, Unicode, maiuscole o altri controlli ANSI;
- include esplicitamente termios nella lista dei moduli standard ammessi dal loader sigillato.

Nel pacchetto operativo sono cambiati solo review.py e runtime.py, più hash della capsula e launcher. Si aggiungono sette test PTY e il loro ingresso nella CI. Nessun sorgente dei sei moduli applicativi, immagine, migrazione o scope della review è cambiato.

Questo errore si verifica prima di review.issue, firme dei ruoli e FiniteActionProcess.start. L'output riporta runtimeAuthorityIssued=null e l'evidenza conserva quel valore. Per questo specifico punto del sorgente, nessuna emissione o applicazione runtime è iniziata. Non si estende questa conclusione a errori successivi o ambigui.

La qualificazione esatta e il wrapper sono nell'[evidenza strutturata](../evidence/chatbot-human-terminal-fix-20261015.json); il [prossimo passo](CHATBOT_PREPARATION_NEXT_20261015.md) richiede una review nuova e conferma manuale. Il primo tentativo di applicazione, CSV Teatri completo e riuso della seconda sorgente restano da osservare.

Qualificazione del sorgente esatto: CI38687882912/job116266819989, **207 test,27 suite,PASS,zero skip**, incluso caricamento completo isolato della closure. La run PR38687887477 è anch'essa PASS; verificatore HUMAN38687887549 PASS. Il wrapper Bash ha sintassi valida e SHA2564164ef0b48b9bd428b5e1b24f95c78c137ecb1f82284f603465d57538c25d343.
