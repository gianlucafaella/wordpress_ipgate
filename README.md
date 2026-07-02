# WordPress IP Gate
IP Gate (Cloudflare Aware) è un plugin WordPress che limita l’accesso al sito in base all’indirizzo IP pubblico reale del visitatore.

Il plugin è pensato soprattutto per installazioni WordPress dietro Cloudflare: quando disponibile, legge l’IP reale dall’header CF-Connecting-IP; in alternativa usa X-Forwarded-For oppure REMOTE_ADDR. La protezione può essere applicata sia al frontend sia al backend del sito.

Dal pannello di amministrazione “IP Gate”, disponibile nelle impostazioni di WordPress, è possibile abilitare o disabilitare la protezione, scegliere tra modalità allowlist e denylist, inserire IP singoli o range CIDR IPv4/IPv6 e configurare un token di bypass opzionale.

In modalità allowlist, il sito è accessibile solo dagli IP presenti nella lista. In modalità denylist, invece, il sito resta accessibile a tutti tranne agli IP indicati. Se un visitatore non rispetta la policy configurata, il plugin interrompe la richiesta e restituisce una risposta HTTP 403 “Accesso negato”.

Il plugin include anche un token di emergenza: se configurato, è possibile aggiungere ?ipgate=TOKEN all’URL per bypassare temporaneamente il blocco. Questa funzione è utile per recuperare l’accesso in caso di configurazione errata della allowlist.

È disponibile inoltre una modalità diagnostica che invia header come X-IP-Gate-Client e X-IP-Gate-From, utili per verificare quale IP viene rilevato dal server e da quale header proviene. Il plugin registra anche informazioni diagnostiche nel log PHP.
