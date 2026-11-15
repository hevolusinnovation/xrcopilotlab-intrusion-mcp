# La VPN dell'azienda: guida per chi la gestisce

Questa guida è per la persona che, in azienda, decide chi può entrare nella rete da fuori: il titolare, il referente
informatico o il fornitore di fiducia. Non serve essere esperti di reti: bastano un accesso al server e i comandi
riportati qui.

**Gli utenti della VPN li crea e li toglie sempre l'azienda.** Hevolus installa lo strumento ma non crea utenti e non
gestisce la configurazione del vostro server: chi entra nella vostra rete lo decidete voi.

## A cosa serve

La VPN è un **ingresso riservato** alla rete dell'azienda. Un dipendente in trasferta, da casa o dal cliente, accende
la VPN sul telefono o sul portatile e lavora come se fosse in ufficio: raggiunge il gestionale, le cartelle condivise,
il desktop remoto, le macchine dell'impianto. Lo stesso vale per una **seconda sede**: il suo router si collega alla
VPN e le due reti si vedono. E se l'azienda non ha un server in ufficio, la VPN può stare su un **server in affitto
(VPS)** che fa da punto d'incontro per tutte le sedi: vedi [Un server centrale](#un-server-centrale-vps-per-casa-e-ufficio).

Così i servizi delicati (desktop remoto, cartelle condivise, Modbus e gli altri protocolli industriali) non devono più
essere aperti su internet, dove chiunque li può attaccare. La pagina di monitoraggio, alla voce *Cosa migliorare*, vi
segnala quelli ancora aperti.

Ogni dispositivo ha **la sua chiave**. Chi non ha una chiave valida non riceve nessuna risposta: per lui la porta della
VPN sembra chiusa come tutte le altre.

## Prima di iniziare

1. **Un indirizzo pubblico dell'ufficio**: l'IP pubblico della linea internet o un nome (`vpn.azienda.it`). Lo trovate
   nel contratto con il provider o nella pagina del router.
2. **Una regola sul router dell'ufficio**: inoltrare la porta **UDP 51820** verso il server su cui è installata la VPN
   (la voce si chiama di solito *port forwarding*, *virtual server* o *NAT*).
3. **Attenzione alle linee senza IP pubblico.** Alcune linee in fibra e quasi tutte quelle mobili (4G/5G) condividono
   l'IP pubblico con altri clienti (si chiama *CGNAT*): da fuori non si può entrare. Le soluzioni sono chiedere al
   provider un **IP pubblico** (spesso costa pochi euro al mese) oppure usare l'**IPv6** della linea, se c'è: la VPN lo
   supporta (vedi più avanti).

## Installazione (una volta sola)

La fa chi amministra il server, insieme al pacchetto di monitoraggio:

```bash
sudo VPN_ENDPOINT=vpn.azienda.it ./install.sh --with wireguard
```

Alla fine l'installazione scrive **quale rete interna apre la VPN**, cioè quella che ha trovato da sola. Controllatela:
se il server ha più schede di rete, potrebbe aver scelto quella sbagliata. Per cambiarla:

```bash
xrc-vpn lan 192.168.1.0/24
```

Se l'indirizzo pubblico non lo sapete ancora, potete impostarlo dopo con `xrc-vpn endpoint`.

## Chi può gestire gli utenti

Chi gestisce la VPN non ha bisogno di essere amministratore completo del server: basta aggiungere il suo account al
gruppo **vpn-admin**. Da quel momento può usare il comando `xrc-vpn`, e solo quello, con la propria password.

```bash
sudo usermod -aG vpn-admin anna        # poi Anna esce e rientra nel server
```

## Aggiungere un telefono o un portatile

```bash
xrc-vpn add mario-telefono
```

Il server mostra un **QR code**. Sul telefono di Mario:

1. installate l'app ufficiale **WireGuard** (App Store o Google Play);
2. toccate **+** e poi **Scansiona da codice QR**;
3. date un nome alla connessione e accendetela.

Per un portatile (Windows, Mac, Linux) è più comodo un file da importare:

```bash
xrc-vpn add mario-pc --conf > mario-pc.conf
```

Nell'app WireGuard del portatile scegliete **Importa tunnel da file**, poi **cancellate il file**: contiene la chiave
di Mario.

> Il QR e il file si vedono **una volta sola**: il server non conserva la chiave privata del dispositivo. Consegnateli
> di persona, mai via email o chat. Se si perdono, `xrc-vpn reissue mario-telefono` ne crea di nuovi e quelli vecchi
> smettono di funzionare.

Usate nomi che dicano **di chi è** e **quale dispositivo** (`mario-telefono`, `mario-pc`): quando qualcosa non va,
sapete subito a chi chiedere. Il nome può contenere solo lettere minuscole, numeri e trattini.

## Aggiungere il router di un'altra sede (o un PC gestito dall'IT)

Ci sono due modi, a seconda di cosa sa fare il router.

**Il router importa un file** (il FRITZ!Box, per esempio). La chiave la crea il server e la mette nel file, come per un
portatile:

```bash
xrc-vpn add sede-milano --lan 192.168.20.0/24 > sede-milano.conf
```

Importate il file nel router (FRITZ!Box: vedi [più avanti](#configurare-i-fritzbox)) e poi **cancellatelo**: contiene
la chiave del router, che il server non conserva. Se si perde, `xrc-vpn reissue sede-milano` ne crea uno nuovo.

**Il router crea la sua chiave** (MikroTik, pfSense/OPNsense, Draytek…). Un router così crea **da solo** la sua chiave e vi fornisce solo la **chiave pubblica**, che non è segreta. La chiave
privata non lascia mai il router. Nel menu WireGuard del router (FRITZ!Box, MikroTik, pfSense/OPNsense, Draytek…)
create una nuova connessione, copiate la chiave pubblica che vi mostra e date:

```bash
xrc-vpn add sede-milano --pubkey <chiave pubblica del router> --lan 192.168.20.0/24
```

`--lan` è la rete della sede di Milano, e deve essere **diversa** da quella dell'ufficio principale. Il server stampa i
campi da copiare nel router: indirizzo del tunnel, chiave pubblica del server, endpoint, reti consentite, *preshared
key* e *keepalive*. La *preshared key* è segreta: copiatela nel router e non conservatela altrove.

Allo stesso modo un PC gestito dal vostro reparto IT può creare la chiave nell'app (*Aggiungi tunnel vuoto*) e dare
solo la chiave pubblica con `--pubkey`, senza `--lan`.

Da Milano verso l'ufficio funziona subito, e anche i telefoni e i portatili in VPN raggiungono Milano. Perché siano i
computer dell'ufficio principale a raggiungere quelli di Milano, il router dell'ufficio deve sapere che la rete
`192.168.20.0/24` passa dal server della VPN (una *rotta statica*).

Gli utenti creati **prima** della nuova sede non conoscono ancora la sua rete: il comando li elenca, e
`xrc-vpn reissue <nome>` dà a ciascuno la configurazione aggiornata.

## Togliere un utente

```bash
xrc-vpn revoke mario-telefono
```

L'effetto è **immediato**: la chiave non apre più niente. Fatelo subito quando:

- un dispositivo viene perso o rubato;
- una persona lascia l'azienda o cambia ruolo;
- la pagina di monitoraggio segnala un collegamento da un **Paese inatteso** e la persona non è in viaggio.

## Vedere chi è collegato

```bash
xrc-vpn list
```

```
NAME                     KIND    ADDRESS         LAST CONNECTION
mario-telefono           device  10.88.0.2       3 min ago
sede-milano              router  10.88.0.3       0 min ago
luca-vecchio-pc          device  10.88.0.5       never
```

La **pagina di monitoraggio** mostra gli stessi utenti, con la città da cui si sono collegati.

![Gli utenti della VPN nella pagina di monitoraggio](images/vpn.jpg)

*Un esempio con dati simulati: anna-portatile si è collegata da un Paese inatteso, luca-vecchio-pc non si collega da
mesi; per ciascuno la pagina propone il comando che lo revoca.*
 Alla voce *Cosa
migliorare* trovate:

- **un utente collegato da un Paese inatteso** (gravità alta), con il comando per revocarlo già pronto;
- **utenti che nessuno usa** da più di 60 giorni: spesso un vecchio telefono o qualcuno che non c'è più, e la loro
  chiave apre ancora la rete;
- **la VPN senza indirizzo pubblico**, se manca `xrc-vpn endpoint`.

L'assistente XRCopilotLab legge le stesse informazioni e può proporvi una revoca, ma non la fa: la decisione resta
vostra.

## Cambiare l'indirizzo pubblico o la rete interna

Se cambia l'IP o il nome dell'ufficio:

```bash
xrc-vpn endpoint 93.41.10.7
```

Se cambia la rete interna da raggiungere (anche più reti, separate da virgola):

```bash
xrc-vpn lan 192.168.1.0/24,192.168.5.0/24
```

In entrambi i casi gli utenti già creati hanno ancora i dati vecchi nella loro configurazione: il comando ve li elenca.
Per ciascuno:

```bash
xrc-vpn reissue mario-telefono
```

Un telefono o un portatile riceve un nuovo QR (o file, con `--conf`), con una chiave nuova; un router che importa un
file riceve un file nuovo. Un router con la sua chiave la tiene: `reissue` ristampa i campi da ricopiare nel router.

## IPv6

La VPN funziona anche in IPv6:

- **come indirizzo pubblico**: se la linea dell'ufficio ha IPv6, potete dare quell'indirizzo
  (`xrc-vpn endpoint 2001:db8::7`). È la via d'uscita più comune quando la linea non ha un IPv4 pubblico (CGNAT).
  Il router deve lasciar passare la porta UDP 51820 verso il server anche in IPv6. Il telefono che si collega deve
  avere IPv6 a sua volta: oggi quasi tutte le reti mobili italiane lo hanno;
- **dentro il tunnel**: ogni utente riceve anche un indirizzo IPv6 privato, creato alla prima accensione e diverso per
  ogni azienda;
- **verso la rete interna**: se l'ufficio usa IPv6, `xrc-vpn lan` accetta anche reti IPv6
  (`xrc-vpn lan 192.168.1.0/24,2001:db8:1::/64`).

## Un server centrale (VPS) per casa e ufficio

Quando le sedi sono due o più (casa e ufficio, due uffici) e nessuna ha un server sempre acceso, la VPN può stare su un
**server in affitto su internet** (un VPS, per esempio Aruba Cloud). Il VPS non ha una rete interna sua: è solo il
**punto d'incontro**. Il router di ogni sede si collega al VPS e da lì le sedi si vedono tra loro.

```mermaid
flowchart LR
  subgraph CASA["Casa (192.168.178.0/24)"]
    PC1[PC, TV, NAS] --- F1[FRITZ!Box]
  end
  subgraph UFFICIO["Ufficio (192.168.10.0/24)"]
    PC2[PC, stampante] --- F2[FRITZ!Box]
  end
  F1 -->|"VPN, in uscita"| VPS["VPS<br/>xrc-vpn lan none"]
  F2 -->|"VPN, in uscita"| VPS
  TEL[Telefono fuori sede] -->|VPN| VPS
  F1 -.->|"internet, linea propria"| NET((Internet))
  F2 -.->|"internet, linea propria"| NET
```

Cosa cambia rispetto a un server in ufficio:

- **Nessuna porta da aprire nelle sedi.** Sono i router a chiamare il VPS, che ha un IP pubblico fisso. Funziona anche
  se la linea di casa o dell'ufficio è in CGNAT (senza IP pubblico).
- **I computer delle sedi non installano niente.** Un portatile collegato al Wi-Fi di casa raggiunge la stampante
  dell'ufficio passando dai due FRITZ!Box. Serve un utente VPN solo per un dispositivo **fuori** da entrambe le sedi
  (il telefono in viaggio).
- **Internet resta quello di ogni sede.** Passa dal VPS solo il traffico verso l'altra sede; la navigazione, lo
  streaming e le videochiamate escono dalla linea di casa o dell'ufficio come prima. Se il VPS si ferma, si perde solo
  il collegamento tra le sedi, non internet.

### Quale VPS

Tutti i passi su un VPS Aruba Cloud, dall'acquisto ai FRITZ!Box collegati, con i piani e i costi:
[Un VPS Aruba come server centrale](vps-aruba.md).

| | Minimo | Consigliato |
|---|---|---|
| Con solo VPN e monitoraggio | 2 vCPU, 2 GB RAM, 40 GB disco | |
| Con Suricata (analisi del traffico) | | 2 vCPU, **4 GB RAM**, 80 GB disco |

- Sistema **Ubuntu 24.04**, IPv4 pubblico (incluso nei VPS).
- Deve essere una **macchina virtuale completa** (KVM/OpenStack, come i VPS e i Cloud Server di Aruba), non un
  container: Falco lo verifica con `ls /sys/kernel/btf/vmlinux`.
- Il traffico tra le sedi conta nel traffico del VPS: per file grandi e copie notturne scegliete un piano con traffico
  abbondante o illimitato.

### Installazione sul VPS

```bash
sudo VPN_LAN=none VPN_ENDPOINT=<IP pubblico del VPS> \
     DASHBOARD_ALLOW="10.88.0.0/24 192.168.178.0/24 192.168.10.0/24" \
     ./install.sh --with fail2ban,crowdsec,wireguard
```

`VPN_LAN=none` dice che il VPS non apre una rete sua. `DASHBOARD_ALLOW` fa aprire la pagina di monitoraggio solo dalle
due sedi e dalla VPN. Nel pannello del provider (firewall del VPS) lasciate aperte solo **SSH** (meglio se solo dagli
IP delle sedi) e **UDP 51820**. Se usate UFW sul VPS: `sudo ufw allow 51820/udp`.

### Preparare le reti delle sedi

Ogni sede deve avere una **rete diversa**. I FRITZ!Box nascono tutti con `192.168.178.0/24`: lasciate quella di casa e
cambiate quella dell'ufficio (FRITZ!Box: *Rete domestica › Rete › Impostazioni di rete › Indirizzi IPv4*), per esempio
in `192.168.10.1` con maschera `255.255.255.0`. I dispositivi dell'ufficio prendono il nuovo indirizzo da soli; quelli
con un IP fisso (stampanti, NAS) vanno aggiornati a mano.

Poi, sul VPS:

```bash
xrc-vpn add casa-fritz    --lan 192.168.178.0/24 > casa-fritz.conf
xrc-vpn add ufficio-fritz --lan 192.168.10.0/24  > ufficio-fritz.conf
xrc-vpn reissue casa-fritz > casa-fritz.conf      # casa è stata creata prima dell'ufficio: ora conosce anche lui
```

Se provate a dare a due sedi la stessa rete, `xrc-vpn` si ferma e lo dice.

### Configurare i FRITZ!Box

Serve FRITZ!OS **7.50 o successivo** (*Sistema › Aggiornamento*). Su ciascun FRITZ!Box:

1. se ci sono già connessioni WireGuard di prova, **cancellatele**;
2. *Internet › Abilitazioni › VPN (WireGuard)* › **Aggiungi connessione**;
3. scegliete **Collegare reti** (*LAN-LAN*), poi **"La connessione è già configurata, importa le impostazioni"** (o
   simile, secondo la versione);
4. caricate il file `.conf` di quella sede (`casa-fritz.conf` a casa, `ufficio-fritz.conf` in ufficio) e confermate;
5. **cancellate il file** dal computer.

> **Da verificare sul vostro FRITZ!Box.** Il file ha come indirizzo del tunnel quello della VPN (`10.88.0.2/32`).
> Alcune versioni di FRITZ!OS, per un collegamento tra reti, vogliono invece l'indirizzo del FRITZ!Box nella sua rete
> (`192.168.178.1/24`). Se l'importazione lo rifiuta, correggete la riga `Address` nel file con l'indirizzo del FRITZ!Box
> e riprovate: il VPS accetta entrambi.

Il collegamento resta acceso da solo (*keepalive* di 25 secondi). Sul VPS, `xrc-vpn list` mostra le due sedi con
l'ultimo collegamento di pochi minuti fa. Dal PC di casa provate `ping 192.168.10.1`: risponde il FRITZ!Box
dell'ufficio.

### Il telefono fuori sede

```bash
xrc-vpn add mario-telefono
```

Il telefono raggiunge entrambe le sedi. Quando è a casa o in ufficio, sul Wi-Fi, la VPN si può tenere spenta.

## Cosa fa e cosa non fa

- Apre **solo** le reti interne indicate e quelle delle sedi collegate. Non fa uscire su internet attraverso l'ufficio
  o il VPS: ognuno naviga con la propria connessione.
- Non tocca il firewall UFW del server. Se è acceso, l'installazione vi dice la regola da aggiungere
  (`sudo ufw allow 51820/udp`).
- Non registra tentativi falliti: chi non ha la chiave giusta non riceve risposta, e non c'è niente da registrare.
- Non sostituisce le password dei servizi: chi entra in VPN deve comunque accedere al gestionale, alle cartelle e agli
  altri servizi con le proprie credenziali.

## Quando qualcosa non va

| Problema | Cosa controllare |
|---|---|
| L'app non si collega mai (nessun "handshake") | La regola di port forwarding UDP 51820 sul router; l'indirizzo pubblico (`xrc-vpn show`); se la linea è in CGNAT (vedi sopra); che il telefono non sia su una rete Wi-Fi che blocca le VPN |
| Le due sedi sono collegate (`xrc-vpn list`) ma non si vedono | Che le reti delle sedi siano diverse; che la sede creata per prima abbia avuto `reissue` dopo l'aggiunta dell'altra; il firewall dei PC (Windows blocca il ping da altre reti finché non lo si permette) |
| Si collega ma non raggiunge i computer dell'ufficio | La rete interna aperta (`xrc-vpn show`, riga *Internal network*); se è sbagliata, `xrc-vpn lan` e poi `reissue` per gli utenti |
| Funzionava e ora no | L'IP pubblico dell'ufficio è cambiato: `xrc-vpn endpoint`, poi `reissue`; oppure l'utente è stato revocato |
| Un utente compare da una città strana | Chiedete alla persona; se non è lei, `xrc-vpn revoke <nome>` subito |

## Riepilogo dei comandi

| Comando | Cosa fa |
|---|---|
| `xrc-vpn add <nome>` | Nuovo telefono o portatile: QR code |
| `xrc-vpn add <nome> --conf > file.conf` | Lo stesso, come file da importare |
| `xrc-vpn add <nome> --lan <rete> > file.conf` | Router di un'altra sede che importa un file (FRITZ!Box) |
| `xrc-vpn add <nome> --pubkey <chiave> [--lan <rete>]` | Router di un'altra sede o PC con chiave propria |
| `xrc-vpn revoke <nome>` | Toglie subito l'accesso |
| `xrc-vpn reissue <nome> [--conf]` | Nuova configurazione dopo un cambio di indirizzo o di rete, o per un dispositivo perso |
| `xrc-vpn list` | Utenti e ultimo collegamento |
| `xrc-vpn show [<nome>]` | Impostazioni del server, o i campi di un router |
| `xrc-vpn endpoint <IP o nome>` | Indirizzo pubblico a cui si collegano gli utenti |
| `xrc-vpn lan <reti> \| auto \| none` | Reti interne che la VPN apre; `none` su un server centrale (VPS) |
